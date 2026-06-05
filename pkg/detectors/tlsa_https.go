package detectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// tlsaHTTPSPrefix is the DANE-for-HTTPS owner-name prefix (RFC 6698 §3, applied
// to HTTPS by RFC 7671 §3). A domain that opts into DANE for its public HTTPS
// service publishes its TLSA pin at _443._tcp.<host>.
const tlsaHTTPSPrefix = "_443._tcp."

// tlsaDialTimeout caps the active TLS handshake to a small, single-shot budget
// so the detector cannot stall a worker the way an unbounded Dial against an
// unresponsive endpoint would. The dangling-DANE pin path is the cheap DNS-only
// case; this is the active path and must be bounded.
const tlsaDialTimeout = 8 * time.Second

// TLSAHTTPS detects a TLSA validation failure on the HTTPS service: a domain
// that publishes a DANE TLSA pin at _443._tcp.<target> but whose live TLS
// certificate (the leaf, plus its presented chain for the trust-anchor usages)
// does NOT match any of the published associations.
//
// DANE for HTTPS (RFC 7671) lets a domain pin its TLS certificate — or the CA
// that issued it — directly in DNS, secured by DNSSEC, so a client can verify
// the certificate without relying on the public CA system. A pin is a
// cryptographic assertion: the leaf's full certificate or its Subject Public Key
// Info, hashed under the named MatchingType, MUST appear in the published
// association set. When the served certificate is rotated (or the operator
// switches CAs) but the TLSA record is left behind, the pin and the live cert
// drift out of sync; from the standpoint of every DANE-validating client this is
// a hard TLS failure (RFC 7671 §5: a published-but-unmatchable pin breaks the
// connection). Mirror of the dangling-DANE-pin pattern the SMTP TLSA vector
// already covers, applied to the HTTPS control plane and detected actively
// against the certificate the server is currently presenting.
//
// Unlike the SMTP-side TLSA detector (which fires on a NXDOMAIN MX host — a pure
// DNS-only signal), this detector requires an actual TLS handshake to extract the
// served certificate. The handshake uses InsecureSkipVerify because the goal is
// to read the certificate bytes, not to chain-validate against the public PKI
// (DANE replaces that trust anchor). A handshake failure (connection refused,
// timeout, TLS error) is treated as "do not know" and produces no finding — the
// detector is biased toward false negatives over false positives, consistent
// with the rest of graverobber.
//
// The validation algorithm follows RFC 7671 §5.1:
//   - Selector 0 (full cert): the association payload is matched against the
//     certificate's DER bytes.
//   - Selector 1 (SPKI): the association payload is matched against the
//     certificate's SubjectPublicKeyInfo DER bytes.
//   - MatchingType 0 (full data): the payload IS the bytes.
//   - MatchingType 1 (SHA-256): the payload is the SHA-256 of the selected bytes.
//   - MatchingType 2 (SHA-512): the payload is the SHA-512 of the selected bytes.
//   - Usage 1/3 (PKIX-EE/DANE-EE): match against the leaf certificate only.
//   - Usage 0/2 (PKIX-TA/DANE-TA): match against any presented chain
//     certificate (the trust-anchor usages pin a CA, not the leaf).
//
// If at least one published TLSA record matches the served certificate set, the
// pin is healthy and no finding is emitted. If every published record fails to
// match, the pin is broken: emit a POTENTIAL finding keyed on the target,
// carrying the DANE owner name in TLSAName and the observed leaf SPKI
// SHA-256 fingerprint in Evidence (the value the operator can copy into a
// corrected TLSA RDATA to repair the pin).
//
// A domain with no TLSA records at _443._tcp.<target> is the healthy non-DANE
// case and is intentionally NOT probed (no handshake at all) — keeping the
// detector low-noise and pipeline-friendly. Unknown/reserved Usage, Selector,
// or MatchingType values are skipped per RFC 6698 §2.1's forward-compatibility
// stance (an unrecognised association cannot disprove a match).
//
// Algorithm:
//  1. Query TLSARecords at _443._tcp.<target>. If none, return no findings.
//  2. tls.Dial target:443 with InsecureSkipVerify. On error, return no findings.
//  3. For each TLSA record, compute the expected payload for the named selector
//     and matching type against each candidate certificate (leaf for EE usages,
//     full chain for TA usages) and compare against the published payload.
//  4. If any record matches, the pin is healthy — return no findings.
//  5. Otherwise emit a POTENTIAL finding.
func TLSAHTTPS(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	owner := tlsaHTTPSPrefix + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	records, err := r.TLSARecords(ctx, owner)
	if err != nil || len(records) == 0 {
		return nil, nil
	}

	chain, leafFP, ok := fetchTLSChain(ctx, target)
	if !ok {
		// Handshake failed (connect refused, timeout, TLS error). No verdict:
		// silent so the active path never produces a false positive on a
		// transient network failure or an HTTPS-less host. The dangling-pin
		// SMTP detector covers the analogous "host gone" case for mail.
		return nil, nil
	}
	if len(chain) == 0 {
		return nil, nil
	}

	for _, rec := range records {
		if tlsaMatches(rec, chain) {
			return nil, nil
		}
	}

	return []finding.Finding{{
		Subdomain:  target,
		Vector:     finding.VectorTLSA,
		Confidence: finding.Potential,
		TLSAName:   owner,
		Scheme:     "https",
		Evidence: fmt.Sprintf(
			"DANE TLSA pin published at %s does not match the served HTTPS certificate (observed leaf SPKI SHA-256: %s) — every DANE-validating client hard-fails the connection (RFC 7671 §5)",
			owner, leafFP,
		),
	}}, nil
}

// fetchTLSChain dials target:443 with SNI=target and returns the presented
// certificate chain plus the SHA-256 of the leaf's SubjectPublicKeyInfo (lower-
// case hex). InsecureSkipVerify is deliberate: the goal is to READ the served
// certificate, not to chain-validate against the public PKI — DANE supplies its
// own trust anchor and the only output of this function is bytes for hash
// comparison. ok is false on any dial/handshake error so the caller can treat
// the result as "no verdict" rather than as a positive signal.
func fetchTLSChain(ctx context.Context, target string) (chain []*x509.Certificate, leafSPKIFingerprint string, ok bool) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if host == "" {
		return nil, "", false
	}

	dctx, cancel := context.WithTimeout(ctx, tlsaDialTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: tlsaDialTimeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		net.JoinHostPort(host, "443"),
		&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // intentional: see comment.
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return nil, "", false
	}
	defer conn.Close()

	// Block of the handshake context check so a deadline-cancelled ctx still
	// short-circuits cleanly even though tls.Dial does not honor it directly.
	if dctx.Err() != nil {
		return nil, "", false
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, "", false
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return state.PeerCertificates, hex.EncodeToString(sum[:]), true
}

// tlsaMatches reports whether a single TLSA record matches any candidate
// certificate in the chain per RFC 7671 §5.1. Unknown usage/selector/matching
// values return false so an unrecognised record can never satisfy the pin (and
// cannot disprove a match either — the caller treats "no matching record" as
// the failure condition, not "this record disproves the chain").
func tlsaMatches(rec resolver.TLSARecord, chain []*x509.Certificate) bool {
	pub, err := hex.DecodeString(rec.Cert)
	if err != nil || len(pub) == 0 {
		return false
	}

	// EE usages (1, 3) pin the leaf; TA usages (0, 2) pin any presented chain
	// certificate (typically the intermediate or root the server sends).
	var candidates []*x509.Certificate
	switch rec.Usage {
	case 1, 3:
		candidates = chain[:1]
	case 0, 2:
		candidates = chain
	default:
		return false
	}

	for _, cert := range candidates {
		var sel []byte
		switch rec.Selector {
		case 0:
			sel = cert.Raw
		case 1:
			sel = cert.RawSubjectPublicKeyInfo
		default:
			continue
		}
		if len(sel) == 0 {
			continue
		}

		var got []byte
		switch rec.MatchingType {
		case 0:
			got = sel
		case 1:
			s := sha256.Sum256(sel)
			got = s[:]
		case 2:
			s := sha512.Sum512(sel)
			got = s[:]
		default:
			continue
		}

		if bytes.Equal(got, pub) {
			return true
		}
	}
	return false
}
