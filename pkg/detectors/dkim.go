package detectors

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// minDKIMKeyBits is the RSA modulus floor below which an inline DKIM key is
// reported as weak. RFC 8301 (Jan 2018) updated RFC 6376 to require signers and
// verifiers to support 1024–4096-bit keys and to deprecate anything shorter:
// "Signers MUST use RSA keys of at least 1024 bits." A 512-bit DKIM key has
// been factored in hours on commodity hardware (the 2012 Zachary Harris
// disclosure against Google, eBay, PayPal, et al.), and 768-bit RSA fell to an
// academic factoring effort in 2009. Any key strictly below 1024 bits lets an
// attacker recover the private key and forge DKIM-passing mail without ever
// touching DNS, so it is a real, exploitable spoofing weakness independent of
// the dangling-CNAME case.
const minDKIMKeyBits = 1024

// DefaultDKIMSelectors is the list of DKIM selectors graverobber probes when no
// override is supplied. DKIM public keys live at <selector>._domainkey.<domain>;
// organizations frequently publish them as CNAMEs delegating the key to an ESP
// (e.g. s1._domainkey.example.com → s1.domainkey.sendgrid.net). The selector
// name is not discoverable from DNS alone, so a passive scanner can only cover
// the common, well-known selectors used by the major email service providers.
//
// Sources: provider onboarding docs (SendGrid s1/s2, Google "google", Mailchimp
// k1, Amazon SES-style, Microsoft "selector1"/"selector2") and the SubdoMailing
// writeup (Guardio Labs, 2024).
var DefaultDKIMSelectors = []string{
	"default",   // generic / self-hosted
	"google",    // Google Workspace
	"k1",        // Mailchimp / Mandrill
	"k2",        // Mailchimp (secondary)
	"s1",        // SendGrid (primary)
	"s2",        // SendGrid (secondary)
	"selector1", // Microsoft 365
	"selector2", // Microsoft 365
	"dkim",      // common self-hosted name
	"mail",      // common self-hosted name
	"smtp",      // common self-hosted name
}

// DKIM detects two DKIM-selector weaknesses, both of which let an attacker sign
// mail that passes DKIM verification for the target domain.
//
// Algorithm:
//  1. For each selector, build the FQDN <selector>._domainkey.<target>.
//  2. Resolve its CNAME (resolver.RawCNAME).
//     a. If the selector is delegated via CNAME, follow the target with
//     CNAMEChain; if the target is NXDOMAIN the ESP resource is gone and the
//     selector is reclaimable — emit a Confidence=Confirmed VectorDKIM
//     finding (the original Rank 6 dangling-CNAME case).
//     b. If the selector is NOT delegated, look up its TXT record and parse the
//     inline DKIM key. If the published RSA public key is below the RFC 8301
//     1024-bit floor (minDKIMKeyBits), emit a Confidence=Likely VectorDKIM
//     finding carrying DKIMKeyBits — a short key can be factored to recover
//     the private key and forge DKIM-passing mail.
//
// The two cases are mutually exclusive per selector: a selector either delegates
// via CNAME or publishes a key inline, never both. selectors overrides
// DefaultDKIMSelectors when non-empty (the --selectors flag). Each selector is
// probed independently; one finding does not short-circuit the others.
func DKIM(ctx context.Context, target string, r *resolver.Resolver, selectors []string) ([]finding.Finding, error) {
	if len(selectors) == 0 {
		selectors = DefaultDKIMSelectors
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate selectors within a single target

	for _, sel := range selectors {
		sel = strings.ToLower(strings.TrimSpace(sel))
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true

		host := sel + "._domainkey." + target

		cname, err := r.RawCNAME(ctx, host)
		if err == nil && cname != "" {
			// The selector delegates via CNAME. Check whether the delegated
			// target still exists. NXDOMAIN means the ESP resource is gone and
			// reclaimable.
			_, chainErr := r.CNAMEChain(ctx, cname)
			if errors.Is(chainErr, resolver.ErrNXDomain) {
				findings = append(findings, finding.Finding{
					Subdomain:    host,
					Vector:       finding.VectorDKIM,
					Confidence:   finding.Confirmed,
					CNAME:        cname,
					DKIMSelector: sel,
					Evidence:     "DKIM selector CNAME target is NXDOMAIN — ESP resource reclaimable",
				})
			}
			continue
		}

		// Not delegated via CNAME. The selector may publish a DKIM key inline as
		// a TXT record. Fetch it and check the RSA modulus size: a key below the
		// RFC 8301 floor is factorable and lets an attacker forge signatures.
		txts, txtErr := r.TXT(ctx, host)
		if txtErr != nil || len(txts) == 0 {
			continue
		}
		bits, ok := weakDKIMKeyBits(txts)
		if !ok {
			continue
		}
		findings = append(findings, finding.Finding{
			Subdomain:    host,
			Vector:       finding.VectorDKIM,
			Confidence:   finding.Likely,
			DKIMSelector: sel,
			DKIMKeyBits:  bits,
			Evidence: fmt.Sprintf(
				"DKIM selector publishes a %d-bit RSA key (below the RFC 8301 %d-bit floor) — factorable, forgeable signatures",
				bits, minDKIMKeyBits),
		})
	}

	return findings, nil
}

// weakDKIMKeyBits inspects the TXT records published at a DKIM selector and
// reports the RSA modulus size when it is below minDKIMKeyBits. The bool result
// is true only for a parsed RSA key that is genuinely too short; it is false for
// a non-DKIM record, a revoked key (empty p=), a non-RSA key type, a key that
// meets the floor, or any record that cannot be parsed (graverobber never
// reports a finding it cannot substantiate).
//
// A DKIM key record is a TXT value of semicolon-separated tag=value pairs, e.g.
//
//	v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo or PKCS#1 public key>
//
// The p= value is the base64-encoded public key. Per RFC 6376 the key is a
// DER-encoded SubjectPublicKeyInfo (X.509), though some signers emit a bare
// PKCS#1 RSAPublicKey; weakDKIMKeyBits accepts either.
func weakDKIMKeyBits(txts []string) (int, bool) {
	for _, txt := range txts {
		tags := parseDKIMTags(txt)
		// A DKIM key record either carries v=DKIM1 or, very commonly, omits v=
		// and is identified by the presence of p=. Require a p= tag; if v= is
		// present it must say DKIM1 (case-insensitive) to avoid misreading an
		// unrelated TXT record that happens to contain a "p=" substring.
		p, hasP := tags["p"]
		if !hasP {
			continue
		}
		if v, hasV := tags["v"]; hasV && !strings.EqualFold(v, "DKIM1") {
			continue
		}
		// k= defaults to "rsa" when absent (RFC 6376 §3.6.1). Only RSA keys have
		// a meaningful modulus-size weakness here; ed25519 keys are fixed-size
		// and out of scope for this check.
		if k, hasK := tags["k"]; hasK && !strings.EqualFold(k, "rsa") {
			continue
		}
		if p == "" {
			// Empty p= is an explicitly revoked key, not a weak key.
			continue
		}
		bits, ok := rsaPublicKeyBits(p)
		if !ok {
			continue
		}
		if bits < minDKIMKeyBits {
			return bits, true
		}
	}
	return 0, false
}

// parseDKIMTags splits a DKIM TXT record into its tag=value map. Tag names are
// lower-cased; whitespace around tags and values is trimmed. Values are kept
// verbatim (base64 in p= must not be altered). A bare tag with no '=' is
// ignored.
func parseDKIMTags(txt string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		if key == "" {
			continue
		}
		// The p= value may legitimately contain internal whitespace (folded
		// base64); strip all whitespace so base64 decoding succeeds.
		val := strings.TrimSpace(kv[1])
		if key == "p" {
			val = strings.Join(strings.Fields(val), "")
		}
		tags[key] = val
	}
	return tags
}

// rsaPublicKeyBits base64-decodes a DKIM p= value and returns the RSA modulus
// bit length. It accepts both the RFC 6376 DER SubjectPublicKeyInfo encoding
// (the common case) and a bare PKCS#1 RSAPublicKey. The bool is false when the
// value is not valid base64, not a parseable RSA public key, or not RSA.
func rsaPublicKeyBits(p string) (int, bool) {
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		// Some records use base64 without padding; try the raw encoding too.
		der, err = base64.RawStdEncoding.DecodeString(p)
		if err != nil {
			return 0, false
		}
	}

	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub.N.BitLen(), true
		}
		return 0, false // parsed, but not an RSA key (e.g. ed25519)
	}

	// Fall back to a bare PKCS#1 RSAPublicKey, which some signers publish.
	if rsaPub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rsaPub.N.BitLen(), true
	}

	return 0, false
}
