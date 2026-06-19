package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"time"
)

// Signals records the independent observations the multi-signal detector aligns
// to decide whether a candidate is a credible takeover (D2). A fingerprint match
// ALONE is never sufficient; it must be corroborated by at least one independent
// unclaimed-backend signal. Each field captures one observation so the evidence
// string can report exactly which signals aligned — the multi-signal evidence is
// what makes a `detected` finding worth confirming and a `not_vulnerable`
// disproof trustworthy.
type Signals struct {
	// FingerprintMatch reports that the service edge was identified and (for an
	// HTTP-fingerprinted provider) the provider "unclaimed" body string was found,
	// or (for an NXDOMAIN-class provider) the provider is one whose unclaimed
	// resource yields NXDOMAIN. It is the PRIOR, never sufficient alone.
	FingerprintMatch bool
	// Provider is the matched service name (e.g. "GitHub Pages").
	Provider string
	// CNAMETarget is the final CNAME target the chain resolves to (the edge).
	CNAMETarget string
	// TargetNXDOMAIN reports that the final CNAME target resolves to NXDOMAIN —
	// an independent signal that no backend is claimed.
	TargetNXDOMAIN bool
	// TLSMismatch reports that the host presented no TLS, a default/provider
	// certificate, or a certificate whose CN/SAN does not cover the host — an
	// independent signal of an unclaimed/just-default backend.
	TLSMismatch bool
	// DanglingEdge reports that the DNS chain ends at a known provider edge
	// (matching the provider's CNAME suffixes). NOTE: this is a DESCRIPTIVE flag
	// for the evidence string — it indicates the chain points at provider
	// infrastructure, which is what makes the provider matchable in the first
	// place. It is NOT by itself an unclaimed-backend signal: every legitimately
	// hosted site on that provider ALSO ends at the same edge (a live, owned
	// GitHub Pages site ends at *.github.io too). Treating a bare edge match as
	// "independent" would re-introduce the exact false positive D2 exists to kill
	// (a custom error page on a live, owned backend tripping detection on
	// fingerprint+edge). The genuinely independent unclaimed signals are
	// TargetNXDOMAIN and TLSMismatch — observations that the backend is actually
	// gone/default, not merely that the chain points at the provider. See
	// Independent.
	DanglingEdge bool
}

// Independent reports whether at least one independent unclaimed-backend signal
// is present. Per D2 these are the signals that the backend is actually
// UNCLAIMED — NXDOMAIN on the CNAME target, or a TLS certificate that is absent /
// default-provider / does not cover the host. A bare "ends at a provider edge"
// (DanglingEdge) is deliberately NOT sufficient: a live, owned site on the same
// provider ends at the same edge, so counting it would re-admit the
// fingerprint-only false positive (the Appendix K guard). DanglingEdge is carried
// for evidence, but corroboration must come from NXDOMAIN or a TLS mismatch.
func (s *Signals) Independent() bool {
	return s.TargetNXDOMAIN || s.TLSMismatch
}

// Chain is a resolved CNAME chain for a host.
type Chain struct {
	Host          string
	CNAMEs        []string // ordered CNAME hops
	FinalCNAME    string   // the last CNAME target (the provider edge)
	FinalNXDOMAIN bool     // does the final target resolve to NXDOMAIN?
}

// EndsAtEdge reports whether the chain's final target matches any of the given
// provider edge suffixes (e.g. "*.github.io"). A leading "*" in an edge pattern
// is treated as a suffix wildcard.
func (c Chain) EndsAtEdge(edges []string) bool {
	final := normalizeHost(c.FinalCNAME)
	if final == "" {
		return false
	}
	for _, e := range edges {
		suf := normalizeHost(strings.TrimPrefix(strings.TrimSpace(e), "*"))
		suf = strings.TrimPrefix(suf, ".")
		if suf == "" {
			continue
		}
		if final == suf || strings.HasSuffix(final, "."+suf) {
			return true
		}
	}
	return false
}

// cnameResolver is the subset of the resolver the chain walker needs. The real
// *resolver.Resolver satisfies it; tests provide a deterministic stub.
type cnameResolver interface {
	// CNAMEChain returns the ordered CNAME chain for host; ErrNXDomain (wrapped)
	// when the host or final target is NXDOMAIN.
	CNAMEChain(ctx context.Context, host string) ([]string, error)
}

// hostLookupResolver optionally lets the chain walker confirm NXDOMAIN on the
// final target independently of the CNAMEChain rcode (defense in depth).
type hostLookupResolver interface {
	// LookupHostRcodeNXDOMAIN reports whether host resolves to NXDOMAIN.
	LookupHostRcodeNXDOMAIN(ctx context.Context, host string) (bool, error)
}

// resolveChain walks the CNAME chain for host using r, recording the final
// target and whether it is NXDOMAIN. nxErr is the sentinel the resolver wraps
// for NXDOMAIN (resolver.ErrNXDomain), passed in to avoid an import cycle and to
// keep this package testable with a stub.
func resolveChain(ctx context.Context, host string, r cnameResolver, nxErr error) Chain {
	c := Chain{Host: normalizeHost(host)}
	chain, err := r.CNAMEChain(ctx, host)
	for _, hop := range chain {
		c.CNAMEs = append(c.CNAMEs, normalizeHost(hop))
	}
	if len(c.CNAMEs) > 0 {
		c.FinalCNAME = c.CNAMEs[len(c.CNAMEs)-1]
	}
	if nxErr != nil && errors.Is(err, nxErr) {
		c.FinalNXDOMAIN = true
	}
	return c
}

// tlsDialer abstracts the TLS probe so tests can inject a fake certificate
// state without a real handshake.
type tlsDialer func(ctx context.Context, host string) (*tls.ConnectionState, error)

// defaultTLSDialer dials host:443 and returns the negotiated TLS state. It uses
// InsecureSkipVerify so the handshake completes even against a mismatched/default
// provider certificate — the detector needs to INSPECT that certificate, which
// requires completing the handshake first. (Same rationale as pkg/detectors.)
func defaultTLSDialer(ctx context.Context, host string) (*tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // recon: must inspect mismatched certs
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

// tlsCertMismatch reports whether the TLS state indicates an unclaimed/default
// backend: no TLS at all, a certificate that does not cover the host, or a
// recognizable default/provider certificate. A nil state (handshake failed)
// counts as a mismatch — a claimed, healthy backend answers TLS for its host.
func tlsCertMismatch(state *tls.ConnectionState, host string) bool {
	if state == nil || len(state.PeerCertificates) == 0 {
		return true // no TLS → unclaimed signal
	}
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(host); err != nil {
		return true // cert does not cover the FQDN
	}
	return isDefaultProviderCert(leaf, host)
}

// certNames returns the DNS names a certificate presents: the SAN DNS entries
// plus the subject CN. Used to decide whether a cert is the owner's (covers the
// exact host) or a provider default (covers only the provider's wildcard).
func certNames(leaf *x509.Certificate) []string {
	if leaf == nil {
		return nil
	}
	names := make([]string, 0, len(leaf.DNSNames)+1)
	names = append(names, leaf.DNSNames...)
	if cn := strings.TrimSpace(leaf.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	return names
}

// defaultCertMarkers are issuer/subject substrings that betray a provider's
// default/placeholder certificate served for an unclaimed edge (rather than a
// certificate the resource owner provisioned for their own hostname).
var defaultCertMarkers = []string{
	"*.github.io",
	"*.herokuapp.com",
	"*.herokudns.com",
	"*.azurewebsites.net",
	"*.cloudfront.net",
	"*.s3.amazonaws.com",
	"*.netlify.app",
	"*.vercel.app",
	"*.fastly.net",
	"*.pages.dev",
	"*.read-the-docs.io",
	"*.surge.sh",
	"kubernetes ingress controller fake certificate",
	"default backend",
}

// isDefaultProviderCert reports whether leaf looks like a provider's default
// certificate for an unclaimed edge: a wildcard/placeholder whose names cover the
// provider domain but not the operator's intended host. If the certificate's SANs
// include the exact host, it is the owner's cert (not a default) and this returns
// false.
func isDefaultProviderCert(leaf *x509.Certificate, host string) bool {
	names := certNames(leaf)
	for _, n := range names {
		if strings.EqualFold(n, host) {
			return false // exact host present → owner cert, not a default
		}
	}
	for _, n := range names {
		ln := strings.ToLower(n)
		for _, m := range defaultCertMarkers {
			if strings.Contains(ln, m) {
				return true
			}
		}
	}
	return false
}

// normalizeHost lower-cases a host and strips a trailing dot and surrounding
// whitespace.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}
