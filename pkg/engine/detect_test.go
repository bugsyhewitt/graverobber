package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
)

// errNX is a stand-in for resolver.ErrNXDomain so the engine's chain walker can
// recognise NXDOMAIN without importing the resolver package in the test.
var errNX = errors.New("test: NXDOMAIN")

// stubResolver is a deterministic CNAMEChain provider.
type stubResolver struct {
	chain []string
	err   error
}

func (s stubResolver) CNAMEChain(_ context.Context, _ string) ([]string, error) {
	return s.chain, s.err
}

// testDB builds a small fingerprint DB containing the GitHub Pages provider (a
// body-fingerprinted service, nxdomain=false) and a hypothetical NXDOMAIN-class
// provider for the NXDOMAIN path.
func testDB(t *testing.T) *fingerprints.DB {
	t.Helper()
	db, err := fingerprints.Load([]byte(`[
		{"service":"GitHub Pages","cname":["github.io"],"fingerprint":"There isn't a GitHub Pages site here.","nxdomain":false,"status":"Vulnerable"},
		{"service":"Worker NX","cname":["workers.dev"],"fingerprint":"","nxdomain":true,"status":"Vulnerable"}
	]`))
	if err != nil {
		t.Fatalf("load test DB: %v", err)
	}
	return db
}

// fakeCertState builds a TLS ConnectionState presenting a single leaf cert with
// the given DNS names — so the detector's TLS-mismatch logic can be driven
// without a handshake.
func fakeCertState(names ...string) *tls.ConnectionState {
	leaf := &x509.Certificate{
		DNSNames: names,
		Subject:  pkix.Name{CommonName: firstOr(names, "")},
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}

func firstOr(s []string, d string) string {
	if len(s) > 0 {
		return s[0]
	}
	return d
}

// TestFingerprintAloneIsNotDetected is graverobber's analogue of Packet 05's
// "the gate cannot lie" test (Appendix K): a fingerprint match with NO
// independent signal must NOT be `detected`. If this goes red, graverobber
// degrades into another noisy fingerprint matcher. This is a release-blocker.
func TestFingerprintAloneIsNotDetected(t *testing.T) {
	db := testDB(t)

	// A custom 404 page that happens to contain the GitHub fingerprint string,
	// but the backend is LIVE: the CNAME target resolves (NOT nxdomain) and the
	// served certificate is the owner's, covering the exact host. Only one signal
	// (the fingerprint) is present.
	host := "cdn.example.com"
	d := NewDetector(db,
		WithResolver(stubResolver{chain: []string{"real-owned.github.io"}}, errNX), // no NXDOMAIN
		WithBodyFetcher(func(_ context.Context, _ string) ([]byte, string, error) {
			return []byte("There isn't a GitHub Pages site here."), "https", nil // fingerprint MATCH
		}),
		WithTLSDialer(func(_ context.Context, h string) (*tls.ConnectionState, error) {
			return fakeCertState(h), nil // owner cert covering the exact host → no mismatch
		}),
	)

	sig, detected := d.Detect(context.Background(), host)
	if detected {
		t.Fatalf("D2 VIOLATION: fingerprint match with no independent signal must NOT be detected (signals=%+v)", sig)
	}
	if !sig.FingerprintMatch {
		t.Fatal("sanity: the fingerprint should still register (just not be sufficient alone)")
	}
	if sig.Independent() {
		t.Fatalf("no independent signal should be present, got %+v", sig)
	}
}

// TestMultiSignalIsDetected: a genuinely dangling resource (fingerprint +
// NXDOMAIN + TLS mismatch) must be detected, and the corroborating signals must
// be recorded for the evidence string.
func TestMultiSignalIsDetected(t *testing.T) {
	db := testDB(t)
	host := "assets.example.com"

	d := NewDetector(db,
		WithResolver(stubResolver{chain: []string{"dangling.github.io"}, err: errNX}, errNX), // NXDOMAIN
		WithBodyFetcher(func(_ context.Context, _ string) ([]byte, string, error) {
			return []byte("There isn't a GitHub Pages site here."), "https", nil // fingerprint
		}),
		WithTLSDialer(func(_ context.Context, _ string) (*tls.ConnectionState, error) {
			return nil, errors.New("tls: handshake failed") // no TLS → mismatch
		}),
	)

	sig, detected := d.Detect(context.Background(), host)
	if !detected {
		t.Fatalf("a genuine dangling resource (fingerprint + nxdomain + tls) must be detected (signals=%+v)", sig)
	}
	if !sig.TargetNXDOMAIN || !sig.TLSMismatch {
		t.Fatalf("the corroborating signals should be recorded for the evidence string, got %+v", sig)
	}
	if !sig.DanglingEdge {
		t.Fatalf("the chain ends at the github.io edge; DanglingEdge should be set, got %+v", sig)
	}

	// The produced finding must be a detected, high-severity, takeover.github-pages.
	f := d.Finding(host, sig)
	if f.State != finding.StateDetected {
		t.Errorf("state = %q, want detected", f.State)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Rule != "takeover.github-pages" {
		t.Errorf("rule = %q, want takeover.github-pages", f.Rule)
	}
	ev := SignalEvidence(sig)
	for _, want := range []string{"fingerprint", "cname-target-nxdomain", "tls"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence %q missing %q", ev, want)
		}
	}
}

// TestFingerprintPlusTLSMismatchOnly: even without NXDOMAIN, a fingerprint plus a
// TLS mismatch (default/provider cert) is two aligned signals → detected. This
// proves any ONE independent signal suffices (D2), not specifically NXDOMAIN.
func TestFingerprintPlusTLSMismatchOnly(t *testing.T) {
	db := testDB(t)
	host := "pages.example.com"
	d := NewDetector(db,
		WithResolver(stubResolver{chain: []string{"victim.github.io"}}, errNX), // resolves (no NXDOMAIN)
		WithBodyFetcher(func(_ context.Context, _ string) ([]byte, string, error) {
			return []byte("There isn't a GitHub Pages site here."), "https", nil
		}),
		WithTLSDialer(func(_ context.Context, _ string) (*tls.ConnectionState, error) {
			// A default GitHub wildcard cert that does NOT cover the host.
			return fakeCertState("*.github.io"), nil
		}),
	)
	sig, detected := d.Detect(context.Background(), host)
	if !detected {
		t.Fatalf("fingerprint + TLS mismatch should be detected, got %+v", sig)
	}
	if sig.TargetNXDOMAIN {
		t.Errorf("target should not be NXDOMAIN in this case")
	}
	if !sig.TLSMismatch {
		t.Errorf("default provider cert should be a TLS mismatch, got %+v", sig)
	}
}

// TestNoProviderEdge: a chain that ends at no known provider edge yields not
// detected (nothing to fingerprint), regardless of body content.
func TestNoProviderEdge(t *testing.T) {
	db := testDB(t)
	d := NewDetector(db,
		WithResolver(stubResolver{chain: []string{"some.random.host.example.net"}}, errNX),
		WithBodyFetcher(func(_ context.Context, _ string) ([]byte, string, error) {
			return []byte("There isn't a GitHub Pages site here."), "https", nil
		}),
		WithTLSDialer(func(_ context.Context, _ string) (*tls.ConnectionState, error) {
			return nil, errors.New("tls: fail")
		}),
	)
	sig, detected := d.Detect(context.Background(), "x.example.com")
	if detected {
		t.Fatalf("no provider edge must not be detected, got %+v", sig)
	}
}

// TestNXDomainClassProvider: for an nxdomain-class provider the fingerprint IS
// the NXDOMAIN observation; NXDOMAIN alone provides both the fingerprint and an
// independent signal, so a dangling workers.dev is detected.
func TestNXDomainClassProvider(t *testing.T) {
	db := testDB(t)
	host := "api.example.com"
	d := NewDetector(db,
		WithResolver(stubResolver{chain: []string{"gone.workers.dev"}, err: errNX}, errNX),
		WithBodyFetcher(func(_ context.Context, _ string) ([]byte, string, error) {
			return nil, "", errors.New("no body") // body irrelevant for NX-class
		}),
		WithTLSDialer(func(_ context.Context, h string) (*tls.ConnectionState, error) {
			return fakeCertState(h), nil // even a matching cert: NXDOMAIN already corroborates
		}),
	)
	sig, detected := d.Detect(context.Background(), host)
	if !detected {
		t.Fatalf("dangling NXDOMAIN-class provider must be detected, got %+v", sig)
	}
	if !sig.FingerprintMatch || !sig.TargetNXDOMAIN {
		t.Errorf("NX-class: fingerprint and target-NXDOMAIN should both be set, got %+v", sig)
	}
}

// TestTLSMismatchHelper exercises the cert-mismatch classifier directly.
func TestTLSMismatchHelper(t *testing.T) {
	cases := []struct {
		name  string
		state *tls.ConnectionState
		host  string
		want  bool
	}{
		{"no tls", nil, "a.example.com", true},
		{"empty chain", &tls.ConnectionState{}, "a.example.com", true},
		{"owner cert covers host", fakeCertState("a.example.com"), "a.example.com", false},
		{"cert does not cover host", fakeCertState("b.example.com"), "a.example.com", true},
		{"default provider wildcard", fakeCertState("*.github.io"), "a.example.com", true},
		{"owner cert wins over default marker", fakeCertState("a.example.com", "*.github.io"), "a.example.com", false},
	}
	for _, tc := range cases {
		if got := tlsCertMismatch(tc.state, tc.host); got != tc.want {
			t.Errorf("%s: tlsCertMismatch = %v, want %v", tc.name, got, tc.want)
		}
	}
}
