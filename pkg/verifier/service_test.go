package verifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// rewriteTransport redirects every outbound request to the test server's host
// while preserving the original request path. This lets the ServiceVerifier
// build real S3/GitHub URLs (from the finding) yet have them answered by an
// httptest.Server on an ephemeral port — no real network, no fixed port.
type rewriteTransport struct {
	base *url.URL // the httptest server's URL (scheme + host)
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.base.Scheme
	req.URL.Host = rt.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

// clientFor builds an *http.Client whose every request is rewritten to srv.
func clientFor(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &http.Client{Transport: rewriteTransport{base: u}}
}

// ---- AWS/S3 ----------------------------------------------------------------

func TestServiceVerifier_S3_NoSuchBucket_Confirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>`))
	}))
	defer srv.Close()

	sv := NewServiceVerifier(Config{})
	sv.client = clientFor(t, srv)

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "AWS/S3",
		Confidence: finding.Likely,
		CNAME:      "my-bucket.s3.amazonaws.com",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Confirmed {
		t.Errorf("S3 NoSuchBucket + 404: confidence = %q, want CONFIRMED", got)
	}
}

func TestServiceVerifier_S3_BucketExists_NoUpgrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A live bucket: 200, no NoSuchBucket marker.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sv := NewServiceVerifier(Config{})
	sv.client = clientFor(t, srv)

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "AWS/S3",
		Confidence: finding.Likely,
		CNAME:      "live-bucket.s3.amazonaws.com",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Likely {
		t.Errorf("S3 live bucket: confidence = %q, want LIKELY (unchanged)", got)
	}
}

// ---- GitHub Pages ----------------------------------------------------------

func TestServiceVerifier_GitHubPages_RepoMissing_Confirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/repos/acme/acme.github.io" {
			t.Errorf("GH API path = %q, want /repos/acme/acme.github.io", got)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	sv := NewServiceVerifier(Config{})
	sv.client = clientFor(t, srv)

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "GitHub Pages",
		Confidence: finding.Likely,
		CNAME:      "acme.github.io",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Confirmed {
		t.Errorf("GH repo 404: confidence = %q, want CONFIRMED", got)
	}
}

func TestServiceVerifier_GitHubPages_RepoExists_NoUpgrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"acme.github.io"}`))
	}))
	defer srv.Close()

	sv := NewServiceVerifier(Config{})
	sv.client = clientFor(t, srv)

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "GitHub Pages",
		Confidence: finding.Likely,
		CNAME:      "acme.github.io",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Likely {
		t.Errorf("GH repo 200: confidence = %q, want LIKELY (unchanged)", got)
	}
}

func TestServiceVerifier_GitHubPages_TokenSetsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	sv := NewServiceVerifier(Config{GitHubToken: "gh_secret"})
	sv.client = clientFor(t, srv)

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "GitHub Pages",
		Confidence: finding.Likely,
		CNAME:      "acme.github.io",
	}
	if _, err := sv.Verify(context.Background(), f); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotAuth != "Bearer gh_secret" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer gh_secret")
	}
}

// ---- Microsoft Azure -------------------------------------------------------

func TestServiceVerifier_Azure_NXDomain_Confirms(t *testing.T) {
	sv := NewServiceVerifier(Config{})
	sv.nxLookup = func(_ context.Context, host string) (bool, error) {
		if host != "deadapp.azurewebsites.net" {
			t.Errorf("nxLookup host = %q, want deadapp.azurewebsites.net", host)
		}
		return true, nil // NXDOMAIN
	}

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "Microsoft Azure",
		Confidence: finding.Likely,
		CNAME:      "deadapp.azurewebsites.net",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Confirmed {
		t.Errorf("Azure NXDOMAIN: confidence = %q, want CONFIRMED", got)
	}
}

func TestServiceVerifier_Azure_Resolves_NoUpgrade(t *testing.T) {
	sv := NewServiceVerifier(Config{})
	sv.nxLookup = func(_ context.Context, _ string) (bool, error) {
		return false, nil // still resolves — not NXDOMAIN
	}

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "Microsoft Azure",
		Confidence: finding.Likely,
		CNAME:      "liveapp.azurewebsites.net",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Likely {
		t.Errorf("Azure resolves: confidence = %q, want LIKELY (unchanged)", got)
	}
}

func TestServiceVerifier_Azure_NonAzureTarget_NoUpgrade(t *testing.T) {
	sv := NewServiceVerifier(Config{})
	sv.nxLookup = func(_ context.Context, _ string) (bool, error) {
		t.Error("nxLookup must not be called for a non-Azure CNAME target")
		return true, nil
	}

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "Microsoft Azure",
		Confidence: finding.Likely,
		CNAME:      "something.example.com", // not an Azure-owned suffix
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Likely {
		t.Errorf("Azure non-azure target: confidence = %q, want LIKELY (unchanged)", got)
	}
}

func TestServiceVerifier_Azure_AlreadyConfirmed_NotDowngraded(t *testing.T) {
	sv := NewServiceVerifier(Config{})
	sv.nxLookup = func(_ context.Context, _ string) (bool, error) {
		t.Error("nxLookup must not be called when finding is already CONFIRMED")
		return false, nil
	}

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "Microsoft Azure",
		Confidence: finding.Confirmed, // body-match already confirmed
		CNAME:      "liveapp.azurewebsites.net",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Confirmed {
		t.Errorf("Azure already confirmed: confidence = %q, want CONFIRMED (unchanged)", got)
	}
}

// ---- dispatch / fallthrough ------------------------------------------------

func TestServiceVerifier_UnknownService_Unchanged(t *testing.T) {
	sv := NewServiceVerifier(Config{})

	f := finding.Finding{
		Vector:     finding.VectorCNAME,
		Service:    "Heroku",
		Confidence: finding.Likely,
		CNAME:      "x.herokuapp.com",
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Likely {
		t.Errorf("unknown service: confidence = %q, want LIKELY (unchanged)", got)
	}
}

func TestServiceVerifier_NonCNAMEVector_Unchanged(t *testing.T) {
	sv := NewServiceVerifier(Config{})
	// An NS finding that happens to carry a service name must not trigger an
	// HTTP probe — active verification is CNAME-vector only.
	sv.client = nil // would panic if a probe were attempted

	f := finding.Finding{
		Vector:     finding.VectorNS,
		Service:    "AWS/S3",
		Confidence: finding.Potential,
	}
	got, err := sv.Verify(context.Background(), f)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != finding.Potential {
		t.Errorf("non-CNAME vector: confidence = %q, want POTENTIAL (unchanged)", got)
	}
}

// compile-time guarantee the struct satisfies the interface.
var _ Verifier = (*ServiceVerifier)(nil)
