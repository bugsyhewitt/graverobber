package links

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// samplePage embeds a mix of cross-origin references the way a real app does:
// an absolute https URL, a scheme-relative CDN URL, a bare quoted host inside a
// JS config blob, plus same-apex and non-host noise that must be filtered out.
const samplePage = `<!doctype html>
<html><head>
<script src="https://cdn.thirdparty.net/app.js"></script>
<link rel="preconnect" href="//analytics.tracker.io/collect">
</head><body>
<script>window.cfg = {api:"api.example.com", legacy:"old-oauth.forgotten.org", v:"1.2.3"};</script>
<img src="https://www.example.com/logo.png">
<a href="https://192.168.0.1/admin">ip</a>
</body></html>`

func newServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// clientForServer builds a Client whose default transport is redirected at the
// httptest server, so Extract("example.com") actually hits the stub regardless
// of scheme/host. This lets us exercise the real fetch path without network.
func clientForServer(srv *httptest.Server) *Client {
	rt := func(req *http.Request) (*http.Response, error) {
		// Rewrite any outbound request to the test server.
		u := req.URL
		u.Scheme = "http"
		u.Host = srv.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(req)
	}
	return NewClient(Config{
		HTTPClient: &http.Client{Transport: roundTripFunc(rt), Timeout: 5 * time.Second},
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExtractHosts_FindsCrossOriginRefs(t *testing.T) {
	got := ExtractHosts([]byte(samplePage))
	want := map[string]bool{
		"cdn.thirdparty.net":      true,
		"analytics.tracker.io":    true,
		"api.example.com":         true,
		"old-oauth.forgotten.org": true,
		"www.example.com":         true,
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host extracted: %q (full: %v)", h, got)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("missing expected hosts: %v (got %v)", want, got)
	}
}

func TestExtractHosts_RejectsIPsAndVersions(t *testing.T) {
	for _, h := range ExtractHosts([]byte(samplePage)) {
		if h == "192.168.0.1" {
			t.Errorf("IPv4 literal must not be treated as a host: %q", h)
		}
		if h == "1.2.3" {
			t.Errorf("version string must not be treated as a host: %q", h)
		}
	}
}

func TestExtract_FiltersSameApex(t *testing.T) {
	srv := newServer(t, http.StatusOK, samplePage)
	c := clientForServer(srv)

	refs, err := c.Extract(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	hosts := map[string]bool{}
	for _, r := range refs {
		hosts[r.Host] = true
		if r.Source != "www.example.com" {
			t.Errorf("Source = %q, want www.example.com", r.Source)
		}
	}
	// Same-apex refs (api.example.com, www.example.com) must be excluded.
	if hosts["api.example.com"] || hosts["www.example.com"] {
		t.Errorf("same-apex host leaked into second-order refs: %v", hosts)
	}
	// Genuine cross-origin refs must survive.
	for _, want := range []string{"cdn.thirdparty.net", "analytics.tracker.io", "old-oauth.forgotten.org"} {
		if !hosts[want] {
			t.Errorf("missing cross-origin ref %q: %v", want, hosts)
		}
	}
}

func TestExtract_NonOKStatusStillExtracts(t *testing.T) {
	srv := newServer(t, http.StatusNotFound, samplePage)
	c := clientForServer(srv)

	refs, err := c.Extract(context.Background(), "dead.example.com")
	if err != nil {
		t.Fatalf("Extract on 404 should still parse body: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("expected refs from a 404 body, got none")
	}
}

func TestExtract_DedupesAcrossForms(t *testing.T) {
	// The same host appears as absolute URL, scheme-relative, and quoted bare.
	body := `a https://dup.example.org/x b //dup.example.org/y c "dup.example.org"`
	srv := newServer(t, http.StatusOK, body)
	c := clientForServer(srv)

	refs, err := c.Extract(context.Background(), "site.test")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var count int
	for _, r := range refs {
		if r.Host == "dup.example.org" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dup.example.org appeared %d times, want 1 (deduped): %+v", count, refs)
	}
}

func TestExtract_EmptyTarget(t *testing.T) {
	c := NewClient(Config{})
	if _, err := c.Extract(context.Background(), "   "); err == nil {
		t.Fatal("expected error on empty target")
	}
}

func TestExtract_TransportFailureIsError(t *testing.T) {
	// Closed server: every scheme attempt fails at the transport.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.Listener.Addr().String()
	srv.Close()
	c := NewClient(Config{
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = addr
				return http.DefaultTransport.RoundTrip(req)
			}),
			Timeout: 2 * time.Second,
		},
	})
	if _, err := c.Extract(context.Background(), "unreachable.example.com"); err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestApex(t *testing.T) {
	cases := map[string]string{
		"cdn.thirdparty.net": "thirdparty.net",
		"a.b.c.example.com":  "example.com",
		"example.com":        "example.com",
		"sub.example.co.uk":  "example.co.uk",
		"":                   "",
	}
	for in, want := range cases {
		if got := Apex(in); got != want {
			t.Errorf("Apex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeHost_StripsPortAndRejectsBareLabels(t *testing.T) {
	cases := map[string]string{
		"CDN.Example.NET:8443": "cdn.example.net",
		"example.com.":         "example.com",
		"localhost":            "",
		"10.0.0.1":             "",
		" host.io ":            "host.io",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
