package ct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sampleCrtsh mirrors a crt.sh JSON response: an array of records, where
// name_value may carry several newline-joined SAN names, and not_before uses
// the dotted-microsecond layout crt.sh emits.
const sampleCrtsh = `[
  {"name_value":"dev.example.com\n*.dev.example.com","not_before":"2026-05-01T08:00:00","not_after":"2026-08-01T08:00:00","issuer_name":"C=US, O=Let's Encrypt, CN=R3"},
  {"name_value":"www.example.com","not_before":"2026-04-01T10:00:00.123456","not_after":"2026-07-01T10:00:00","issuer_name":"C=US, O=Let's Encrypt, CN=R3"},
  {"name_value":"dev.example.com","not_before":"2026-05-01T08:00:00","not_after":"2026-08-01T08:00:00","issuer_name":"C=US, O=Let's Encrypt, CN=R3"}
]`

func newTestServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); !strings.HasPrefix(got, "%.") {
			t.Errorf("expected wildcard query, got %q", got)
		}
		if got := r.URL.Query().Get("output"); got != "json" {
			t.Errorf("expected output=json, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestQuery_ParsesAndDeduplicates(t *testing.T) {
	srv := newTestServer(t, sampleCrtsh)
	c := NewClient(Config{BaseURL: srv.URL, RateLimit: -1})

	certs, err := c.Query(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	// dev.example.com appears three ways (bare, wildcard, duplicate record) but
	// the wildcard collapses to dev.example.com and the duplicate (name,
	// not_before) is dropped — so two distinct names total.
	names := map[string]int{}
	for _, c := range certs {
		names[c.Name]++
	}
	if names["dev.example.com"] != 1 {
		t.Errorf("dev.example.com: want 1 unique cert, got %d (%+v)", names["dev.example.com"], certs)
	}
	if names["www.example.com"] != 1 {
		t.Errorf("www.example.com: want 1, got %d", names["www.example.com"])
	}
	if len(certs) != 2 {
		t.Fatalf("want 2 certs, got %d: %+v", len(certs), certs)
	}
}

func TestQuery_FlagsTakeoverCandidates(t *testing.T) {
	srv := newTestServer(t, sampleCrtsh)
	c := NewClient(Config{BaseURL: srv.URL, RateLimit: -1})

	candidates := map[string]bool{"DEV.example.com": true} // mixed case on purpose
	certs, err := c.Query(context.Background(), "example.com", candidates)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	var flagged, unflagged int
	for _, cert := range certs {
		if cert.Name == "dev.example.com" {
			if !cert.TakeoverCandidate {
				t.Errorf("dev.example.com should be flagged as takeover candidate")
			}
			flagged++
		}
		if cert.Name == "www.example.com" {
			if cert.TakeoverCandidate {
				t.Errorf("www.example.com should NOT be flagged")
			}
			unflagged++
		}
	}
	if flagged != 1 || unflagged != 1 {
		t.Fatalf("flagged=%d unflagged=%d; want 1/1", flagged, unflagged)
	}
}

func TestQuery_ParsesNotBefore(t *testing.T) {
	srv := newTestServer(t, sampleCrtsh)
	c := NewClient(Config{BaseURL: srv.URL, RateLimit: -1})

	certs, err := c.Query(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	for _, cert := range certs {
		if cert.Name == "dev.example.com" && !cert.NotBefore.Equal(want) {
			t.Errorf("dev.example.com NotBefore = %v, want %v", cert.NotBefore, want)
		}
	}
}

func TestQuery_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := NewClient(Config{BaseURL: srv.URL, RateLimit: -1})

	if _, err := c.Query(context.Background(), "example.com", nil); err == nil {
		t.Fatal("expected error on 503, got nil")
	}
}

func TestQuery_EmptyApex(t *testing.T) {
	c := NewClient(Config{RateLimit: -1})
	if _, err := c.Query(context.Background(), "   ", nil); err == nil {
		t.Fatal("expected error on empty apex")
	}
}

func TestCandidatesFromFindings(t *testing.T) {
	jsonl := `{"subdomain":"dev.example.com","vector":"cname","confidence":"LIKELY","timestamp":"2026-05-01T00:00:00Z"}
{"subdomain":"OLD.example.com","vector":"ns","confidence":"POTENTIAL","timestamp":"2026-05-01T00:00:00Z"}

{"subdomain":"mail.example.com","vector":"mx","confidence":"CONFIRMED","timestamp":"2026-05-01T00:00:00Z"}
`
	set, err := CandidatesFromFindings(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("CandidatesFromFindings: %v", err)
	}
	for _, want := range []string{"dev.example.com", "old.example.com", "mail.example.com"} {
		if !set[want] {
			t.Errorf("candidate set missing %q: %v", want, set)
		}
	}
	if len(set) != 3 {
		t.Errorf("want 3 candidates, got %d: %v", len(set), set)
	}
}

func TestCandidatesFromFindings_BadLine(t *testing.T) {
	if _, err := CandidatesFromFindings(strings.NewReader("{not json}\n")); err == nil {
		t.Fatal("expected parse error on malformed JSONL")
	}
}

func TestApex(t *testing.T) {
	cases := map[string]string{
		"dev.example.com":         "example.com",
		"a.b.c.example.com":       "example.com",
		"example.com":             "example.com",
		"DEV.Example.COM.":        "example.com",
		"sub.example.co.uk":       "example.co.uk",
		"deep.sub.example.com.au": "example.com.au",
		"localhost":               "localhost",
		"":                        "",
	}
	for in, want := range cases {
		if got := Apex(in); got != want {
			t.Errorf("Apex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupeApexes(t *testing.T) {
	in := []string{
		"dev.example.com",
		"www.example.com",
		"app.other.org",
		"api.example.com",
		"other.org",
	}
	got := DedupeApexes(in)
	want := []string{"example.com", "other.org"}
	if len(got) != len(want) {
		t.Fatalf("DedupeApexes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DedupeApexes[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRateLimit_FirstCallImmediate(t *testing.T) {
	srv := newTestServer(t, "[]")
	c := NewClient(Config{BaseURL: srv.URL, RateLimit: time.Hour}) // huge interval

	start := time.Now()
	if _, err := c.Query(context.Background(), "example.com", nil); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("first query blocked %v; should be immediate", elapsed)
	}
}
