package confirm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCanary_NewIsUniqueAndNonEmpty: minted canaries have non-empty, distinct
// IDs and tokens. An empty token would make every reflection check trivially
// match, so non-emptiness is a safety property.
func TestCanary_NewIsUniqueAndNonEmpty(t *testing.T) {
	c := NewCanaries()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		can := c.New()
		if can.ID == "" || can.Token == "" {
			t.Fatalf("canary must be non-empty: %+v", can)
		}
		if !strings.HasPrefix(can.Token, "nmc-canary-") {
			t.Errorf("token should be namespaced, got %q", can.Token)
		}
		if seen[can.ID] {
			t.Fatalf("duplicate canary ID %q", can.ID)
		}
		seen[can.ID] = true
	}
}

// TestCanary_Path returns the hidden well-known path.
func TestCanary_Path(t *testing.T) {
	c := &Canary{ID: "abcd1234"}
	if got := c.Path(); got != "/.well-known/nmc-abcd1234" {
		t.Errorf("Path() = %q, want /.well-known/nmc-abcd1234", got)
	}
}

// TestCanary_ReflectedAt_HTTP exercises the real HTTP reflector against an
// httptest server: a body containing the token reflects; one without does not.
func TestCanary_ReflectedAt_HTTP(t *testing.T) {
	c := NewCanaries()
	canary := c.New()

	hit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("prefix " + canary.Token + " suffix"))
	}))
	defer hit.Close()
	miss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer miss.Close()

	if !c.ReflectedAt(context.Background(), hit.URL, canary) {
		t.Error("token present in body should reflect")
	}
	if c.ReflectedAt(context.Background(), miss.URL, canary) {
		t.Error("token absent from body must not reflect")
	}
	// A nil canary or empty URL never reflects.
	if c.ReflectedAt(context.Background(), "", canary) || c.ReflectedAt(context.Background(), hit.URL, nil) {
		t.Error("nil canary / empty URL must not reflect")
	}
}

// TestCanary_CustomReflector lets a test substitute the reflection check.
func TestCanary_CustomReflector(t *testing.T) {
	var gotURL string
	c := NewCanaries(WithReflector(func(_ context.Context, url string, _ *Canary) bool {
		gotURL = url
		return true
	}))
	canary := c.New()
	if !c.ReflectedAt(context.Background(), "https://x.example.com/p", canary) {
		t.Error("custom reflector should report true")
	}
	if gotURL != "https://x.example.com/p" {
		t.Errorf("reflector got url %q", gotURL)
	}
}
