package confirm

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// fakeBlaster builds a blaster whose probes are driven by in-memory data so the
// blast-radius characterization is tested deterministically without network I/O.
func fakeBlaster(cookies map[string][]*http.Cookie, statuses map[string]int) *blaster {
	return &blaster{
		setCookies: func(_ context.Context, apexURL string) []*http.Cookie {
			return cookies[apexURL]
		},
		statusOf: func(_ context.Context, url string) int {
			if s, ok := statuses[url]; ok {
				return s
			}
			return 0
		},
	}
}

// TestBlast_SharedCookieScope: a takeover of a subdomain whose apex sets a
// Domain=.apex cookie reports the cookie-scope (session-theft) blast radius —
// the big severity driver (§12 acceptance #3).
func TestBlast_SharedCookieScope(t *testing.T) {
	b := fakeBlaster(
		map[string][]*http.Cookie{
			"https://example.com": {{Name: "session", Value: "x", Domain: ".example.com"}},
		},
		nil,
	)
	got := b.Radius(context.Background(), "static.example.com")
	if !strings.Contains(got, "shares *.example.com cookies") {
		t.Errorf("expected shared-cookie blast radius, got %q", got)
	}
	if !strings.Contains(got, "session theft") {
		t.Errorf("shared cookie should call out session theft, got %q", got)
	}
	// ACME issuance is always present.
	if !strings.Contains(got, "ACME cert issuable") {
		t.Errorf("ACME issuance should always be noted, got %q", got)
	}
}

// TestBlast_IsolatedSubdomain: a subdomain whose apex sets only a host-only
// cookie (no Domain attribute) does NOT report a shared-cookie blast radius
// (§12 acceptance #3, the negative).
func TestBlast_IsolatedSubdomain(t *testing.T) {
	b := fakeBlaster(
		map[string][]*http.Cookie{
			// Host-only cookie (Domain empty) is not shared with subdomains.
			"https://example.com": {{Name: "csrftoken", Value: "y", Domain: ""}},
		},
		nil,
	)
	got := b.Radius(context.Background(), "isolated.example.com")
	if strings.Contains(got, "shares") {
		t.Errorf("a host-only cookie must NOT yield a shared-cookie blast radius, got %q", got)
	}
	if !strings.Contains(got, "content control of isolated.example.com") {
		t.Errorf("blast radius must always state content control, got %q", got)
	}
}

// TestBlast_OAuthRedirectFlag: a subdomain that answers a common OAuth callback
// path is flagged as a candidate account-takeover primitive (the hand-off to
// P10), but only as a flag — graverobber does not run the attack.
func TestBlast_OAuthRedirectFlag(t *testing.T) {
	b := fakeBlaster(nil, map[string]int{
		"https://login.example.com/oauth/callback": http.StatusOK,
	})
	got := b.Radius(context.Background(), "login.example.com")
	if !strings.Contains(got, "OAuth redirect_uri") || !strings.Contains(got, "account takeover") {
		t.Errorf("a resolving OAuth callback should flag account-takeover candidacy, got %q", got)
	}
	if !strings.Contains(got, "P10") {
		t.Errorf("the OAuth flag should hand off to the OAuth tool (P10), got %q", got)
	}
}

// TestBlast_NoOAuthWhenServerError: a 5xx on the callback paths is not a flag (no
// false OAuth claim).
func TestBlast_NoOAuthWhenServerError(t *testing.T) {
	b := fakeBlaster(nil, map[string]int{
		"https://x.example.com/callback":       http.StatusBadGateway,
		"https://x.example.com/oauth/callback": http.StatusServiceUnavailable,
	})
	got := b.Radius(context.Background(), "x.example.com")
	if strings.Contains(got, "OAuth redirect_uri") {
		t.Errorf("server errors on callback paths must NOT flag OAuth, got %q", got)
	}
}

// TestCookieScopesTo covers the cookie-domain scoping predicate directly.
func TestCookieScopesTo(t *testing.T) {
	cases := []struct {
		domain string
		fqdn   string
		want   bool
	}{
		{".example.com", "static.example.com", true},
		{"example.com", "static.example.com", true},
		{".example.com", "example.com", true},
		{"", "static.example.com", false},           // host-only cookie
		{".other.com", "static.example.com", false}, // different apex
		{".example.com", "static.notexample.com", false},
	}
	for _, tc := range cases {
		ck := &http.Cookie{Domain: tc.domain}
		if got := cookieScopesTo(ck, tc.fqdn); got != tc.want {
			t.Errorf("cookieScopesTo(Domain=%q, %q) = %v, want %v", tc.domain, tc.fqdn, got, tc.want)
		}
	}
}

// TestBlastRadius_AlwaysContentAndACME verifies the invariant that a blast radius
// always states content control and ACME issuability even when NO probe fires
// (the empty-data blaster mirrors a host whose probes all fail/return nothing).
// It uses the injectable blaster so the test is fully deterministic — no network.
func TestBlastRadius_AlwaysContentAndACME(t *testing.T) {
	b := fakeBlaster(nil, nil) // every probe returns empty/0 → no extra signals
	got := b.Radius(context.Background(), "isolated.example.com")
	if !strings.Contains(got, "content control of isolated.example.com") {
		t.Errorf("blast radius must always state content control, got %q", got)
	}
	if !strings.Contains(got, "ACME cert issuable") {
		t.Errorf("blast radius must always note ACME issuability, got %q", got)
	}
	// With no cookie or OAuth signal, neither escalation should be claimed.
	if strings.Contains(got, "shares") || strings.Contains(got, "OAuth") {
		t.Errorf("no escalation should be claimed without signals, got %q", got)
	}
}
