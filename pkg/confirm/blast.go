package confirm

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// BlastRadius characterizes what a confirmed takeover of fqdn grants — the
// difference between "confirmed takeover" (half a finding) and "confirmed
// takeover of a subdomain that shares session cookies and sits in an OAuth
// allow-list" (the finding, and its severity).
//
// It checks, read-only and non-destructively:
//
//  1. Cookie scope (the big severity driver). If the apex sets a cookie with
//     Domain=.<apex>, that cookie is sent to every subdomain — including a
//     taken-over one — so content control of the subdomain becomes session theft
//     / CSRF surface. A takeover of static.example.com where the app sets
//     Domain=.example.com cookies is categorically worse than an isolated host.
//  2. OAuth redirect / account-takeover candidacy (a FLAG, not the attack).
//     Common OAuth-callback path shapes resolving on the FQDN suggest it may sit
//     in a redirect_uri allow-list, which would make the takeover an
//     account-takeover primitive. graverobber notes this and hands off to the
//     OAuth tool; it does NOT run the capture (scope).
//  3. ACME certificate issuability. A confirmed takeover lets the holder obtain a
//     valid TLS certificate for the FQDN via ACME → phishing with a real padlock.
//     This is always true for a content takeover, so it is always noted.
//
// BlastRadius performs only benign GET/HEAD requests with a short timeout and a
// bounded body; it never sends mail, never completes an OAuth flow, and never
// serves content. A nil/zero result is impossible — it always returns at least
// "content control of <fqdn>".
func BlastRadius(ctx context.Context, fqdn string) string {
	return defaultBlaster.Radius(ctx, fqdn)
}

// blaster holds the (injectable) probes behind BlastRadius so tests can drive
// the characterization deterministically without real network I/O.
type blaster struct {
	// setCookies returns the Set-Cookie cookies observed when fetching the apex.
	setCookies func(ctx context.Context, apexURL string) []*http.Cookie
	// statusOf returns the HTTP status of a GET to url (or >=500 / 0 on failure).
	statusOf func(ctx context.Context, url string) int
}

// defaultBlaster wires the real HTTP probes.
var defaultBlaster = &blaster{
	setCookies: httpSetCookies,
	statusOf:   httpStatus,
}

// Radius is the characterization, parameterized over the blaster's probes.
func (b *blaster) Radius(ctx context.Context, fqdn string) string {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	parts := []string{"content control of " + host}

	// 1) Cookie scope.
	if b.sharesCookieScope(ctx, host) {
		parts = append(parts, "shares *."+apexOf(host)+" cookies (session theft / CSRF surface)")
	}
	// 2) OAuth redirect candidacy.
	if b.plausibleOAuthRedirect(ctx, host) {
		parts = append(parts, "candidate OAuth redirect_uri -> account takeover (hand to OAuth tool, P10)")
	}
	// 3) ACME issuance (always available on a content takeover).
	parts = append(parts, "ACME cert issuable (valid-TLS phishing surface)")
	return strings.Join(parts, "; ")
}

// sharesCookieScope reports whether the apex sets a parent-domain cookie
// (Domain=.<apex>) that would also be sent to fqdn. That is the session-theft
// severity driver.
func (b *blaster) sharesCookieScope(ctx context.Context, fqdn string) bool {
	apex := apexOf(fqdn)
	if apex == "" {
		return false
	}
	for _, scheme := range []string{"https", "http"} {
		cookies := b.setCookies(ctx, scheme+"://"+apex)
		for _, ck := range cookies {
			if cookieScopesTo(ck, fqdn) {
				return true
			}
		}
		if len(cookies) > 0 {
			break // got a response on this scheme; don't double-probe
		}
	}
	return false
}

// cookieScopesTo reports whether a Set-Cookie's Domain attribute scopes the
// cookie to fqdn. A leading-dot Domain (Domain=.example.com) — or a bare apex
// Domain that fqdn is a subdomain of — reaches the subdomain. A cookie with no
// Domain attribute is host-only (does NOT scope to subdomains) and is ignored.
func cookieScopesTo(ck *http.Cookie, fqdn string) bool {
	if ck == nil || ck.Domain == "" {
		return false // host-only cookie: not shared with subdomains
	}
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ck.Domain)), ".")
	if d == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	return host == d || strings.HasSuffix(host, "."+d)
}

// oauthCallbackPaths are common OAuth/OIDC redirect-endpoint path shapes. A
// non-server-error response at one of these on the FQDN is a heuristic flag that
// the host may participate in an OAuth flow (and thus sit in a redirect_uri
// allow-list). It is deliberately a weak signal surfaced as a candidate, not a
// claim — the OAuth tool (P10) decides.
var oauthCallbackPaths = []string{
	"/callback",
	"/oauth/callback",
	"/oauth2/callback",
	"/auth/callback",
	"/signin-oidc",
	"/login/oauth2/code",
}

// plausibleOAuthRedirect reports whether any common OAuth-callback path responds
// on fqdn with a non-server-error status. Purely a flag; never completes a flow.
func (b *blaster) plausibleOAuthRedirect(ctx context.Context, fqdn string) bool {
	for _, p := range oauthCallbackPaths {
		st := b.statusOf(ctx, "https://"+fqdn+p)
		if st > 0 && st < 500 {
			return true
		}
	}
	return false
}

// --- real HTTP probes (read-only, bounded) ---------------------------------

// blastClient is a short-timeout client used for the read-only blast-radius
// probes. It does NOT follow redirects (so a 302 from an OAuth endpoint is
// observed as-is, not chased into a real flow) and skips TLS verification (a
// dangling/just-claimed edge often serves a mismatched cert — the probe must
// still observe the status, exactly as the detector's HTTP probe does).
var blastClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		// See pkg/detectors: dangling edges characteristically serve mismatched
		// certs; the blast probe is recon, not a trust-sensitive connection.
		TLSClientConfig: blastTLSConfig(),
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 6 * time.Second,
	},
}

func httpSetCookies(ctx context.Context, apexURL string) []*http.Cookie {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apexURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "graverobber/confirm")
	resp, err := blastClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	return resp.Cookies()
}

func httpStatus(ctx context.Context, url string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "graverobber/confirm")
	resp, err := blastClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
