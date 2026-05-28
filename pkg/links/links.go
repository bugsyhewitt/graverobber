// Package links implements graverobber's second-order takeover discovery step.
//
// Second-order subdomain takeover (Patrik Hudak; the `second-order` Go tool)
// occurs when a live web application references a host in its HTML, JavaScript,
// or JSON responses that is itself dangling — a forgotten analytics endpoint, a
// legacy CDN URL, an abandoned OAuth redirect host. The referencing page
// resolves and serves fine; the vulnerability is one hop deeper, in a host the
// page points at.
//
// links does exactly the extraction half of that loop and nothing more: it
// fetches a live target, pulls every cross-origin host reference out of the
// response body, and returns those hosts. It deliberately does NOT run the
// scanner itself — keeping graverobber pipeline-friendly (stdin→stdout) per the
// project ethos. The intended use is:
//
//	graverobber links -l live-hosts.txt | graverobber scan --json
//
// links is a leaf package: it depends only on the standard library. It does not
// touch the core scanner, the resolver, or the fingerprint database.
package links

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultTimeout bounds a single page fetch when Config.Timeout is zero.
const DefaultTimeout = 15 * time.Second

// maxBodyBytes caps a single page read. Large bundled JS files are common; this
// guards against an unbounded read of a hostile or oversized response.
const maxBodyBytes = 16 << 20 // 16 MiB

// hostRefRe matches the host portion of a URL-like token in a response body.
// It is intentionally permissive: it catches absolute URLs (https://host/...),
// scheme-relative URLs (//host/...), and bare quoted hostnames in JS/JSON
// ("cdn.example.net"). The host is captured in group 1.
//
// The trailing label is constrained to a 2–24 char alphabetic TLD so version
// strings ("1.2.3"), IP addresses, and dotted identifiers do not masquerade as
// hosts. This errs toward precision: a missed exotic TLD is a benign omission,
// whereas a false host pollutes the downstream scan.
var hostRefRe = regexp.MustCompile(
	`(?i)(?:https?:)?//([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,24})` +
		`|["'\x60]([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,24})["'\x60]`,
)

// Reference is a single cross-origin host reference discovered in a page.
type Reference struct {
	// Host is the referenced (sub)domain, lower-cased and normalized.
	Host string `json:"host"`
	// Source is the target host whose page referenced Host.
	Source string `json:"source"`
}

// Config configures a Client.
type Config struct {
	// Timeout bounds a single page fetch. Zero means DefaultTimeout.
	Timeout time.Duration
	// HTTPClient overrides the HTTP client (tests). Nil builds a default.
	HTTPClient *http.Client
	// UserAgent overrides the request User-Agent. Empty uses a default.
	UserAgent string
	// HTTPOnly fetches over http:// only (skips the https-first attempt).
	HTTPOnly bool
	// HTTPSOnly fetches over https:// only (no http fallback).
	HTTPSOnly bool
}

// Client fetches live pages and extracts cross-origin host references.
type Client struct {
	http      *http.Client
	userAgent string
	httpOnly  bool
	httpsOnly bool
}

// NewClient builds a Client from cfg.
func NewClient(cfg Config) *Client {
	httpc := cfg.HTTPClient
	if httpc == nil {
		to := cfg.Timeout
		if to == 0 {
			to = DefaultTimeout
		}
		httpc = &http.Client{Timeout: to}
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "graverobber-links/1.0"
	}
	return &Client{
		http:      httpc,
		userAgent: ua,
		httpOnly:  cfg.HTTPOnly,
		httpsOnly: cfg.HTTPSOnly,
	}
}

// Extract fetches target's live page and returns the unique cross-origin host
// references found in the body, excluding any host on the same registrable apex
// as target (those are first-order and the main scanner already covers them).
//
// Fetch strategy mirrors the scanner: https first, then http fallback on
// connect failure, unless HTTPOnly/HTTPSOnly constrains it. A non-2xx status is
// not an error — the body of an error page may still carry references — but a
// transport failure on every attempted scheme is.
func (c *Client) Extract(ctx context.Context, target string) ([]Reference, error) {
	host := normalizeHost(target)
	if host == "" {
		return nil, fmt.Errorf("links: empty target")
	}

	body, err := c.fetch(ctx, host)
	if err != nil {
		return nil, err
	}

	srcApex := Apex(host)
	hosts := ExtractHosts(body)

	seen := make(map[string]bool)
	var out []Reference
	for _, h := range hosts {
		if h == host || Apex(h) == srcApex {
			// Same host or same registrable apex: first-order, not second-order.
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, Reference{Host: h, Source: host})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

// fetch retrieves target's page body, applying the https-first / http-fallback
// scheme policy. It returns the body bytes of the first scheme that connects.
func (c *Client) fetch(ctx context.Context, host string) ([]byte, error) {
	var schemes []string
	switch {
	case c.httpOnly:
		schemes = []string{"http"}
	case c.httpsOnly:
		schemes = []string{"https"}
	default:
		schemes = []string{"https", "http"}
	}

	var lastErr error
	for _, scheme := range schemes {
		body, err := c.get(ctx, scheme+"://"+host+"/")
		if err == nil {
			return body, nil
		}
		lastErr = err
		// Abort the fallback loop if the context is done — no point retrying.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("links: fetch %s: %w", host, lastErr)
}

// get performs one GET and returns the (size-capped) body. A non-2xx response
// still returns its body: error pages frequently embed analytics/CDN hosts.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// ExtractHosts pulls every distinct URL-like host reference out of a response
// body and returns them sorted. It is exported so callers (and tests) can run
// the extraction over an arbitrary byte slice without an HTTP fetch.
func ExtractHosts(body []byte) []string {
	matches := hostRefRe.FindAllSubmatch(body, -1)
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		// Group 1 = absolute/scheme-relative URL host; group 2 = quoted bare host.
		raw := m[1]
		if len(raw) == 0 {
			raw = m[2]
		}
		h := normalizeHost(string(raw))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// normalizeHost trims whitespace and a trailing dot and lower-cases a hostname,
// stripping any port suffix. It rejects values that are not plausible hostnames
// (no dot, or all-numeric labels that are really IPs/versions).
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	if s == "" || !strings.Contains(s, ".") {
		return ""
	}
	// Reject bare IPv4 literals: every label numeric.
	allNumeric := true
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return ""
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				allNumeric = false
				break
			}
		}
		if !allNumeric {
			break
		}
	}
	if allNumeric {
		return ""
	}
	return s
}

// Apex reduces a hostname to its registrable apex using the same pragmatic
// last-two-labels heuristic (last three for common second-level ccTLDs) as the
// ct package, so the same-apex filter in Extract matches ct's deduplication. It
// is not a full Public Suffix List implementation; an over-broad apex merely
// makes the same-apex filter slightly more aggressive, which is the safe
// direction (it drops references, never invents them).
func Apex(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	labels := strings.Split(host, ".")
	clean := labels[:0]
	for _, l := range labels {
		if l != "" {
			clean = append(clean, l)
		}
	}
	if len(clean) < 2 {
		return strings.Join(clean, ".")
	}
	n := 2
	last := clean[len(clean)-1]
	secondLast := clean[len(clean)-2]
	if len(last) == 2 && len(secondLast) <= 3 && len(clean) >= 3 {
		n = 3
	}
	if n > len(clean) {
		n = len(clean)
	}
	return strings.Join(clean[len(clean)-n:], ".")
}
