// Package ct queries Certificate Transparency logs (via crt.sh) for recent
// certificate issuances on target domains and flags certificates issued for
// subdomains that graverobber classifies as takeover candidates.
//
// The detection loop this closes: the main scanner finds dangling-record
// candidates; ct confirms whether exploitation already occurred. An unexpected
// certificate issued for a dangling subdomain is near-proof a takeover has
// already happened — an attacker who claimed the resource provisioned TLS for
// it.
//
// ct is a leaf-ish package: it depends only on the standard library and
// pkg/finding (for cross-referencing a prior scan's output). It does not touch
// the core scanner.
package ct

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// DefaultBaseURL is the crt.sh JSON endpoint. crt.sh answers
// `?q=%.example.com&output=json` with a JSON array of certificate records and
// requires no authentication. It is injectable so tests can point at an
// httptest server.
const DefaultBaseURL = "https://crt.sh/"

// DefaultRateLimit is the polite query interval against crt.sh: roughly one
// request per second. crt.sh is a community service backed by a single
// PostgreSQL instance; hammering it gets you throttled or blocked.
const DefaultRateLimit = time.Second

// maxBodyBytes caps a single crt.sh response. Busy apex domains can return tens
// of thousands of certificates; this guards against an unbounded read.
const maxBodyBytes = 64 << 20 // 64 MiB

// crtshRecord is the subset of a crt.sh JSON record ct consumes. crt.sh returns
// more fields (id, serial_number, etc.) which are ignored.
type crtshRecord struct {
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	IssuerName string `json:"issuer_name"`
}

// Certificate is a single certificate-name observation emitted by the client.
// One crt.sh record may carry several SAN names (newline-joined in
// name_value); each distinct name yields one Certificate.
type Certificate struct {
	// Name is the (sub)domain the certificate was issued for.
	Name string `json:"name"`
	// Apex is the registrable apex the crt.sh query was keyed on.
	Apex string `json:"apex"`
	// NotBefore is the certificate validity start, parsed from crt.sh.
	NotBefore time.Time `json:"not_before"`
	// Issuer is the certificate issuer distinguished name.
	Issuer string `json:"issuer,omitempty"`
	// TakeoverCandidate is true when Name matches a subdomain in the prior-scan
	// candidate set supplied to the client. When no candidate set is supplied it
	// is always false.
	TakeoverCandidate bool `json:"takeover_candidate"`
}

// Config configures a Client.
type Config struct {
	// BaseURL overrides the crt.sh endpoint (tests point this at httptest).
	// Empty means DefaultBaseURL.
	BaseURL string
	// RateLimit is the minimum interval between upstream queries. Zero means
	// DefaultRateLimit; a negative value disables rate limiting (tests).
	RateLimit time.Duration
	// Timeout bounds a single crt.sh request. Zero means 30s.
	Timeout time.Duration
	// HTTPClient overrides the HTTP client (tests). Nil builds a default.
	HTTPClient *http.Client
}

// Client queries crt.sh for certificates on apex domains.
type Client struct {
	baseURL   string
	rateLimit time.Duration
	http      *http.Client
	// last gates the rate limiter; nil ticker channel disables it.
	limiter <-chan time.Time
}

// NewClient builds a Client from cfg.
func NewClient(cfg Config) *Client {
	base := cfg.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	rl := cfg.RateLimit
	if rl == 0 {
		rl = DefaultRateLimit
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		to := cfg.Timeout
		if to == 0 {
			to = 30 * time.Second
		}
		httpc = &http.Client{Timeout: to}
	}
	c := &Client{
		baseURL:   base,
		rateLimit: rl,
		http:      httpc,
	}
	return c
}

// Query fetches all certificates crt.sh knows for apex (and its subdomains),
// keyed on the wildcard query `%.<apex>`. candidates, when non-nil, is the set
// of subdomains a prior graverobber scan flagged as takeover candidates;
// returned certificates whose Name is in that set have TakeoverCandidate=true.
//
// candidates keys are matched case-insensitively against each certificate name.
func (c *Client) Query(ctx context.Context, apex string, candidates map[string]bool) ([]Certificate, error) {
	apex = normalizeHost(apex)
	if apex == "" {
		return nil, fmt.Errorf("ct: empty apex")
	}

	if err := c.wait(ctx); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("q", "%."+apex)
	q.Set("output", "json")
	u := strings.TrimRight(c.baseURL, "/") + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "graverobber-ct/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ct: fetch %s: %w", apex, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ct: fetch %s: unexpected status %s", apex, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ct: read %s: %w", apex, err)
	}

	return parseRecords(body, apex, candidates)
}

// wait blocks until the rate limiter permits the next request, or ctx is done.
// The first call returns immediately; subsequent calls space out by rateLimit.
func (c *Client) wait(ctx context.Context) error {
	if c.rateLimit <= 0 {
		return nil
	}
	if c.limiter == nil {
		// Lazily start the ticker on first use so the very first query is not
		// delayed by a full interval.
		t := time.NewTicker(c.rateLimit)
		c.limiter = t.C
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.limiter:
		return nil
	}
}

// parseRecords decodes a crt.sh JSON body into deduplicated Certificates. A
// single crt.sh record's name_value may hold several newline-separated SAN
// names; each distinct (name, not_before) pair becomes one Certificate. Names
// are cross-referenced against candidates to set TakeoverCandidate.
func parseRecords(body []byte, apex string, candidates map[string]bool) ([]Certificate, error) {
	var records []crtshRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("ct: parse %s: %w", apex, err)
	}

	// Lower-case the candidate set once for case-insensitive matching.
	var candSet map[string]bool
	if len(candidates) > 0 {
		candSet = make(map[string]bool, len(candidates))
		for k, v := range candidates {
			if v {
				candSet[normalizeHost(k)] = true
			}
		}
	}

	seen := make(map[string]bool)
	var out []Certificate
	for _, rec := range records {
		nb := parseCrtTime(rec.NotBefore)
		for _, raw := range strings.Split(rec.NameValue, "\n") {
			name := normalizeHost(raw)
			if name == "" {
				continue
			}
			// Drop the leading wildcard label: "*.dev.example.com" certifies
			// "dev.example.com" for our candidate-matching purposes.
			name = strings.TrimPrefix(name, "*.")
			key := name + "|" + rec.NotBefore
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Certificate{
				Name:              name,
				Apex:              apex,
				NotBefore:         nb,
				Issuer:            rec.IssuerName,
				TakeoverCandidate: candSet[name],
			})
		}
	}

	// Deterministic ordering: by name, then newest-first within a name.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].NotBefore.After(out[j].NotBefore)
	})
	return out, nil
}

// crtTimeLayouts are the timestamp formats crt.sh has used for not_before /
// not_after across its history. Parsing tolerates either.
var crtTimeLayouts = []string{
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.999999",
	time.RFC3339,
}

// parseCrtTime parses a crt.sh timestamp, returning the zero time on failure
// (crt.sh occasionally returns malformed or empty values; a zero time is a
// benign sentinel the caller can detect with IsZero).
func parseCrtTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range crtTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// normalizeHost trims whitespace and a trailing dot and lower-cases a hostname.
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

// CandidatesFromFindings reads a graverobber JSONL findings file and returns the
// set of subdomains it flagged, suitable as the candidates argument to Query.
// Only subdomain values are collected; the vector and confidence are not
// inspected here — any prior finding marks its subdomain as worth watching in
// CT logs.
func CandidatesFromFindings(r io.Reader) (map[string]bool, error) {
	set := make(map[string]bool)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return nil, fmt.Errorf("ct: parse findings line: %w", err)
		}
		if h := normalizeHost(f.Subdomain); h != "" {
			set[h] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ct: read findings: %w", err)
	}
	return set, nil
}

// Apex reduces a hostname to its registrable-apex query key for crt.sh. It is a
// pragmatic last-two-labels heuristic (last three for common second-level
// ccTLDs like co.uk / com.au), matching the deduplication the ct subcommand
// applies to a noisy subdomain list. It is not a full Public Suffix List
// implementation; over-broad apexes simply return a superset of certificates,
// which is harmless for candidate cross-referencing.
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

// DedupeApexes maps a stream of (possibly subdomain) hosts to the unique set of
// apex domains to query, preserving first-seen order for deterministic output.
func DedupeApexes(hosts []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, h := range hosts {
		a := Apex(h)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}
