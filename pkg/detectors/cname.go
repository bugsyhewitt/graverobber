// Package detectors implements graverobber's three v1.0 takeover detection
// vectors, one file per vector:
//
//	cname.go  dangling CNAME -> fingerprint match
//	ns.go     deleted DNS hosted zone (NS takeover)
//	spf.go    claimable SPF include: domain (the SubdoMailing vector)
package detectors

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// Config carries the per-scan options relevant to detectors.
type Config struct {
	// HTTPOnly probes services over HTTP only.
	HTTPOnly bool
	// HTTPSOnly probes services over HTTPS only. When both flags are false the
	// detector tries HTTPS first and falls back to HTTP (handoff Q4).
	HTTPSOnly bool
	// Timeout is the per-request HTTP timeout. Zero uses the default (10s).
	Timeout time.Duration
}

// hostBucket is a buffered-channel token bucket limiting a destination to ~N
// req/s. Each bucket owns one ticker goroutine; stop is closed by DrainBuckets
// to reclaim goroutines between scan runs.
//
// Goroutine lifetime: goroutines are tied to the scan session, not the process.
// CLI callers can ignore this (the process exits). Library embedders (e.g. the
// Pho3nix MCP server) MUST call DrainBuckets() after each scan to prevent
// goroutine accumulation across multiple scan invocations.
type hostBucket struct {
	tokens chan struct{}
	stop   chan struct{}
}

const (
	destRatePerSec = 10      // internal per-host cap, ~10 req/s
	maxBodyBytes   = 1 << 20 // 1 MiB cap on HTTP response body reads
)

var (
	bucketsMu sync.Mutex
	buckets   = map[string]*hostBucket{}
)

// destWait blocks until the per-host token bucket allows a request, or the
// context is cancelled (in which case it returns ctx.Err()).
func destWait(ctx context.Context, host string) error {
	bucketsMu.Lock()
	b, ok := buckets[host]
	if !ok {
		b = newBucket(destRatePerSec)
		buckets[host] = b
	}
	bucketsMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.tokens:
		return nil
	}
}

// DrainBuckets stops all per-host rate-limit goroutines and clears the bucket
// cache. Library embedders must call this after each scan to reclaim goroutines.
// It is safe to call concurrently and from any goroutine.
func DrainBuckets() {
	bucketsMu.Lock()
	defer bucketsMu.Unlock()
	for _, b := range buckets {
		close(b.stop)
	}
	buckets = map[string]*hostBucket{}
}

func newBucket(rps int) *hostBucket {
	b := &hostBucket{
		tokens: make(chan struct{}, rps),
		stop:   make(chan struct{}),
	}
	// Pre-fill so the first burst of requests is not unnecessarily throttled.
	for i := 0; i < rps; i++ {
		b.tokens <- struct{}{}
	}
	interval := time.Second / time.Duration(rps)
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-b.stop:
				return
			case <-tick.C:
				select {
				case b.tokens <- struct{}{}:
				default: // bucket full; discard tick
				}
			}
		}
	}()
	return b
}

var sharedTransport = &http.Transport{
	ResponseHeaderTimeout: 10 * time.Second,
	// InsecureSkipVerify is deliberate: dangling/unclaimed service endpoints
	// characteristically serve TLS certificates that do NOT match the probed
	// hostname — that cert mismatch is part of the vulnerable state we are
	// trying to detect. Enforcing cert validity would cause the HTTPS probe to
	// fail on the most interesting targets and prevent reading the body
	// fingerprint. This is a security-recon probe, not a trust-sensitive
	// connection. Do not remove without updating isConnectError fallback logic.
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
}

// fetch performs a single GET to url and returns the (capped) body.
func fetch(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "graverobber/1.0")
	client := &http.Client{Transport: sharedTransport, Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// probeHTTP fetches host via HTTPS then HTTP (per cfg), enforcing the per-host
// rate limit. Returns body, winning scheme, and any error.
func probeHTTP(ctx context.Context, host string, cfg Config) ([]byte, string, error) {
	if err := destWait(ctx, host); err != nil {
		return nil, "", err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	try := func(scheme string) ([]byte, string, error) {
		b, err := fetch(ctx, scheme+"://"+host, timeout)
		return b, scheme, err
	}

	if cfg.HTTPSOnly {
		return try("https")
	}
	if cfg.HTTPOnly {
		return try("http")
	}
	// HTTPS first; fall back to HTTP only on transport-level failures.
	body, scheme, err := try("https")
	if err == nil {
		return body, scheme, nil
	}
	if !isConnectError(err) {
		return body, scheme, err
	}
	return try("http")
}

// isConnectError reports whether err is a transport/TLS failure rather than a
// valid HTTP-level error. Only transport failures trigger the HTTP fallback.
func isConnectError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "tls:") ||
		strings.Contains(s, "TLS") ||
		strings.Contains(s, "EOF")
}

// CNAME detects dangling-CNAME subdomain takeover.
//
// Algorithm (handoff "Detection vectors / 1. CNAME fingerprint matching"):
//  1. Resolve the full CNAME chain for target.
//  2. Detect wildcard DNS (resolver.IsWildcard) to suppress false positives.
//  3. For each chain hop, match the host suffix against db (DB.MatchCNAME).
//  4. Fetch the service — HTTPS first, HTTP fallback unless cfg constrains it;
//     for NXDOMAIN-type fingerprints the DNS rcode alone is the signal.
//  5. Assign confidence: Confirmed for definitive body strings (e.g. S3) or
//     NXDOMAIN matches, Likely for non-definitive fingerprint matches,
//     Potential for a dangling CNAME to a service not in the database.
func CNAME(ctx context.Context, target string, r *resolver.Resolver, db *fingerprints.DB, cfg Config) ([]finding.Finding, error) {
	chain, chainErr := r.CNAMEChain(ctx, target)
	isNXDomain := errors.Is(chainErr, resolver.ErrNXDomain)
	if chainErr != nil && !isNXDomain {
		return nil, nil // transient DNS error — skip silently
	}
	if len(chain) == 0 {
		return nil, nil // no CNAME record at all
	}

	finalTarget := chain[len(chain)-1]

	// Wildcard zones would make every random subdomain appear to resolve, so
	// suppress findings under them to avoid false positives.
	if wild, err := r.IsWildcard(ctx, finalTarget); err == nil && wild {
		return nil, nil
	}

	// Collect fingerprint matches across all chain hops (deduplicated).
	matches := matchChain(db, chain)

	if len(matches) == 0 {
		return []finding.Finding{{
			Subdomain:  target,
			Vector:     finding.VectorCNAME,
			Confidence: finding.Potential,
			CNAME:      finalTarget,
			Evidence:   "dangling CNAME with no fingerprint match",
		}}, nil
	}

	var findings []finding.Finding
	for _, fp := range matches {
		f := finding.Finding{
			Subdomain:   target,
			Vector:      finding.VectorCNAME,
			Service:     fp.Service,
			Fingerprint: fp.Fingerprint,
			CNAME:       finalTarget,
		}

		if fp.NXDomain {
			if isNXDomain {
				f.Confidence = finding.Confirmed
				f.Evidence = "NXDOMAIN on CNAME target matches NXDomain fingerprint"
			} else {
				f.Confidence = finding.Likely
				f.Evidence = "NXDomain fingerprint match; target still resolves"
			}
			findings = append(findings, f)
			continue
		}

		body, scheme, err := probeHTTP(ctx, finalTarget, cfg)
		if err != nil {
			f.Confidence = finding.Likely
			f.Evidence = "CNAME fingerprint match; HTTP probe failed"
			findings = append(findings, f)
			continue
		}

		f.Scheme = scheme
		if fp.MatchBody(body) {
			f.Confidence = finding.Confirmed
			f.Evidence = "fingerprint string found in HTTP response body"
		} else {
			f.Confidence = finding.Likely
			f.Evidence = "CNAME matches known service; fingerprint string absent from response"
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// matchChain returns deduplicated fingerprint matches across all CNAME hops.
func matchChain(db *fingerprints.DB, chain []string) []fingerprints.Fingerprint {
	seen := map[string]bool{}
	var out []fingerprints.Fingerprint
	for _, hop := range chain {
		for _, fp := range db.MatchCNAME(hop) {
			if !seen[fp.Service] {
				seen[fp.Service] = true
				out = append(out, fp)
			}
		}
	}
	return out
}
