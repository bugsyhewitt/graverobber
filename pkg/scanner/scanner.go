// Package scanner orchestrates graverobber's concurrent takeover scan: it owns
// the worker pool, fans each target out across the three detection vectors, and
// streams findings back to the caller.
//
// This package is the primary integration point for embedders such as the
// Pho3nix MCP server, which imports pkg/scanner directly and consumes
// finding.Finding values rather than shelling out to the CLI and parsing JSONL
// (see handoff open question #1 — library-first). The graverobber binary in
// cmd/ is itself just a thin wrapper over Scanner.Run.
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/detectors"
	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
	"github.com/bugsyhewitt/graverobber/pkg/verifier"
)

// Options configures a scan run.
type Options struct {
	Concurrency int           // worker goroutine count (handoff default: 50)
	Timeout     time.Duration // per-target HTTP timeout (handoff default: 10s)
	RateLimit   int           // global requests/sec; 0 == unlimited
	NoNS        bool          // skip the NS takeover vector
	NoSPF       bool          // skip the SPF include vector
	NoMX        bool          // skip the MX takeover vector
	HTTPOnly    bool          // probe services over HTTP only
	HTTPSOnly   bool          // probe services over HTTPS only
	Resolvers   []string      // custom recursive DNS resolvers
}

// DefaultOptions returns the handoff-specified defaults.
func DefaultOptions() Options {
	return Options{
		Concurrency: 50,
		Timeout:     10 * time.Second,
		RateLimit:   0,
	}
}

// Scanner runs takeover detection against a stream of targets.
type Scanner struct {
	opts     Options
	db       *fingerprints.DB
	resolver *resolver.Resolver
	verifier verifier.Verifier
}

// New constructs a Scanner. db must be non-nil. The active verifier defaults to
// verifier.NoopVerifier (v1.0); v1.1 swaps in real active verification via
// SetVerifier without any other change.
func New(db *fingerprints.DB, opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultOptions().Concurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	return &Scanner{
		opts:     opts,
		db:       db,
		resolver: resolver.New(opts.Resolvers, opts.Timeout),
		verifier: verifier.NoopVerifier{},
	}
}

// SetVerifier overrides the active verifier (v1.1 integration point).
func (s *Scanner) SetVerifier(v verifier.Verifier) {
	if v != nil {
		s.verifier = v
	}
}

// Run consumes targets from the targets channel and emits findings on the
// returned channel, which is closed once every worker has drained and exited
// (either targets closed, or ctx cancelled). Run does not block — it returns
// the output channel immediately.
//
// Findings are deduplicated within a single Run call by the key
// (Subdomain, Vector, Service) so that duplicate input targets or multi-hop
// chains that match the same service never produce duplicate output rows.
func (s *Scanner) Run(ctx context.Context, targets <-chan string) <-chan finding.Finding {
	out := make(chan finding.Finding)
	var wg sync.WaitGroup
	var emitted sync.Map // key: subdomain+"\x00"+vector+"\x00"+service

	wg.Add(s.opts.Concurrency)
	for i := 0; i < s.opts.Concurrency; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-targets:
					if !ok {
						return
					}
					s.scanTarget(ctx, target, &emitted, out)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// dedupKey returns the deduplication key for a finding.
func dedupKey(f finding.Finding) string {
	return f.Subdomain + "\x00" + string(f.Vector) + "\x00" + f.Service
}

// vectorFunc is one detection vector's per-target entry point. The three
// production vectors (CNAME, NS, SPF) are wired through package-level vars of
// this type so that scanTarget dispatches them uniformly and concurrently, and
// so tests can substitute deterministic stubs without touching DNS or HTTP.
type vectorFunc func(ctx context.Context, s *Scanner, target string) ([]finding.Finding, error)

// The production vectors. These are vars, not direct calls, purely to provide a
// package-private seam for the scanner's concurrency tests; production code
// never reassigns them.
var (
	cnameVector vectorFunc = func(ctx context.Context, s *Scanner, target string) ([]finding.Finding, error) {
		cfg := detectors.Config{HTTPOnly: s.opts.HTTPOnly, HTTPSOnly: s.opts.HTTPSOnly}
		return detectors.CNAME(ctx, target, s.resolver, s.db, cfg)
	}
	nsVector vectorFunc = func(ctx context.Context, s *Scanner, target string) ([]finding.Finding, error) {
		return detectors.NS(ctx, target, s.resolver)
	}
	spfVector vectorFunc = func(ctx context.Context, s *Scanner, target string) ([]finding.Finding, error) {
		return detectors.SPF(ctx, target, s.resolver)
	}
	mxVector vectorFunc = func(ctx context.Context, s *Scanner, target string) ([]finding.Finding, error) {
		return detectors.MX(ctx, target, s.resolver)
	}
)

// scanTarget runs the per-target detection pipeline and emits any findings.
//
// CNAME always runs. NS and SPF run unless disabled. The three vectors are
// independent and I/O-bound (CNAME probes HTTP, NS probes authoritative
// nameservers with UDP retries, SPF recurses TXT records), so scanTarget fans
// them out across one goroutine each and joins on a WaitGroup. Per-target wall
// time is therefore roughly max(CNAME, NS, SPF) rather than their sum.
//
// Only the collection of findings is parallelised; deduplication
// (the emitted sync.Map) and emission are performed serially afterwards exactly
// as before, so output semantics are unchanged.
func (s *Scanner) scanTarget(ctx context.Context, target string, emitted *sync.Map, out chan<- finding.Finding) {
	// Select the enabled vectors. CNAME always runs; NS, SPF, and MX are opt-out.
	vectors := []vectorFunc{cnameVector}
	if !s.opts.NoNS {
		vectors = append(vectors, nsVector)
	}
	if !s.opts.NoSPF {
		vectors = append(vectors, spfVector)
	}
	if !s.opts.NoMX {
		vectors = append(vectors, mxVector)
	}

	// Fan out: run each enabled vector concurrently, collecting findings into a
	// per-vector slot so no shared-slice synchronisation is needed.
	results := make([][]finding.Finding, len(vectors))
	var wg sync.WaitGroup
	wg.Add(len(vectors))
	for i, vec := range vectors {
		go func(i int, vec vectorFunc) {
			defer wg.Done()
			if fs, err := vec(ctx, s, target); err == nil {
				results[i] = fs
			}
		}(i, vec)
	}
	wg.Wait()

	var found []finding.Finding
	for _, fs := range results {
		found = append(found, fs...)
	}

	for _, f := range found {
		if _, dup := emitted.LoadOrStore(dedupKey(f), struct{}{}); dup {
			continue
		}
		if f.Timestamp.IsZero() {
			f.Timestamp = time.Now().UTC()
		}
		if conf, err := s.verifier.Verify(ctx, f); err == nil {
			f.Confidence = conf
		}
		select {
		case <-ctx.Done():
			return
		case out <- f:
		}
	}
}
