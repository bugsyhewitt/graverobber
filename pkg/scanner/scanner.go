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
func (s *Scanner) Run(ctx context.Context, targets <-chan string) <-chan finding.Finding {
	out := make(chan finding.Finding)
	var wg sync.WaitGroup

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
					s.scanTarget(ctx, target, out)
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

// scanTarget runs the per-target detection pipeline and emits any findings.
//
// CNAME always runs. NS and SPF run unless disabled; the handoff specifies them
// as additional per-target work that does not block the CNAME path — the build
// step may parallelise the three vectors with their own goroutines.
func (s *Scanner) scanTarget(ctx context.Context, target string, out chan<- finding.Finding) {
	cfg := detectors.Config{HTTPOnly: s.opts.HTTPOnly, HTTPSOnly: s.opts.HTTPSOnly}

	var found []finding.Finding

	if fs, err := detectors.CNAME(ctx, target, s.resolver, s.db, cfg); err == nil {
		found = append(found, fs...)
	}
	if !s.opts.NoNS {
		if fs, err := detectors.NS(ctx, target, s.resolver); err == nil {
			found = append(found, fs...)
		}
	}
	if !s.opts.NoSPF {
		if fs, err := detectors.SPF(ctx, target, s.resolver); err == nil {
			found = append(found, fs...)
		}
	}

	for _, f := range found {
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
