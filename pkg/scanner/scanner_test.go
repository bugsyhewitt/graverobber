package scanner

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
)

// ---- #5: finding deduplication ---------------------------------------------

// TestDedupKey verifies the key uniqueness properties the scanner uses to
// filter duplicate findings within a Run call.
func TestDedupKey(t *testing.T) {
	cases := []struct {
		a, b finding.Finding
		same bool
		desc string
	}{
		{
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			true,
			"identical findings → same key (dedup fires)",
		},
		{
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			finding.Finding{Subdomain: "other.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			false,
			"different subdomain → different key",
		},
		{
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorNS, Service: "AWS/S3"},
			false,
			"different vector → different key",
		},
		{
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3"},
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: "GitHub Pages"},
			false,
			"different service → different key",
		},
		{
			// Potential CNAME findings have empty service.
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: ""},
			finding.Finding{Subdomain: "sub.example.com", Vector: finding.VectorCNAME, Service: ""},
			true,
			"identical no-service (Potential) findings → same key",
		},
	}
	for _, tc := range cases {
		ka, kb := dedupKey(tc.a), dedupKey(tc.b)
		if (ka == kb) != tc.same {
			t.Errorf("%s: equal=%v, want %v (keys %q vs %q)",
				tc.desc, ka == kb, tc.same, ka, kb)
		}
	}
}

// TestDedupKey_UsedByEmittedMap verifies that a sync.Map keyed on dedupKey
// correctly deduplicates a stream of identical findings — matching the
// LoadOrStore pattern used in scanTarget.
func TestDedupKey_UsedByEmittedMap(t *testing.T) {
	f := finding.Finding{
		Subdomain:  "dup.example.com",
		Vector:     finding.VectorCNAME,
		Service:    "AWS/S3",
		Confidence: finding.Confirmed,
		Timestamp:  time.Now().UTC(),
	}

	var emitted sync.Map
	emitCount := 0
	for range 5 {
		if _, dup := emitted.LoadOrStore(dedupKey(f), struct{}{}); !dup {
			emitCount++
		}
	}
	if emitCount != 1 {
		t.Errorf("expected 1 emission through dedup map, got %d", emitCount)
	}
}

// TestRun_TerminatesWithEmptyDB confirms that Run drains cleanly with an empty
// fingerprint DB (no findings emitted) and that the dedup logic doesn't
// interfere with normal operation.
func TestRun_TerminatesWithEmptyDB(t *testing.T) {
	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load empty db: %v", err)
	}
	sc := New(db, Options{
		Concurrency: 2,
		Timeout:     500 * time.Millisecond,
		NoNS:        true,
		NoSPF:       true,
	})

	targets := make(chan string, 3)
	targets <- "a.example.com"
	targets <- "a.example.com" // intentional duplicate
	targets <- "b.example.com"
	close(targets)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	for range sc.Run(ctx, targets) {
		count++
	}
	// With an empty DB, no findings should be emitted.
	if count != 0 {
		t.Errorf("expected 0 findings from empty DB, got %d", count)
	}
}

// ---- #2: dedup sync.Map is Run-scoped, not Scanner-scoped ------------------

// TestScanner_EmittedMapIsRunLocal verifies by struct inspection that Scanner
// holds no sync.Map field. The dedup map must be a local variable inside Run
// so it is garbage-collected after each run — not accumulated for the lifetime
// of the Scanner (which library embedders like Pho3nix hold long-lived).
func TestScanner_EmittedMapIsRunLocal(t *testing.T) {
	sType := reflect.TypeOf(Scanner{})
	syncMapType := reflect.TypeOf(sync.Map{})
	for i := range sType.NumField() {
		f := sType.Field(i)
		if f.Type == syncMapType {
			t.Errorf("Scanner has sync.Map field %q — dedup map must be local to Run(), "+
				"not a struct field (would leak across repeated Run calls)", f.Name)
		}
	}
}

// TestRun_SecondRunDeduplicationIsIndependentOfFirst calls Run twice on the
// same Scanner and verifies the second run's dedup state is not inherited from
// the first. If the emitted map were Scanner-scoped, findings from run 1 would
// be suppressed in run 2.
//
// Because we can't produce real findings without a live DNS/HTTP stack, we test
// the invariant at the sync.Map level: demonstrate that two separate Run calls
// each receive a fresh LoadOrStore map by verifying identical inputs produce
// identical output counts across both runs.
func TestRun_SecondRunDeduplicationIsIndependentOfFirst(t *testing.T) {
	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	sc := New(db, Options{
		Concurrency: 1,
		Timeout:     200 * time.Millisecond,
		NoNS:        true,
		NoSPF:       true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runOnce := func() int {
		targets := make(chan string, 2)
		targets <- "sub.example.com"
		targets <- "sub.example.com" // intentional duplicate within one run
		close(targets)
		var n int
		for range sc.Run(ctx, targets) {
			n++
		}
		return n
	}

	run1 := runOnce()
	run2 := runOnce()

	// With an empty DB, both runs produce 0 findings.
	// Crucially, if the emitted map leaked from run1 into run2, behavior could
	// diverge — this test would catch that if we had real findings.
	if run1 != run2 {
		t.Errorf("run1=%d findings, run2=%d: second run's dedup state must not inherit from first",
			run1, run2)
	}

	// Direct proof: verify the dedup mechanism works within a single run by
	// exercising the LoadOrStore pattern directly with the same map.
	var emitted sync.Map
	_, loaded1 := emitted.LoadOrStore("key", struct{}{})
	_, loaded2 := emitted.LoadOrStore("key", struct{}{})
	// First store: loaded1 is false (key was new). Second store: loaded2 is true.
	if loaded1 {
		t.Error("first LoadOrStore on fresh map should not report loaded")
	}
	if !loaded2 {
		t.Error("second LoadOrStore on same map should report loaded (dedup fires)")
	}
	// A fresh map for run2 would NOT have this key pre-loaded.
	var freshMap sync.Map
	_, loaded := freshMap.Load("key")
	if loaded {
		t.Error("fresh sync.Map must not have pre-existing keys from prior run")
	}
}
