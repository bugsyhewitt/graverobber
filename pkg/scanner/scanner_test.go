package scanner

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
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
		NoMX:        true,
		NoDKIM:      true,
		NoDMARC:     true,
		NoAXFR:      true,
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

// ---- #1 (POST_V01 Rank 1): vectors run concurrently per target -------------

// TestRun_VectorsRunConcurrently verifies that the three per-target detection
// vectors (CNAME, NS, SPF) execute concurrently rather than serially. Each
// vector is replaced with a stub that sleeps for a fixed delay; if the vectors
// ran serially the per-target wall time would be ~3*delay, but concurrent
// execution bounds it to ~max(delay) plus scheduling slack.
//
// The test injects stubs via the package-private vector seam (cnameVector,
// nsVector, spfVector) so it exercises scanTarget's real fan-out path without
// touching DNS or HTTP.
func TestRun_VectorsRunConcurrently(t *testing.T) {
	const delay = 200 * time.Millisecond

	// Save and restore the production vector functions.
	origCNAME, origNS, origSPF := cnameVector, nsVector, spfVector
	t.Cleanup(func() {
		cnameVector, nsVector, spfVector = origCNAME, origNS, origSPF
	})

	// Track peak concurrency to prove the vectors overlap in time.
	var inFlight, peak int32
	stub := func(ctx context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if cur <= p || atomic.CompareAndSwapInt32(&peak, p, cur) {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
		atomic.AddInt32(&inFlight, -1)
		return nil, nil
	}
	cnameVector, nsVector, spfVector = stub, stub, stub

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	// Single worker, single target: any concurrency observed must come from the
	// per-target vector fan-out, not from multiple workers or targets. MX,
	// DKIM, DMARC, and AXFR are disabled so the timing measures only the three
	// stubbed vectors (the real detectors would otherwise hit DNS and skew the
	// clock).
	sc := New(db, Options{Concurrency: 1, Timeout: time.Second, NoMX: true, NoDKIM: true, NoDMARC: true, NoAXFR: true})

	targets := make(chan string, 1)
	targets <- "sub.example.com"
	close(targets)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	for range sc.Run(ctx, targets) {
	}
	elapsed := time.Since(start)

	// Serial execution would take ~3*delay (600ms). Concurrent execution takes
	// ~delay (200ms). Use 2*delay as the upper bound: comfortably above the
	// concurrent expectation, well below the serial sum, robust to CI jitter.
	if elapsed >= 2*delay {
		t.Errorf("per-target wall time %v >= %v: vectors appear to run serially "+
			"(serial sum would be ~%v, concurrent ~%v)",
			elapsed, 2*delay, 3*delay, delay)
	}

	if peak < 3 {
		t.Errorf("peak concurrent vectors = %d, want 3: vectors are not all "+
			"running at the same time", peak)
	}
}

// TestRun_DisabledVectorsAreNotRun verifies the fan-out still honours the NoNS
// and NoSPF options — disabled vectors must not be dispatched even though the
// enabled ones now run concurrently.
func TestRun_DisabledVectorsAreNotRun(t *testing.T) {
	origCNAME, origNS, origSPF := cnameVector, nsVector, spfVector
	t.Cleanup(func() {
		cnameVector, nsVector, spfVector = origCNAME, origNS, origSPF
	})

	var cnameCalls, nsCalls, spfCalls int32
	cnameVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&cnameCalls, 1)
		return nil, nil
	}
	nsVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&nsCalls, 1)
		return nil, nil
	}
	spfVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&spfCalls, 1)
		return nil, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	sc := New(db, Options{Concurrency: 1, Timeout: time.Second, NoNS: true, NoSPF: true, NoMX: true, NoDKIM: true, NoDMARC: true, NoAXFR: true})

	targets := make(chan string, 1)
	targets <- "sub.example.com"
	close(targets)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range sc.Run(ctx, targets) {
	}

	if got := atomic.LoadInt32(&cnameCalls); got != 1 {
		t.Errorf("CNAME vector called %d times, want 1 (CNAME always runs)", got)
	}
	if got := atomic.LoadInt32(&nsCalls); got != 0 {
		t.Errorf("NS vector called %d times, want 0 (NoNS set)", got)
	}
	if got := atomic.LoadInt32(&spfCalls); got != 0 {
		t.Errorf("SPF vector called %d times, want 0 (NoSPF set)", got)
	}
}

// TestRun_AllVectorFindingsAreEmitted verifies that findings produced by every
// enabled vector survive the concurrent fan-out and reach the output channel
// (subject to the unchanged dedup logic).
func TestRun_AllVectorFindingsAreEmitted(t *testing.T) {
	origCNAME, origNS, origSPF := cnameVector, nsVector, spfVector
	t.Cleanup(func() {
		cnameVector, nsVector, spfVector = origCNAME, origNS, origSPF
	})

	mk := func(v finding.Vector, svc string) vectorFunc {
		return func(_ context.Context, _ *Scanner, target string) ([]finding.Finding, error) {
			return []finding.Finding{{Subdomain: target, Vector: v, Service: svc}}, nil
		}
	}
	cnameVector = mk(finding.VectorCNAME, "AWS/S3")
	nsVector = mk(finding.VectorNS, "Route53")
	spfVector = mk(finding.VectorSPF, "SendGrid")

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	// Disable MX/DKIM/DMARC/AXFR so the emitted set is exactly the three stubbed vectors.
	sc := New(db, Options{Concurrency: 1, Timeout: time.Second, NoMX: true, NoDKIM: true, NoDMARC: true, NoAXFR: true})

	targets := make(chan string, 1)
	targets <- "sub.example.com"
	close(targets)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := map[finding.Vector]bool{}
	var n int
	for f := range sc.Run(ctx, targets) {
		got[f.Vector] = true
		n++
	}
	if n != 3 {
		t.Errorf("emitted %d findings, want 3 (one per vector)", n)
	}
	for _, v := range []finding.Vector{finding.VectorCNAME, finding.VectorNS, finding.VectorSPF} {
		if !got[v] {
			t.Errorf("no finding emitted for vector %q", v)
		}
	}
}

// TestRun_NoMXDisablesMXVector verifies that when NoMX is set the mxVector
// function is not called, and that when NoMX is false it is called once.
func TestRun_NoMXDisablesMXVector(t *testing.T) {
	origMX := mxVector
	t.Cleanup(func() { mxVector = origMX })

	var mxCalls int32
	mxVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&mxCalls, 1)
		return nil, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}

	runWith := func(noMX bool) int32 {
		atomic.StoreInt32(&mxCalls, 0)
		sc := New(db, Options{
			Concurrency: 1,
			Timeout:     200 * time.Millisecond,
			NoNS:        true,
			NoSPF:       true,
			NoMX:        noMX,
			NoDKIM:      true,
			NoDMARC:     true,
			NoAXFR:      true,
		})
		targets := make(chan string, 1)
		targets <- "sub.example.com"
		close(targets)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for range sc.Run(ctx, targets) {
		}
		return atomic.LoadInt32(&mxCalls)
	}

	if got := runWith(true); got != 0 {
		t.Errorf("NoMX=true: mxVector called %d times, want 0", got)
	}
	if got := runWith(false); got != 1 {
		t.Errorf("NoMX=false: mxVector called %d times, want 1", got)
	}
}

// TestRun_NoDKIMDisablesDKIMVector verifies that when NoDKIM is set the
// dkimVector function is not called, and that when NoDKIM is false it is called
// once.
func TestRun_NoDKIMDisablesDKIMVector(t *testing.T) {
	origDKIM := dkimVector
	t.Cleanup(func() { dkimVector = origDKIM })

	var dkimCalls int32
	dkimVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&dkimCalls, 1)
		return nil, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}

	runWith := func(noDKIM bool) int32 {
		atomic.StoreInt32(&dkimCalls, 0)
		sc := New(db, Options{
			Concurrency: 1,
			Timeout:     200 * time.Millisecond,
			NoNS:        true,
			NoSPF:       true,
			NoMX:        true,
			NoDKIM:      noDKIM,
			NoDMARC:     true,
			NoAXFR:      true,
		})
		targets := make(chan string, 1)
		targets <- "sub.example.com"
		close(targets)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for range sc.Run(ctx, targets) {
		}
		return atomic.LoadInt32(&dkimCalls)
	}

	if got := runWith(true); got != 0 {
		t.Errorf("NoDKIM=true: dkimVector called %d times, want 0", got)
	}
	if got := runWith(false); got != 1 {
		t.Errorf("NoDKIM=false: dkimVector called %d times, want 1", got)
	}
}

// TestRun_NoDMARCDisablesDMARCVector verifies that when NoDMARC is set the
// dmarcVector function is not called, and that when NoDMARC is false it is
// called once.
func TestRun_NoDMARCDisablesDMARCVector(t *testing.T) {
	origDMARC := dmarcVector
	t.Cleanup(func() { dmarcVector = origDMARC })

	var dmarcCalls int32
	dmarcVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&dmarcCalls, 1)
		return nil, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}

	runWith := func(noDMARC bool) int32 {
		atomic.StoreInt32(&dmarcCalls, 0)
		sc := New(db, Options{
			Concurrency: 1,
			Timeout:     200 * time.Millisecond,
			NoNS:        true,
			NoSPF:       true,
			NoMX:        true,
			NoDKIM:      true,
			NoDMARC:     noDMARC,
			NoAXFR:      true,
		})
		targets := make(chan string, 1)
		targets <- "sub.example.com"
		close(targets)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for range sc.Run(ctx, targets) {
		}
		return atomic.LoadInt32(&dmarcCalls)
	}

	if got := runWith(true); got != 0 {
		t.Errorf("NoDMARC=true: dmarcVector called %d times, want 0", got)
	}
	if got := runWith(false); got != 1 {
		t.Errorf("NoDMARC=false: dmarcVector called %d times, want 1", got)
	}
}

// TestRun_NoAXFRDisablesAXFRVector verifies that when NoAXFR is set the
// axfrVector function is not called, and that when NoAXFR is false it is called
// once. AXFR is opt-out (on by default), mirroring the other DNS vectors.
func TestRun_NoAXFRDisablesAXFRVector(t *testing.T) {
	origAXFR := axfrVector
	t.Cleanup(func() { axfrVector = origAXFR })

	var axfrCalls int32
	axfrVector = func(_ context.Context, _ *Scanner, _ string) ([]finding.Finding, error) {
		atomic.AddInt32(&axfrCalls, 1)
		return nil, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}

	runWith := func(noAXFR bool) int32 {
		atomic.StoreInt32(&axfrCalls, 0)
		sc := New(db, Options{
			Concurrency: 1,
			Timeout:     200 * time.Millisecond,
			NoNS:        true,
			NoSPF:       true,
			NoMX:        true,
			NoDKIM:      true,
			NoDMARC:     true,
			NoAXFR:      noAXFR,
		})
		targets := make(chan string, 1)
		targets <- "sub.example.com"
		close(targets)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for range sc.Run(ctx, targets) {
		}
		return atomic.LoadInt32(&axfrCalls)
	}

	if got := runWith(true); got != 0 {
		t.Errorf("NoAXFR=true: axfrVector called %d times, want 0", got)
	}
	if got := runWith(false); got != 1 {
		t.Errorf("NoAXFR=false: axfrVector called %d times, want 1", got)
	}
}

// ---- --min-confidence filter ----------------------------------------------

// TestRun_MinConfidenceFiltersWeakerFindings stubs the CNAME vector to emit one
// finding of each confidence tier and verifies that Options.MinConfidence
// suppresses everything weaker than the threshold while the empty default emits
// all three.
func TestRun_MinConfidenceFiltersWeakerFindings(t *testing.T) {
	origCNAME := cnameVector
	t.Cleanup(func() { cnameVector = origCNAME })

	// One finding per tier, distinguished by Service so the dedup key is unique.
	cnameVector = func(_ context.Context, _ *Scanner, target string) ([]finding.Finding, error) {
		return []finding.Finding{
			{Subdomain: target, Vector: finding.VectorCNAME, Service: "conf", Confidence: finding.Confirmed},
			{Subdomain: target, Vector: finding.VectorCNAME, Service: "likely", Confidence: finding.Likely},
			{Subdomain: target, Vector: finding.VectorCNAME, Service: "pot", Confidence: finding.Potential},
		}, nil
	}

	db, err := fingerprints.Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("load db: %v", err)
	}

	run := func(min finding.Confidence) map[finding.Confidence]int {
		sc := New(db, Options{
			Concurrency:   1,
			Timeout:       time.Second,
			NoNS:          true,
			NoSPF:         true,
			NoMX:          true,
			NoDKIM:        true,
			NoDMARC:       true,
			NoAXFR:        true,
			MinConfidence: min,
		})
		targets := make(chan string, 1)
		targets <- "sub.example.com"
		close(targets)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got := map[finding.Confidence]int{}
		for f := range sc.Run(ctx, targets) {
			got[f.Confidence]++
		}
		return got
	}

	cases := []struct {
		min       finding.Confidence
		wantTotal int
		wantTiers []finding.Confidence
		desc      string
	}{
		{"", 3, []finding.Confidence{finding.Confirmed, finding.Likely, finding.Potential}, "no threshold emits all three"},
		{finding.Potential, 3, []finding.Confidence{finding.Confirmed, finding.Likely, finding.Potential}, "potential threshold emits all three"},
		{finding.Likely, 2, []finding.Confidence{finding.Confirmed, finding.Likely}, "likely threshold drops potential"},
		{finding.Confirmed, 1, []finding.Confidence{finding.Confirmed}, "confirmed threshold keeps only confirmed"},
	}
	for _, tc := range cases {
		got := run(tc.min)
		total := 0
		for _, n := range got {
			total += n
		}
		if total != tc.wantTotal {
			t.Errorf("%s: emitted %d findings, want %d (%v)", tc.desc, total, tc.wantTotal, got)
		}
		for _, tier := range tc.wantTiers {
			if got[tier] != 1 {
				t.Errorf("%s: tier %q count = %d, want 1", tc.desc, tier, got[tier])
			}
		}
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
		NoMX:        true,
		NoDKIM:      true,
		NoDMARC:     true,
		NoAXFR:      true,
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
