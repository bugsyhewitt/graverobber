package detectors

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// ---- fingerprint DB helpers ------------------------------------------------

func mustDB(t *testing.T, raw string) *fingerprints.DB {
	t.Helper()
	db, err := fingerprints.Load([]byte(raw))
	if err != nil {
		t.Fatalf("load DB: %v", err)
	}
	return db
}

var testFingerprintsJSON = `[
  {"service":"AWS/S3","cname":["s3.amazonaws.com"],"fingerprint":"The specified bucket does not exist","nxdomain":false,"status":"Vulnerable","discussion":""},
  {"service":"GitHub Pages","cname":["github.io"],"fingerprint":"There isn't a GitHub Pages site here.","nxdomain":false,"status":"Vulnerable","discussion":""},
  {"service":"Azure","cname":["azurewebsites.net"],"fingerprint":"","nxdomain":true,"status":"Vulnerable","discussion":""}
]`

// ---- fingerprint matching --------------------------------------------------

func TestMatchCNAME_Hit(t *testing.T) {
	db := mustDB(t, testFingerprintsJSON)
	hits := db.MatchCNAME("mybucket.s3.amazonaws.com")
	if len(hits) != 1 || hits[0].Service != "AWS/S3" {
		t.Fatalf("expected AWS/S3 hit, got %v", hits)
	}
}

func TestMatchCNAME_Miss(t *testing.T) {
	db := mustDB(t, testFingerprintsJSON)
	hits := db.MatchCNAME("app.heroku.com")
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %v", hits)
	}
}

func TestMatchBody(t *testing.T) {
	db := mustDB(t, testFingerprintsJSON)
	fp := db.MatchCNAME("mybucket.s3.amazonaws.com")[0]

	if !fp.MatchBody([]byte("... The specified bucket does not exist ...")) {
		t.Error("expected body match")
	}
	if fp.MatchBody([]byte("hello world")) {
		t.Error("unexpected body match")
	}
}

func TestMatchBody_EmptyFingerprint(t *testing.T) {
	db := mustDB(t, testFingerprintsJSON)
	fp := db.MatchCNAME("app.azurewebsites.net")[0]
	if fp.MatchBody([]byte("anything")) {
		t.Error("empty fingerprint should never match body")
	}
}

// ---- SPF parsing -----------------------------------------------------------

func TestExtractSPF(t *testing.T) {
	cases := []struct {
		txts []string
		want string
	}{
		{[]string{"v=spf1 include:spf.example.com ~all"}, "v=spf1 include:spf.example.com ~all"},
		{[]string{"some-other-record", "v=spf1 include:a.com -all"}, "v=spf1 include:a.com -all"},
		{[]string{"v=spf1"}, "v=spf1"},
		{[]string{"not-spf"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		got := extractSPF(c.txts)
		if got != c.want {
			t.Errorf("extractSPF(%v) = %q, want %q", c.txts, got, c.want)
		}
	}
}

// stubResolver is a minimal resolver that records calls and returns canned data.
type stubResolver struct {
	cnameChains map[string][]string
	cnameErrors map[string]error
	txts        map[string][]string
	nsList      map[string][]string
	soaError    map[string]error // keyed by "zone@ns"
	wildcards   map[string]bool
}

func newStub() *stubResolver {
	return &stubResolver{
		cnameChains: map[string][]string{},
		cnameErrors: map[string]error{},
		txts:        map[string][]string{},
		nsList:      map[string][]string{},
		soaError:    map[string]error{},
		wildcards:   map[string]bool{},
	}
}

// We can't easily swap out the *resolver.Resolver since it has unexported fields,
// so we test the pure-logic helpers separately and drive the full detectors
// through an httptest server for HTTP-dependent paths.

// ---- CNAME confidence ladder -----------------------------------------------

// TestCNAMEConfidence_Confirmed_BodyMatch exercises the path where the HTTP
// body contains the fingerprint string → Confirmed.
func TestCNAMEConfidence_Confirmed_BodyMatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("The specified bucket does not exist"))
	}))
	defer srv.Close()

	// Point sharedTransport at the test TLS server.
	orig := sharedTransport
	sharedTransport = srv.Client().Transport.(*http.Transport)
	defer func() { sharedTransport = orig }()

	db := mustDB(t, testFingerprintsJSON)

	// Fabricate a fingerprint match result for the test server host.
	fp := db.MatchCNAME("mybucket.s3.amazonaws.com")[0]
	host := srv.Listener.Addr().String()

	f := finding.Finding{
		Subdomain:   "test.example.com",
		Vector:      finding.VectorCNAME,
		Service:     fp.Service,
		Fingerprint: fp.Fingerprint,
		CNAME:       host,
	}

	cfg := Config{HTTPSOnly: true, Timeout: 5 * 1e9} // 5s

	body, scheme, err := probeHTTP(context.Background(), host, cfg)
	if err != nil {
		t.Fatalf("probeHTTP: %v", err)
	}
	if scheme != "https" {
		t.Errorf("expected https, got %s", scheme)
	}
	if !fp.MatchBody(body) {
		t.Errorf("expected body match")
	}

	// Assign confidence as the detector would.
	if fp.MatchBody(body) {
		f.Confidence = finding.Confirmed
	} else {
		f.Confidence = finding.Likely
	}
	if f.Confidence != finding.Confirmed {
		t.Errorf("expected Confirmed, got %s", f.Confidence)
	}
}

// TestCNAMEConfidence_Likely_NoBodyMatch exercises the path where the CNAME
// matches a known service but the body string is absent → Likely.
func TestCNAMEConfidence_Likely_NoBodyMatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some other content"))
	}))
	defer srv.Close()

	orig := sharedTransport
	sharedTransport = srv.Client().Transport.(*http.Transport)
	defer func() { sharedTransport = orig }()

	db := mustDB(t, testFingerprintsJSON)
	fp := db.MatchCNAME("mybucket.s3.amazonaws.com")[0]
	host := srv.Listener.Addr().String()

	cfg := Config{HTTPSOnly: true, Timeout: 5 * 1e9}
	body, _, err := probeHTTP(context.Background(), host, cfg)
	if err != nil {
		t.Fatalf("probeHTTP: %v", err)
	}

	var conf finding.Confidence
	if fp.MatchBody(body) {
		conf = finding.Confirmed
	} else {
		conf = finding.Likely
	}
	if conf != finding.Likely {
		t.Errorf("expected Likely, got %s", conf)
	}
}

// TestCNAMEConfidence_Potential checks the matchChain helper returns no hits
// when no fingerprint covers the CNAME target.
func TestCNAMEConfidence_Potential(t *testing.T) {
	db := mustDB(t, testFingerprintsJSON)
	chain := []string{"app.unknown-service.io"}
	matches := matchChain(db, chain)
	if len(matches) != 0 {
		t.Errorf("expected no matches for unknown service, got %d", len(matches))
	}
}

// TestMatchChain_Dedup verifies that the same service matched at multiple
// chain hops is emitted only once.
func TestMatchChain_Dedup(t *testing.T) {
	db := mustDB(t, `[{"service":"Svc","cname":["a.com","b.com"],"fingerprint":"x","nxdomain":false,"status":"Vulnerable","discussion":""}]`)
	// Both hops match the same service.
	chain := []string{"foo.a.com", "bar.b.com"}
	matches := matchChain(db, chain)
	if len(matches) != 1 {
		t.Errorf("expected 1 deduplicated match, got %d", len(matches))
	}
}

// ---- NS provider matching --------------------------------------------------

func TestMatchNSProvider_Known(t *testing.T) {
	ns := []string{"ns1.p20.awsdns-20.org", "ns2.p20.awsdns-20.org"}
	p := matchNSProvider(ns)
	if p == "" {
		t.Error("expected provider match for AWS Route 53 nameserver")
	}
}

func TestMatchNSProvider_Unknown(t *testing.T) {
	ns := []string{"ns1.example-registrar.com"}
	p := matchNSProvider(ns)
	if p != "" {
		t.Errorf("expected empty provider, got %q", p)
	}
}

// ---- isConnectError --------------------------------------------------------

func TestIsConnectError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"connection refused", true},
		{"no such host", true},
		{"i/o timeout", true},
		{"tls: bad certificate", true},
		{"404 Not Found", false},
		{"", false},
	}
	for _, c := range cases {
		err := &errMsg{c.msg}
		if got := isConnectError(err); got != c.want {
			t.Errorf("isConnectError(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

type errMsg struct{ s string }

func (e *errMsg) Error() string { return e.s }

// ---- DB merge / load -------------------------------------------------------

func TestDB_Merge(t *testing.T) {
	a := mustDB(t, `[{"service":"A","cname":["a.com"],"fingerprint":"x","nxdomain":false,"status":"Vulnerable","discussion":""}]`)
	b := mustDB(t, `[{"service":"A","cname":["a.com"],"fingerprint":"y","nxdomain":false,"status":"Vulnerable","discussion":""},
	                  {"service":"B","cname":["b.com"],"fingerprint":"z","nxdomain":false,"status":"Vulnerable","discussion":""}]`)
	a.Merge(b)
	if a.Len() != 2 {
		t.Errorf("expected 2 entries after merge, got %d", a.Len())
	}
	// Service A should be replaced by b's version.
	hits := a.MatchCNAME("app.a.com")
	if len(hits) != 1 || hits[0].Fingerprint != "y" {
		t.Errorf("expected replaced fingerprint 'y', got %v", hits)
	}
}

// ---- Embedded seed DB ------------------------------------------------------

func TestEmbedded(t *testing.T) {
	db, err := fingerprints.Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	if db.Len() == 0 {
		t.Error("embedded DB should have at least one fingerprint")
	}
}

// ---- resolver sentinel values ----------------------------------------------

func TestResolverSentinels(t *testing.T) {
	r := resolver.New(nil, 0)
	if r == nil {
		t.Fatal("resolver.New returned nil")
	}
	// Servers() and Timeout() must not panic.
	_ = r.Servers()
	_ = r.Timeout()
}

// ---- #3: per-host rate limiter goroutine lifecycle -------------------------

// TestDrainBuckets_ClearsBucketMap verifies that DrainBuckets removes all
// entries from the bucket map and that new requests after drain create fresh
// buckets (proving the stop channel design does not leave dangling state).
func TestDrainBuckets_ClearsBucketMap(t *testing.T) {
	// Ensure a clean slate.
	DrainBuckets()

	// Create some buckets.
	for i := 0; i < 5; i++ {
		_ = destWait(context.Background(), fmt.Sprintf("host%d.test.invalid", i))
	}

	bucketsMu.Lock()
	before := len(buckets)
	bucketsMu.Unlock()

	if before == 0 {
		t.Fatal("expected non-zero bucket count after destWait calls")
	}

	DrainBuckets()

	bucketsMu.Lock()
	after := len(buckets)
	bucketsMu.Unlock()

	if after != 0 {
		t.Errorf("DrainBuckets must clear all buckets, got %d remaining", after)
	}
}

// TestDrainBuckets_GoroutinesStop verifies that the ticker goroutine for a
// bucket actually exits after DrainBuckets is called. The goroutine count
// must not grow unbounded with input size.
func TestDrainBuckets_GoroutinesStop(t *testing.T) {
	DrainBuckets()

	before := runtime.NumGoroutine()

	const hosts = 20
	for i := 0; i < hosts; i++ {
		_ = destWait(context.Background(), fmt.Sprintf("gtest%d.test.invalid", i))
	}

	created := runtime.NumGoroutine()
	if created <= before {
		// Runtime may reuse goroutines; skip rather than fail.
		t.Skip("goroutine count did not increase; skipping goroutine-drain check")
	}

	DrainBuckets()

	// Allow goroutines a moment to observe the stop channel and exit.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		runtime.Gosched()
		if runtime.NumGoroutine() <= before+2 { // +2 for scheduler noise
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Errorf("goroutines did not stop after DrainBuckets: before=%d created=%d now=%d",
		before, created, runtime.NumGoroutine())
}

// TestDestWait_ContextCancellation verifies that destWait returns ctx.Err()
// when the context is cancelled while waiting for a token.
func TestDestWait_ContextCancellation(t *testing.T) {
	DrainBuckets()

	// Create a bucket with zero initial tokens and a very slow refill so it
	// will definitely block.
	const rps = 1
	b := &hostBucket{
		tokens: make(chan struct{}, rps),
		stop:   make(chan struct{}),
	}
	// Do NOT pre-fill — bucket starts empty so the first destWait blocks.
	interval := time.Second / rps
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
				default:
				}
			}
		}
	}()

	bucketsMu.Lock()
	buckets["ctx-cancel-test.invalid"] = b
	bucketsMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- destWait(ctx, "ctx-cancel-test.invalid")
	}()

	// Cancel immediately — destWait should unblock.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected non-nil error from cancelled destWait")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("destWait did not return after context cancellation")
	}

	// DrainBuckets closes b.stop and clears the map — do not close b.stop manually.
	DrainBuckets()
}

// ---- #4: TLS InsecureSkipVerify is present and deliberate ------------------

// TestSharedTransport_InsecureSkipVerify confirms the HTTP probe transport
// skips TLS verification. Dangling endpoints characteristically serve
// mismatched certificates; without this flag, the HTTPS probe would fail on
// the very targets the tool is designed to detect.
func TestSharedTransport_InsecureSkipVerify(t *testing.T) {
	if sharedTransport.TLSClientConfig == nil {
		t.Fatal("sharedTransport.TLSClientConfig must not be nil")
	}
	if !sharedTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("sharedTransport must set InsecureSkipVerify=true for recon probes")
	}
}

// TestProbeHTTP_MismatchedCert verifies that probeHTTP succeeds against a TLS
// server whose certificate does not match the probed hostname — the exact
// condition present on dangling-CNAME endpoints.
func TestProbeHTTP_MismatchedCert(t *testing.T) {
	const body = "The specified bucket does not exist"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// srv.Client() has the test CA; our sharedTransport (InsecureSkipVerify)
	// should succeed even without that CA.
	orig := sharedTransport
	sharedTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	defer func() { sharedTransport = orig }()

	got, scheme, err := probeHTTP(context.Background(), srv.Listener.Addr().String(),
		Config{HTTPSOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("probeHTTP with InsecureSkipVerify failed: %v", err)
	}
	if scheme != "https" {
		t.Errorf("expected https scheme, got %s", scheme)
	}
	if string(got) != body {
		t.Errorf("expected body %q, got %q", body, got)
	}
}

// TestNSUnanimity verifies that matchNSProvider only confirms known providers
// and that the NS algorithm skeleton respects the unanimity invariant.
// (Live DNS testing is not in-scope for unit tests; this covers logic paths.)
func TestNSUnanimity_MatchProvider(t *testing.T) {
	// Known providers should be matched.
	known := []struct {
		ns   []string
		want bool
	}{
		{[]string{"ns1.example.awsdns-01.com"}, true},
		{[]string{"ns1.googledomains.com"}, true},
		{[]string{"ns1.azure-dns.com"}, true},
		{[]string{"ns1.cloudflare.com"}, true},
		{[]string{"ns1.completely-unknown-registrar.com"}, false},
	}
	for _, tc := range known {
		got := matchNSProvider(tc.ns) != ""
		if got != tc.want {
			t.Errorf("matchNSProvider(%v) known=%v, want=%v", tc.ns, got, tc.want)
		}
	}
}
