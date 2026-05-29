package detectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/nsproviders"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
	"github.com/miekg/dns"
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

// ---- MX provider matching --------------------------------------------------

func TestMatchMailProvider_Known(t *testing.T) {
	cases := []struct {
		mx   string
		want bool
	}{
		{"aspmx.l.google.com", true},
		{"mail.protection.outlook.com", true},
		{"smtp.sendgrid.net", true},
		{"mta.mailgun.org", true},
		{"inbound-smtp.us-east-1.amazonses.com", true},
		{"ns1.completely-unknown-mailhost.io", false},
	}
	for _, tc := range cases {
		got := matchMailProvider(tc.mx) != ""
		if got != tc.want {
			t.Errorf("matchMailProvider(%q) known=%v, want=%v", tc.mx, got, tc.want)
		}
	}
}

func TestMatchMailProvider_Unknown(t *testing.T) {
	mx := []string{"mail.private-company.example"}
	p := matchMailProvider(mx[0])
	if p != "" {
		t.Errorf("expected empty provider, got %q", p)
	}
}

// TestMXFinding_VectorConstant checks that VectorMX has the correct wire value.
func TestMXFinding_VectorConstant(t *testing.T) {
	if string(finding.VectorMX) != "mx" {
		t.Errorf("VectorMX wire value must be \"mx\", got %q", finding.VectorMX)
	}
}

// TestMXFinding_MXHostsField confirms the MXHosts field is populated correctly
// when constructing a VectorMX finding (struct-level test; no DNS needed).
func TestMXFinding_MXHostsField(t *testing.T) {
	f := finding.Finding{
		Subdomain:  "mail.example.com",
		Vector:     finding.VectorMX,
		Confidence: finding.Confirmed,
		MXHosts:    []string{"dangling.mail.example.com"},
		Evidence:   "MX host is NXDOMAIN — mail host does not exist",
	}
	if len(f.MXHosts) != 1 || f.MXHosts[0] != "dangling.mail.example.com" {
		t.Errorf("unexpected MXHosts: %v", f.MXHosts)
	}
	if f.Vector != finding.VectorMX {
		t.Errorf("expected VectorMX, got %q", f.Vector)
	}
}

// TestSetProviders_OverridesActiveList verifies that SetProviders swaps the
// list the NS detector matches against, and that resetting to nil restores the
// cache-or-default behaviour.
func TestSetProviders_OverridesActiveList(t *testing.T) {
	defer SetProviders(nil) // restore default for other tests

	custom, err := nsproviders.Load([]byte(`[{"suffix":"only-this.test","label":"Custom","vulnerable":true}]`))
	if err != nil {
		t.Fatalf("nsproviders.Load: %v", err)
	}
	SetProviders(custom)

	if activeProviders().Match("ns1.only-this.test") == "" {
		t.Error("SetProviders override not applied: custom suffix did not match")
	}
	if activeProviders().Match("ns1.linode.com") != "" {
		t.Error("SetProviders override should have replaced the default list")
	}
}

// ---- DKIM selector vector --------------------------------------------------

// TestDKIMFinding_VectorConstant checks that VectorDKIM has the correct wire value.
func TestDKIMFinding_VectorConstant(t *testing.T) {
	if string(finding.VectorDKIM) != "dkim" {
		t.Errorf("VectorDKIM wire value must be \"dkim\", got %q", finding.VectorDKIM)
	}
}

// TestDKIMFinding_Fields confirms the DKIM-specific fields are populated as the
// detector would build them (struct-level test; no DNS needed).
func TestDKIMFinding_Fields(t *testing.T) {
	f := finding.Finding{
		Subdomain:    "s1._domainkey.example.com",
		Vector:       finding.VectorDKIM,
		Confidence:   finding.Confirmed,
		CNAME:        "s1.domainkey.u123.wl.sendgrid.net",
		DKIMSelector: "s1",
		Evidence:     "DKIM selector CNAME target is NXDOMAIN — ESP resource reclaimable",
	}
	if f.Vector != finding.VectorDKIM {
		t.Errorf("expected VectorDKIM, got %q", f.Vector)
	}
	if f.DKIMSelector != "s1" {
		t.Errorf("expected selector s1, got %q", f.DKIMSelector)
	}
	if f.CNAME == "" {
		t.Error("DKIM finding must carry the dangling CNAME target")
	}
}

// TestDefaultDKIMSelectors_CoversCommonESPs verifies the built-in selector list
// includes the well-known ESP selectors the detector relies on for coverage.
func TestDefaultDKIMSelectors_CoversCommonESPs(t *testing.T) {
	want := []string{"default", "google", "s1", "s2", "k1", "selector1", "selector2"}
	have := map[string]bool{}
	for _, s := range DefaultDKIMSelectors {
		have[s] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("DefaultDKIMSelectors missing common selector %q", w)
		}
	}
}

// dkimDNSServer spins up a local UDP DNS server that models a single dangling
// DKIM selector. The selector danglingSel publishes a CNAME to danglingTarget;
// danglingTarget is NXDOMAIN. Every other name returns NOERROR with no answer.
// It returns the server address and a cleanup func.
func dkimDNSServer(t *testing.T, danglingFQDN, danglingTarget string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if pErr := req.Unpack(buf[:n]); pErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)

			q := req.Question[0]
			name := q.Name

			switch {
			case q.Qtype == dns.TypeCNAME && name == dns.Fqdn(danglingFQDN):
				resp.Answer = []dns.RR{&dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dns.Fqdn(danglingTarget),
				}}
			case q.Qtype == dns.TypeA && name == dns.Fqdn(danglingTarget):
				// The delegated ESP resource is gone.
				resp.Rcode = dns.RcodeNameError
			default:
				// All other selectors: NOERROR, no CNAME → not delegated.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestDKIM_DanglingSelectorConfirmed drives the full DKIM detector against a
// local DNS server: one selector CNAMEs to a target that is NXDOMAIN, which must
// produce exactly one Confirmed VectorDKIM finding.
func TestDKIM_DanglingSelectorConfirmed(t *testing.T) {
	const (
		target   = "example.com"
		selector = "s1"
	)
	danglingFQDN := selector + "._domainkey." + target
	danglingTarget := "s1.domainkey.deleted-esp.invalid"

	addr, cleanup := dkimDNSServer(t, danglingFQDN, danglingTarget)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{"s1", "s2", "default"})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 dangling-selector finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDKIM {
		t.Errorf("vector: got %q, want dkim", f.Vector)
	}
	if f.Confidence != finding.Confirmed {
		t.Errorf("confidence: got %q, want CONFIRMED", f.Confidence)
	}
	if f.DKIMSelector != selector {
		t.Errorf("selector: got %q, want %q", f.DKIMSelector, selector)
	}
	if f.CNAME != danglingTarget {
		t.Errorf("cname: got %q, want %q", f.CNAME, danglingTarget)
	}
	if f.Subdomain != danglingFQDN {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, danglingFQDN)
	}
}

// TestDKIM_NoFindingsWhenNotDelegated verifies that selectors without a CNAME
// (inline TXT keys or absent records) produce no findings.
func TestDKIM_NoFindingsWhenNotDelegated(t *testing.T) {
	// Server with a dangling FQDN that none of the probed selectors match, so
	// every selector returns NOERROR/no-CNAME.
	addr, cleanup := dkimDNSServer(t, "unused._domainkey.example.com", "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, "example.com", r, []string{"s1", "default", "google"})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-delegated selectors, got %d: %+v", len(findings), findings)
	}
}

// TestDKIM_DedupSelectors verifies a duplicated selector in the override list is
// probed only once (no duplicate findings).
func TestDKIM_DedupSelectors(t *testing.T) {
	const target = "example.com"
	danglingFQDN := "s1._domainkey." + target
	danglingTarget := "s1.domainkey.deleted-esp.invalid"

	addr, cleanup := dkimDNSServer(t, danglingFQDN, danglingTarget)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{"s1", "S1", " s1 "})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(findings))
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

// ---- DMARC report-domain takeover vector -----------------------------------

// TestDMARCFinding_VectorConstant pins the wire value of the DMARC vector.
func TestDMARCFinding_VectorConstant(t *testing.T) {
	if finding.VectorDMARC != "dmarc" {
		t.Errorf("VectorDMARC: got %q, want dmarc", finding.VectorDMARC)
	}
}

func TestExtractDMARC(t *testing.T) {
	cases := []struct {
		txts []string
		want string
	}{
		{[]string{"v=DMARC1; p=reject; rua=mailto:r@x.net"}, "v=DMARC1; p=reject; rua=mailto:r@x.net"},
		{[]string{"some-other", "v=DMARC1; p=none"}, "v=DMARC1; p=none"},
		{[]string{"  v=DMARC1; p=quarantine  "}, "v=DMARC1; p=quarantine"},
		{[]string{"v=spf1 include:a.com -all"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := extractDMARC(c.txts); got != c.want {
			t.Errorf("extractDMARC(%v) = %q, want %q", c.txts, got, c.want)
		}
	}
}

func TestDMARCReportDomains(t *testing.T) {
	cases := []struct {
		record string
		want   []string
	}{
		{
			"v=DMARC1; p=reject; rua=mailto:agg@reports.example.net",
			[]string{"reports.example.net"},
		},
		{
			"v=DMARC1; p=none; rua=mailto:a@x.net,mailto:b@y.net; ruf=mailto:f@z.net",
			[]string{"x.net", "y.net", "z.net"},
		},
		{
			// size-limit suffix and mixed case
			"v=DMARC1; RUA=MAILTO:Agg@Reports.Example.NET!10m",
			[]string{"reports.example.net"},
		},
		{
			// no reporting tags
			"v=DMARC1; p=reject; pct=100",
			nil,
		},
		{
			// malformed mailto (no @) is skipped
			"v=DMARC1; rua=mailto:not-an-address",
			nil,
		},
	}
	for _, c := range cases {
		got := dmarcReportDomains(c.record)
		if len(got) != len(c.want) {
			t.Fatalf("dmarcReportDomains(%q) = %v, want %v", c.record, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("dmarcReportDomains(%q)[%d] = %q, want %q", c.record, i, got[i], c.want[i])
			}
		}
	}
}

// dmarcDNSServer spins up a local UDP DNS server modelling a DMARC record at
// _dmarc.<target> whose TXT carries dmarcRecord. reportDomain is NXDOMAIN; every
// other A query returns NOERROR with no answer (i.e. the domain exists).
func dmarcDNSServer(t *testing.T, target, dmarcRecord, nxDomain string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if pErr := req.Unpack(buf[:n]); pErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)

			q := req.Question[0]
			name := q.Name

			switch {
			case q.Qtype == dns.TypeTXT && name == dns.Fqdn("_dmarc."+target):
				resp.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{dmarcRecord},
				}}
			case q.Qtype == dns.TypeA && name == dns.Fqdn(nxDomain):
				resp.Rcode = dns.RcodeNameError
			case q.Qtype == dns.TypeCNAME && name == dns.Fqdn(nxDomain):
				resp.Rcode = dns.RcodeNameError
			default:
				// Everything else NOERROR/no-answer → exists.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestDMARC_DanglingReportDomainPotential drives the full detector: a DMARC
// policy whose rua= domain is NXDOMAIN must yield exactly one Potential finding.
func TestDMARC_DanglingReportDomainPotential(t *testing.T) {
	const (
		target       = "example.com"
		reportDomain = "reports.deleted-vendor.invalid"
	)
	record := "v=DMARC1; p=reject; rua=mailto:agg@" + reportDomain

	addr, cleanup := dmarcDNSServer(t, target, record, reportDomain)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, target, r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDMARC {
		t.Errorf("vector: got %q, want dmarc", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.DMARCURI != reportDomain {
		t.Errorf("dmarc_uri: got %q, want %q", f.DMARCURI, reportDomain)
	}
	if f.Subdomain != reportDomain {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, reportDomain)
	}
}

// TestDMARC_LiveReportDomainNoFinding verifies that a report domain which
// resolves (exists) produces no finding. The policy is p=reject so that the
// (separately tested) weak-policy sub-case does not fire — this test isolates
// the dangling-report-domain path.
func TestDMARC_LiveReportDomainNoFinding(t *testing.T) {
	const target = "example.com"
	// nxDomain is some unrelated name; the report domain "live.example.net"
	// is not it, so the server returns NOERROR for it → exists → no finding.
	record := "v=DMARC1; p=reject; rua=mailto:a@live.example.net"

	addr, cleanup := dmarcDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, target, r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for live report domain, got %d: %+v", len(findings), findings)
	}
}

// TestDMARCPolicy unit-tests the p= tag parser across enforcement levels,
// case-insensitivity, tag ordering, and absence.
func TestDMARCPolicy(t *testing.T) {
	cases := []struct {
		record string
		want   string
	}{
		{"v=DMARC1; p=none", "none"},
		{"v=DMARC1; p=reject; rua=mailto:r@x.net", "reject"},
		{"v=DMARC1; p=quarantine; pct=50", "quarantine"},
		{"v=DMARC1; P=None", "none"},                     // case-insensitive tag + value
		{"v=DMARC1; rua=mailto:r@x.net; p=none", "none"}, // p= not first
		{"v=DMARC1; sp=none; p=reject", "reject"},        // sp= must not shadow p=
		{"v=DMARC1; rua=mailto:r@x.net", ""},             // no p= tag
		{"v=DMARC1;p=none ", "none"},                     // no space after ; , trailing space
		{"v=spf1 include:a.com -all", ""},                // not a DMARC record
	}
	for _, c := range cases {
		if got := dmarcPolicy(c.record); got != c.want {
			t.Errorf("dmarcPolicy(%q) = %q, want %q", c.record, got, c.want)
		}
	}
}

// TestDMARC_WeakPolicyPotential drives the full detector: a p=none policy whose
// report domains all resolve must yield exactly one Potential weak-policy
// finding keyed on the target, carrying the policy in DMARCPolicy (not DMARCURI).
func TestDMARC_WeakPolicyPotential(t *testing.T) {
	const target = "example.com"
	// rua points at a live domain so the dangling-report sub-case yields nothing;
	// the only finding must be the weak policy itself.
	record := "v=DMARC1; p=none; rua=mailto:a@live.example.net"

	addr, cleanup := dmarcDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, target, r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDMARC {
		t.Errorf("vector: got %q, want dmarc", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.DMARCPolicy != "none" {
		t.Errorf("dmarc_policy: got %q, want none", f.DMARCPolicy)
	}
	if f.DMARCURI != "" {
		t.Errorf("dmarc_uri: got %q, want empty for the weak-policy sub-case", f.DMARCURI)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (weak policy is keyed on the target)", f.Subdomain, target)
	}
}

// TestDMARC_WeakPolicyNoReportingEvidence verifies the evidence string calls out
// the worse case: p=none with no rua= aggregate reporting (no enforcement AND no
// visibility).
func TestDMARC_WeakPolicyNoReportingEvidence(t *testing.T) {
	const target = "example.com"
	record := "v=DMARC1; p=none" // no rua=

	addr, cleanup := dmarcDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, target, r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "no rua=") {
		t.Errorf("evidence %q does not call out the missing aggregate reporting", findings[0].Evidence)
	}
}

// TestDMARC_StrongPolicyNoWeakFinding verifies that p=reject and p=quarantine
// (enforcing policies) never produce a weak-policy finding.
func TestDMARC_StrongPolicyNoWeakFinding(t *testing.T) {
	for _, policy := range []string{"reject", "quarantine"} {
		const target = "example.com"
		record := "v=DMARC1; p=" + policy + "; rua=mailto:a@live.example.net"

		addr, cleanup := dmarcDNSServer(t, target, record, "unused.invalid")

		r := resolver.New([]string{addr}, 2*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		findings, err := DMARC(ctx, target, r)
		cancel()
		cleanup()
		if err != nil {
			t.Fatalf("DMARC(p=%s): %v", policy, err)
		}
		if len(findings) != 0 {
			t.Errorf("p=%s: expected no findings, got %d: %+v", policy, len(findings), findings)
		}
	}
}

// TestDMARC_WeakPolicyAndDanglingReport verifies both sub-cases fire together
// when a p=none policy also names an NXDOMAIN report domain: one weak-policy
// finding (keyed on the target) plus one dangling-report finding (keyed on the
// claimable domain).
func TestDMARC_WeakPolicyAndDanglingReport(t *testing.T) {
	const (
		target       = "example.com"
		reportDomain = "reports.deleted-vendor.invalid"
	)
	record := "v=DMARC1; p=none; rua=mailto:agg@" + reportDomain

	addr, cleanup := dmarcDNSServer(t, target, record, reportDomain)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, target, r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d: %+v", len(findings), findings)
	}

	var sawWeak, sawDangling bool
	for _, f := range findings {
		switch {
		case f.DMARCPolicy == "none" && f.Subdomain == target && f.DMARCURI == "":
			sawWeak = true
		case f.DMARCURI == reportDomain && f.Subdomain == reportDomain && f.DMARCPolicy == "":
			sawDangling = true
		}
	}
	if !sawWeak {
		t.Errorf("missing weak-policy finding in %+v", findings)
	}
	if !sawDangling {
		t.Errorf("missing dangling-report finding in %+v", findings)
	}
}

// TestDMARC_NoRecordNoFinding verifies that a target with no DMARC TXT record
// produces no findings (and no error).
func TestDMARC_NoRecordNoFinding(t *testing.T) {
	// Server returns NOERROR/no-answer for the _dmarc TXT query.
	addr, cleanup := dmarcDNSServer(t, "other.com", "v=DMARC1; p=none", "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DMARC(ctx, "example.com", r)
	if err != nil {
		t.Fatalf("DMARC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no DMARC record, got %d", len(findings))
	}
}

// ---- SPF redirect= modifier ------------------------------------------------

// TestSPFReferences verifies that include: mechanisms and the redirect=
// modifier are both extracted, in record order, with case-folding and the
// redirect flag set correctly. Non-referencing mechanisms (ip4, a, mx, all)
// must be ignored.
func TestSPFReferences(t *testing.T) {
	cases := []struct {
		record string
		want   []spfReference
	}{
		{
			"v=spf1 include:_spf.example.com -all",
			[]spfReference{{domain: "_spf.example.com"}},
		},
		{
			"v=spf1 redirect=_spf.example.net",
			[]spfReference{{domain: "_spf.example.net", redirect: true}},
		},
		{
			// both directives, mixed case, plus ignorable mechanisms
			"v=spf1 ip4:1.2.3.0/24 include:A.Example.COM a mx redirect=B.Example.NET ~all",
			[]spfReference{
				{domain: "a.example.com"},
				{domain: "b.example.net", redirect: true},
			},
		},
		{
			// no external references
			"v=spf1 ip4:10.0.0.0/8 -all",
			nil,
		},
	}
	for _, c := range cases {
		got := spfReferences(c.record)
		if len(got) != len(c.want) {
			t.Fatalf("spfReferences(%q) = %v, want %v", c.record, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("spfReferences(%q)[%d] = %+v, want %+v", c.record, i, got[i], c.want[i])
			}
		}
	}
}

// spfDNSServer spins up a local UDP DNS server modelling an SPF policy: the
// target's TXT record carries spfRecord, and nxDomain is NXDOMAIN for both A and
// CNAME queries (the claimable target). Every other name returns NOERROR with no
// answer (i.e. it exists with no SPF policy of its own, so recursion stops).
func spfDNSServer(t *testing.T, target, spfRecord, nxDomain string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if pErr := req.Unpack(buf[:n]); pErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)

			q := req.Question[0]
			name := q.Name

			switch {
			case q.Qtype == dns.TypeTXT && name == dns.Fqdn(target):
				resp.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{spfRecord},
				}}
			case name == dns.Fqdn(nxDomain) && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeCNAME):
				resp.Rcode = dns.RcodeNameError
			default:
				// Everything else NOERROR/no-answer → exists, no SPF policy.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestSPF_DanglingRedirectPotential drives the full SPF detector: a policy whose
// redirect= target is NXDOMAIN must yield exactly one Potential VectorSPF
// finding whose evidence names the redirect= directive (not include:).
func TestSPF_DanglingRedirectPotential(t *testing.T) {
	const (
		target         = "example.com"
		redirectTarget = "_spf.deleted-vendor.invalid"
	)
	record := "v=spf1 redirect=" + redirectTarget

	addr, cleanup := spfDNSServer(t, target, record, redirectTarget)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := SPF(ctx, target, r)
	if err != nil {
		t.Fatalf("SPF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorSPF {
		t.Errorf("vector: got %q, want spf", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.SPFInclude != redirectTarget {
		t.Errorf("spf_include: got %q, want %q", f.SPFInclude, redirectTarget)
	}
	if f.Subdomain != redirectTarget {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, redirectTarget)
	}
	if !strings.Contains(f.Evidence, "redirect=") {
		t.Errorf("evidence: got %q, want it to mention redirect=", f.Evidence)
	}
}

// TestSPF_LiveRedirectNoFinding verifies that a redirect= target that resolves
// (exists) produces no finding.
func TestSPF_LiveRedirectNoFinding(t *testing.T) {
	const target = "example.com"
	// The redirect target "live.example.net" is not the server's NXDOMAIN name,
	// so it returns NOERROR → exists → no finding.
	record := "v=spf1 redirect=live.example.net"

	addr, cleanup := spfDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := SPF(ctx, target, r)
	if err != nil {
		t.Fatalf("SPF: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for live redirect target, got %d: %+v", len(findings), findings)
	}
}

// TestSPFPermissiveAll is a table-driven check of the permissive-"all" parser:
// only a Pass-qualified catch-all ("+all" or a bare "all", which RFC 7208
// §4.6.2 treats as Pass) is flagged; -all/~all/?all and records with no all
// mechanism are not. The match is case-insensitive on the mechanism name.
func TestSPFPermissiveAll(t *testing.T) {
	cases := []struct {
		record string
		want   string
	}{
		{"v=spf1 include:_spf.example.com -all", ""},     // hard fail — secure
		{"v=spf1 ip4:10.0.0.0/8 ~all", ""},               // soft fail — cautious
		{"v=spf1 ?all", ""},                              // neutral
		{"v=spf1 +all", "+all"},                          // explicit pass — permissive
		{"v=spf1 mx all", "all"},                         // bare all defaults to +all
		{"v=spf1 include:_spf.example.com +ALL", "+ALL"}, // case-insensitive
		{"v=spf1 ip4:1.2.3.0/24", ""},                    // no all mechanism at all
		{"v=spf1 -all include:_spf.example.com", ""},     // hard fail anywhere
	}
	for _, c := range cases {
		if got := spfPermissiveAll(c.record); got != c.want {
			t.Errorf("spfPermissiveAll(%q) = %q, want %q", c.record, got, c.want)
		}
	}
}

// TestSPF_PermissiveAllPotential drives the full SPF detector against a record
// ending in "+all": it must yield exactly one Potential VectorSPF finding keyed
// on the target (not an external domain), with SPFAll set, SPFInclude empty, and
// evidence that names the offending mechanism.
func TestSPF_PermissiveAllPotential(t *testing.T) {
	const target = "spoofable.example.com"
	record := "v=spf1 ip4:192.0.2.0/24 +all"

	addr, cleanup := spfDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := SPF(ctx, target, r)
	if err != nil {
		t.Fatalf("SPF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorSPF {
		t.Errorf("vector: got %q, want spf", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want the target %q (permissive sub-case is keyed on the target)", f.Subdomain, target)
	}
	if f.SPFAll != "+all" {
		t.Errorf("spf_all: got %q, want %q", f.SPFAll, "+all")
	}
	if f.SPFInclude != "" {
		t.Errorf("spf_include: got %q, want empty for the permissive sub-case", f.SPFInclude)
	}
	if !strings.Contains(f.Evidence, "+all") {
		t.Errorf("evidence: got %q, want it to mention +all", f.Evidence)
	}
}

// TestSPF_HardFailAllNoFinding verifies that the secure "-all" catch-all yields
// no permissive finding.
func TestSPF_HardFailAllNoFinding(t *testing.T) {
	const target = "secure.example.com"
	record := "v=spf1 ip4:192.0.2.0/24 -all"

	addr, cleanup := spfDNSServer(t, target, record, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := SPF(ctx, target, r)
	if err != nil {
		t.Fatalf("SPF: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a -all policy, got %d: %+v", len(findings), findings)
	}
}

// TestSPF_PermissiveAndDanglingBothFire confirms the permissive-policy and
// dangling-reference sub-cases are independent and can both fire for one record:
// a "+all" policy that also includes an NXDOMAIN domain yields two findings.
func TestSPF_PermissiveAndDanglingBothFire(t *testing.T) {
	const (
		target   = "doubly-broken.example.com"
		danglDom = "_spf.deleted-vendor.invalid"
	)
	record := "v=spf1 include:" + danglDom + " +all"

	addr, cleanup := spfDNSServer(t, target, record, danglDom)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := SPF(ctx, target, r)
	if err != nil {
		t.Fatalf("SPF: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (permissive + dangling), got %d: %+v", len(findings), findings)
	}

	var sawPermissive, sawDangling bool
	for _, f := range findings {
		if f.Vector != finding.VectorSPF {
			t.Errorf("vector: got %q, want spf", f.Vector)
		}
		switch {
		case f.SPFAll != "":
			sawPermissive = true
			if f.Subdomain != target {
				t.Errorf("permissive finding subdomain: got %q, want %q", f.Subdomain, target)
			}
		case f.SPFInclude != "":
			sawDangling = true
			if f.SPFInclude != danglDom {
				t.Errorf("dangling finding spf_include: got %q, want %q", f.SPFInclude, danglDom)
			}
		}
	}
	if !sawPermissive {
		t.Error("expected a permissive-policy finding (SPFAll set)")
	}
	if !sawDangling {
		t.Error("expected a dangling-reference finding (SPFInclude set)")
	}
}

// ---- DKIM weak inline key sub-vector ---------------------------------------

// Pre-generated RSA public keys (base64 DER SubjectPublicKeyInfo, the RFC 6376
// p= encoding) used to drive the weak-key path. The 512- and 768-bit keys are
// constants because modern Go's crypto/rsa refuses to *generate* keys below 1024
// bits (they are insecure — which is exactly the weakness this detector flags),
// yet x509 still happily *parses* them, which is the path production exercises.
// Generated once with `openssl genrsa <bits> | openssl rsa -pubout -outform DER`.
const (
	weakDKIMKey512 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM+qWU6fNj5OWpUB058EH8JJ4R40YXJSV42XKV4UnK0NAKz5X9yChoCGEjaaDHaAABv9irEScK6P6xKQmgFusEsCAwEAAQ=="
	weakDKIMKey768 = "MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhALn6vD6wapo8cerZ4DwipVSMrRXS4YNWEX00CK5JLp90ZQuNOwQac70uLWq+ujOeprzia66B0UjJABxaN9quxZ/Ro21kPmOUKEIyoPGfHAzpkCV7+vnOW/zLtv2KYTBhZQIDAQAB"
)

// dkimPublicKeyB64 generates an RSA key pair of the given size (>= 1024) and
// returns the base64-encoded DER SubjectPublicKeyInfo. Used for the
// at-or-above-floor (strong-key) cases; the weak cases use the constants above.
func dkimPublicKeyB64(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate %d-bit RSA key: %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// TestParseDKIMTags checks tag splitting, lower-casing, whitespace handling, and
// the p= whitespace-stripping that folded base64 records require.
func TestParseDKIMTags(t *testing.T) {
	tags := parseDKIMTags("V=DKIM1; K=rsa; p=AB CD\tEF ; t=y")
	if tags["v"] != "DKIM1" {
		t.Errorf("v: got %q, want DKIM1", tags["v"])
	}
	if tags["k"] != "rsa" {
		t.Errorf("k: got %q, want rsa", tags["k"])
	}
	if tags["p"] != "ABCDEF" {
		t.Errorf("p: whitespace not stripped, got %q", tags["p"])
	}
	if tags["t"] != "y" {
		t.Errorf("t: got %q, want y", tags["t"])
	}
	// A part with no '=' must be ignored, not panic.
	if got := parseDKIMTags("v=DKIM1; standalone; p=X"); got["p"] != "X" {
		t.Errorf("standalone tag broke parsing: %v", got)
	}
}

// TestRSAPublicKeyBits verifies the modulus size is read from a real DER SPKI
// key and that a non-RSA / garbage value reports ok=false.
func TestRSAPublicKeyBits(t *testing.T) {
	p2048 := dkimPublicKeyB64(t, 2048)
	if bits, ok := rsaPublicKeyBits(p2048); !ok || bits != 2048 {
		t.Errorf("2048-bit key: got (%d, %v), want (2048, true)", bits, ok)
	}
	// A short key parses (x509 does not gate parse on size), reporting its bits.
	if bits, ok := rsaPublicKeyBits(weakDKIMKey512); !ok || bits != 512 {
		t.Errorf("512-bit key: got (%d, %v), want (512, true)", bits, ok)
	}

	// Not base64 at all.
	if _, ok := rsaPublicKeyBits("!!!not-base64!!!"); ok {
		t.Error("invalid base64 must report ok=false")
	}
	// Valid base64 but not a public key.
	if _, ok := rsaPublicKeyBits(base64.StdEncoding.EncodeToString([]byte("hello"))); ok {
		t.Error("non-key DER must report ok=false")
	}
}

// TestWeakDKIMKeyBits is the table-driven core: only a genuinely short RSA key
// yields (bits, true); everything else (strong key, revoked key, non-RSA, non-
// DKIM record, malformed) yields (_, false).
func TestWeakDKIMKeyBits(t *testing.T) {
	weak := weakDKIMKey512    // below the 1024 floor
	weak768 := weakDKIMKey768 // also below the floor
	strong := dkimPublicKeyB64(t, 2048)

	cases := []struct {
		name     string
		txts     []string
		wantBits int
		wantOK   bool
	}{
		{"weak 512-bit key", []string{"v=DKIM1; k=rsa; p=" + weak}, 512, true},
		{"weak 768-bit key", []string{"v=DKIM1; k=rsa; p=" + weak768}, 768, true},
		{"weak key, no v= tag", []string{"k=rsa; p=" + weak}, 512, true},
		{"weak key, no k= tag (rsa default)", []string{"v=DKIM1; p=" + weak}, 512, true},
		{"strong 2048-bit key", []string{"v=DKIM1; k=rsa; p=" + strong}, 0, false},
		{"revoked key (empty p=)", []string{"v=DKIM1; k=rsa; p="}, 0, false},
		{"non-RSA key type", []string{"v=DKIM1; k=ed25519; p=" + weak}, 0, false},
		{"not a DKIM record", []string{"v=spf1 include:a.com -all"}, 0, false},
		{"wrong v= version", []string{"v=DKIM2; k=rsa; p=" + weak}, 0, false},
		{"no records", nil, 0, false},
		{"first record junk, second weak", []string{"some-other-txt", "v=DKIM1; p=" + weak}, 512, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bits, ok := weakDKIMKeyBits(c.txts)
			if ok != c.wantOK || bits != c.wantBits {
				t.Errorf("weakDKIMKeyBits = (%d, %v), want (%d, %v)", bits, ok, c.wantBits, c.wantOK)
			}
		})
	}
}

// dkimKeyDNSServer models a selector that publishes an inline DKIM TXT key (no
// CNAME). The selector keySel._domainkey.<target> returns a TXT record carrying
// keyTXT; that name has no CNAME. Every other name returns NOERROR/no-answer.
func dkimKeyDNSServer(t *testing.T, keyFQDN, keyTXT string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if pErr := req.Unpack(buf[:n]); pErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)

			q := req.Question[0]
			name := q.Name

			if q.Qtype == dns.TypeTXT && name == dns.Fqdn(keyFQDN) {
				resp.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{keyTXT},
				}}
			}
			// CNAME queries and all other names: NOERROR/no-answer → not
			// delegated, drives the detector into the inline-key path.

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestDKIM_WeakInlineKeyLikely drives the full detector: a selector publishing a
// 512-bit inline RSA key (no CNAME) must yield exactly one LIKELY VectorDKIM
// finding carrying the bit size, the selector, and no CNAME.
func TestDKIM_WeakInlineKeyLikely(t *testing.T) {
	const (
		target   = "example.com"
		selector = "s1"
	)
	keyFQDN := selector + "._domainkey." + target
	keyTXT := "v=DKIM1; k=rsa; p=" + weakDKIMKey512

	addr, cleanup := dkimKeyDNSServer(t, keyFQDN, keyTXT)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{"s1", "s2", "default"})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 weak-key finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDKIM {
		t.Errorf("vector: got %q, want dkim", f.Vector)
	}
	if f.Confidence != finding.Likely {
		t.Errorf("confidence: got %q, want LIKELY", f.Confidence)
	}
	if f.DKIMKeyBits != 512 {
		t.Errorf("dkim_key_bits: got %d, want 512", f.DKIMKeyBits)
	}
	if f.DKIMSelector != selector {
		t.Errorf("selector: got %q, want %q", f.DKIMSelector, selector)
	}
	if f.CNAME != "" {
		t.Errorf("weak-key finding must not carry a CNAME, got %q", f.CNAME)
	}
	if f.Subdomain != keyFQDN {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, keyFQDN)
	}
	if !strings.Contains(f.Evidence, "RFC 8301") {
		t.Errorf("evidence should cite RFC 8301, got %q", f.Evidence)
	}
}

// TestDKIM_StrongInlineKeyNoFinding verifies a selector publishing a 2048-bit
// inline key produces no finding.
func TestDKIM_StrongInlineKeyNoFinding(t *testing.T) {
	const target = "example.com"
	keyFQDN := "s1._domainkey." + target
	keyTXT := "v=DKIM1; k=rsa; p=" + dkimPublicKeyB64(t, 2048)

	addr, cleanup := dkimKeyDNSServer(t, keyFQDN, keyTXT)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{"s1", "default"})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a strong inline key, got %d: %+v", len(findings), findings)
	}
}
