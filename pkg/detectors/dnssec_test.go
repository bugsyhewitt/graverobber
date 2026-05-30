package detectors

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
	"github.com/miekg/dns"
)

// dnssecDNSServer starts an in-process UDP DNS server for the DNSSEC detector
// tests. For the target name it answers:
//
//   - DS queries with one DS record per key tag in dsKeyTags (empty → no DS),
//     using safe defaults (Algorithm 13 ECDSAP256SHA256, DigestType 2 SHA-256).
//   - DNSKEY queries according to keyState:
//   - "present": one DNSKEY record using safe algorithm 13 (signed, healthy),
//   - "absent":  NOERROR with no answer (the orphan: zone exists, no key),
//   - "servfail": SERVFAIL (a validating resolver's response to a broken chain).
//
// Use dnssecDNSServerEx to customise the DS / DNSKEY algorithms (the weak-
// algorithm sub-case relies on it). Every other name/type answers
// NOERROR/no-answer. The returned cleanup closes the socket. It mirrors
// tlsaDNSServer's structure.
func dnssecDNSServer(t *testing.T, target string, dsKeyTags []uint16, keyState string) (string, func()) {
	t.Helper()
	ds := make([]testDS, 0, len(dsKeyTags))
	for _, tag := range dsKeyTags {
		ds = append(ds, testDS{KeyTag: tag, Algorithm: 13, DigestType: 2})
	}
	var keys []testDNSKEY
	if keyState == "present" {
		keys = []testDNSKEY{{Algorithm: 13}}
	}
	return dnssecDNSServerEx(t, target, ds, keys, keyState)
}

// testDS / testDNSKEY are the shape the extended helper accepts so a test can
// dictate the algorithm and digest-type bytes the weak-algorithm detector
// inspects.
type testDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
}

type testDNSKEY struct {
	Algorithm uint8
}

// dnssecDNSServerEx is the algorithm-aware variant of dnssecDNSServer. keyState
// is interpreted as before: "absent" / "servfail" / anything else = present
// (the keys slice is what is served). Pass an explicit empty keys slice with
// keyState != "absent"/"servfail" for the "zone exists, no key" case if needed.
func dnssecDNSServerEx(t *testing.T, target string, dsRecs []testDS, keys []testDNSKEY, keyState string) (string, func()) {
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
			case q.Qtype == dns.TypeDS && name == dns.Fqdn(target):
				for _, ds := range dsRecs {
					resp.Answer = append(resp.Answer, &dns.DS{
						Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
						KeyTag:     ds.KeyTag,
						Algorithm:  ds.Algorithm,
						DigestType: ds.DigestType,
						Digest:     "0000000000000000000000000000000000000000000000000000000000000000",
					})
				}
			case q.Qtype == dns.TypeDNSKEY && name == dns.Fqdn(target):
				switch keyState {
				case "servfail":
					resp.Rcode = dns.RcodeServerFailure
				case "absent":
					// NOERROR, no answer.
				default:
					for _, k := range keys {
						resp.Answer = append(resp.Answer, &dns.DNSKEY{
							Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
							Flags:     257, // KSK
							Protocol:  3,
							Algorithm: k.Algorithm,
							PublicKey: "AwEAAa==",
						})
					}
				}
			default:
				// Everything else NOERROR/no-answer.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestDNSSEC_OrphanedDSPotential drives the full detector: a DS at the parent
// with no DNSKEY at the child must yield exactly one Potential finding keyed on
// the target, carrying the orphaned key tags.
func TestDNSSEC_OrphanedDSPotential(t *testing.T) {
	const target = "broken-dnssec.example.com"

	addr, cleanup := dnssecDNSServer(t, target, []uint16{12345}, "absent")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDNSSEC {
		t.Errorf("vector: got %q, want dnssec", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (DNSSEC orphan is keyed on the target)", f.Subdomain, target)
	}
	if len(f.DSKeyTags) != 1 || f.DSKeyTags[0] != 12345 {
		t.Errorf("ds_key_tags: got %v, want [12345]", f.DSKeyTags)
	}
}

// TestDNSSEC_ServfailIsOrphan verifies that a SERVFAIL on the DNSKEY query — the
// response a validating resolver gives for an already-broken chain — is treated
// as confirmation of the orphan, not as an indeterminate error.
func TestDNSSEC_ServfailIsOrphan(t *testing.T) {
	const target = "servfail-dnssec.example.com"

	addr, cleanup := dnssecDNSServer(t, target, []uint16{54321}, "servfail")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding on SERVFAIL DNSKEY, got %d: %+v", len(findings), findings)
	}
	if findings[0].DSKeyTags[0] != 54321 {
		t.Errorf("ds_key_tags: got %v, want [54321]", findings[0].DSKeyTags)
	}
}

// TestDNSSEC_SignedZoneNoFinding verifies that a DS at the parent WITH a matching
// DNSKEY at the child — the normal, healthy signed delegation — produces no
// finding.
func TestDNSSEC_SignedZoneNoFinding(t *testing.T) {
	const target = "secure-dnssec.example.com"

	addr, cleanup := dnssecDNSServer(t, target, []uint16{12345}, "present")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a healthy signed zone, got %d: %+v", len(findings), findings)
	}
}

// TestDNSSEC_NoDSNoFinding verifies that an unsigned (insecure) delegation — no
// DS at the parent, the common default — is never flagged, regardless of whether
// the child happens to publish a DNSKEY.
func TestDNSSEC_NoDSNoFinding(t *testing.T) {
	const target = "unsigned.example.com"

	addr, cleanup := dnssecDNSServer(t, target, nil, "absent")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for an unsigned delegation (no DS), got %d: %+v", len(findings), findings)
	}
}

// TestDNSSEC_MultipleDSDedupSorted verifies that several DS records (a common
// during-rollover state) are reported as one finding with deduplicated,
// ascending-sorted key tags.
func TestDNSSEC_MultipleDSDedupSorted(t *testing.T) {
	const target = "multi-ds.example.com"

	// Out of order and with a duplicate to prove dedup + sort.
	addr, cleanup := dnssecDNSServer(t, target, []uint16{40000, 10000, 40000, 25000}, "absent")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	want := []uint16{10000, 25000, 40000}
	got := findings[0].DSKeyTags
	if len(got) != len(want) {
		t.Fatalf("ds_key_tags: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ds_key_tags[%d]: got %d, want %d (must be deduped & ascending)", i, got[i], want[i])
		}
	}
}

// TestDNSSEC_EvidenceExplainsBreak pins the evidence wording so the
// human-readable signal cannot silently drift below the bar the other vectors
// set: it must name the DS, the missing DNSKEY, and the SERVFAIL outage.
func TestDNSSEC_EvidenceExplainsBreak(t *testing.T) {
	const target = "broken-dnssec.example.com"

	addr, cleanup := dnssecDNSServer(t, target, []uint16{12345}, "absent")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	for _, want := range []string{"DS", "DNSKEY", "SERVFAIL"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence %q should mention %q", ev, want)
		}
	}
}

// TestDNSSEC_EmptyTargetNoFinding verifies the detector tolerates an empty/blank
// target without a DNS call or a panic.
func TestDNSSEC_EmptyTargetNoFinding(t *testing.T) {
	r := resolver.New([]string{"127.0.0.1:1"}, 200*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, "   ", r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a blank target, got %d", len(findings))
	}
}

// TestDNSSECFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestDNSSECFinding_VectorConstant(t *testing.T) {
	if finding.VectorDNSSEC != "dnssec" {
		t.Errorf("VectorDNSSEC = %q, want \"dnssec\"", finding.VectorDNSSEC)
	}
}

// TestDedupSortedKeyTags unit-tests the key-tag normaliser directly.
func TestDedupSortedKeyTags(t *testing.T) {
	got := dedupSortedKeyTags([]uint16{5, 1, 5, 3, 1})
	want := []uint16{1, 3, 5}
	if len(got) != len(want) {
		t.Fatalf("dedupSortedKeyTags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupSortedKeyTags[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestWeakDNSKEYAlgorithm pins the RFC 8624 forbidden / deprecated algorithm
// names and confirms modern algorithms are not flagged. This table is the
// contract — any drift in the mapping is a vector regression.
func TestWeakDNSKEYAlgorithm(t *testing.T) {
	cases := []struct {
		alg      uint8
		wantName string
		wantWeak bool
	}{
		{1, "RSAMD5", true},
		{3, "DSA/SHA-1", true},
		{5, "RSASHA1", true},
		{6, "DSA-NSEC3-SHA1", true},
		{7, "RSASHA1-NSEC3-SHA1", true},
		{12, "ECC-GOST", true},
		// modern, safe algorithms must not be flagged
		{8, "", false},  // RSASHA256
		{10, "", false}, // RSASHA512
		{13, "", false}, // ECDSAP256SHA256
		{14, "", false}, // ECDSAP384SHA384
		{15, "", false}, // ED25519
		{16, "", false}, // ED448
		// reserved / unknown — never weak by default (the registry can grow)
		{0, "", false},
		{255, "", false},
	}
	for _, tc := range cases {
		name, weak := weakDNSKEYAlgorithm(tc.alg)
		if weak != tc.wantWeak || name != tc.wantName {
			t.Errorf("weakDNSKEYAlgorithm(%d) = (%q, %v), want (%q, %v)", tc.alg, name, weak, tc.wantName, tc.wantWeak)
		}
	}
}

// TestWeakDSDigest pins the DS digest-type weakness mapping.
func TestWeakDSDigest(t *testing.T) {
	cases := []struct {
		dt       uint8
		wantName string
		wantWeak bool
	}{
		{0, "DS-RESERVED", true},
		{1, "DS-SHA1", true},
		{2, "", false}, // SHA-256, the mandatory current
		{4, "", false}, // SHA-384
		{255, "", false},
	}
	for _, tc := range cases {
		name, weak := weakDSDigest(tc.dt)
		if weak != tc.wantWeak || name != tc.wantName {
			t.Errorf("weakDSDigest(%d) = (%q, %v), want (%q, %v)", tc.dt, name, weak, tc.wantName, tc.wantWeak)
		}
	}
}

// TestDNSSEC_WeakChildKeyAlgorithmPotential drives the full detector: a healthy
// signed delegation (DS present + DNSKEY present) where the child key uses
// RSASHA1 (algorithm 5, RFC 8624 NOT RECOMMENDED) must yield exactly one
// Potential finding listing the weak algorithm, with no false orphan diagnosis.
func TestDNSSEC_WeakChildKeyAlgorithmPotential(t *testing.T) {
	const target = "weak-dnssec.example.com"

	addr, cleanup := dnssecDNSServerEx(t, target,
		[]testDS{{KeyTag: 12345, Algorithm: 5, DigestType: 2}}, // DS algorithm matches the key
		[]testDNSKEY{{Algorithm: 5}},                           // RSASHA1
		"present")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 weak-algorithm finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDNSSEC {
		t.Errorf("vector: got %q, want dnssec", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, target)
	}
	if len(f.DNSSECWeakAlgs) != 1 || f.DNSSECWeakAlgs[0] != "RSASHA1" {
		t.Errorf("dnssec_weak_algs: got %v, want [RSASHA1]", f.DNSSECWeakAlgs)
	}
	// The DS key tags ride along so the operator can match the registrar record.
	if len(f.DSKeyTags) != 1 || f.DSKeyTags[0] != 12345 {
		t.Errorf("ds_key_tags: got %v, want [12345]", f.DSKeyTags)
	}
	// Importantly, the weak-algorithm sub-case must NOT pretend to be an orphan.
	if !strings.Contains(f.Evidence, "weak") || !strings.Contains(f.Evidence, "RFC 8624") {
		t.Errorf("evidence %q must name the weakness and the RFC", f.Evidence)
	}
}

// TestDNSSEC_WeakDSDigestPotential verifies a SHA-1 DS digest (digest type 1,
// RFC 8624 NOT RECOMMENDED) is flagged even when the key algorithm itself is
// modern.
func TestDNSSEC_WeakDSDigestPotential(t *testing.T) {
	const target = "sha1-ds.example.com"

	addr, cleanup := dnssecDNSServerEx(t, target,
		[]testDS{{KeyTag: 50000, Algorithm: 13, DigestType: 1}}, // ECDSA key, SHA-1 digest
		[]testDNSKEY{{Algorithm: 13}},
		"present")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding for SHA-1 DS digest, got %d: %+v", len(findings), findings)
	}
	if len(findings[0].DNSSECWeakAlgs) != 1 || findings[0].DNSSECWeakAlgs[0] != "DS-SHA1" {
		t.Errorf("dnssec_weak_algs: got %v, want [DS-SHA1]", findings[0].DNSSECWeakAlgs)
	}
}

// TestDNSSEC_MultipleWeaknessesDedupSorted verifies that several weak signals
// (a weak key algorithm appearing twice + a weak DS digest type) are reduced to
// one finding whose DNSSECWeakAlgs slice is deduplicated and ascending-sorted —
// the same stability property the orphan sub-case provides for DSKeyTags.
func TestDNSSEC_MultipleWeaknessesDedupSorted(t *testing.T) {
	const target = "multi-weak.example.com"

	addr, cleanup := dnssecDNSServerEx(t, target,
		// Two DS records: both name algorithm 5 (RSASHA1) — must dedupe.
		// The second uses digest type 1 (SHA-1) — distinct weakness.
		[]testDS{
			{KeyTag: 10000, Algorithm: 5, DigestType: 2},
			{KeyTag: 20000, Algorithm: 5, DigestType: 1},
		},
		// Two child keys: RSASHA1 (5) again + DSA/SHA-1 (3). Three distinct
		// weakness names total: RSASHA1, DSA/SHA-1, DS-SHA1.
		[]testDNSKEY{{Algorithm: 5}, {Algorithm: 3}},
		"present")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding consolidating the weaknesses, got %d", len(findings))
	}
	got := findings[0].DNSSECWeakAlgs
	want := []string{"DS-SHA1", "DSA/SHA-1", "RSASHA1"} // ascending
	if len(got) != len(want) {
		t.Fatalf("dnssec_weak_algs: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dnssec_weak_algs[%d]: got %q, want %q (must dedupe & sort)", i, got[i], want[i])
		}
	}
}

// TestDNSSEC_ModernAlgorithmsNoFinding is the regression guard: a healthy
// signed delegation using only modern algorithms (ECDSA P-256, DS SHA-256) must
// produce no finding. This is the common, secure case — flagging it would be a
// false-positive flood across the internet.
func TestDNSSEC_ModernAlgorithmsNoFinding(t *testing.T) {
	const target = "modern-dnssec.example.com"

	addr, cleanup := dnssecDNSServerEx(t, target,
		[]testDS{{KeyTag: 12345, Algorithm: 13, DigestType: 2}}, // ECDSA + SHA-256
		[]testDNSKEY{{Algorithm: 13}},
		"present")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a modern signed delegation, got %d: %+v", len(findings), findings)
	}
}

// TestDNSSEC_OrphanStillFiresWhenWeakAlgorithmAlsoApplicable verifies the
// orphan sub-case keeps its priority: when there is no DNSKEY at all, the
// detector must emit the orphan finding (DSKeyTags set, DNSSECWeakAlgs empty),
// not silently re-route into the weak-algorithm branch. The two sub-cases are
// distinguished by which of the two fields is set.
func TestDNSSEC_OrphanFindingHasNoWeakAlgs(t *testing.T) {
	const target = "broken-dnssec.example.com"

	addr, cleanup := dnssecDNSServerEx(t, target,
		[]testDS{{KeyTag: 12345, Algorithm: 5, DigestType: 1}}, // both weak, but no DNSKEY
		nil,
		"absent")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DNSSEC(ctx, target, r)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the orphan finding, got %d", len(findings))
	}
	if len(findings[0].DNSSECWeakAlgs) != 0 {
		t.Errorf("orphan sub-case must not populate DNSSECWeakAlgs, got %v", findings[0].DNSSECWeakAlgs)
	}
	if len(findings[0].DSKeyTags) == 0 {
		t.Errorf("orphan sub-case must populate DSKeyTags")
	}
}
