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
//   - DNSKEY queries according to keyState:
//   - "present": one DNSKEY record (signed, healthy),
//   - "absent":  NOERROR with no answer (the orphan: zone exists, no key),
//   - "servfail": SERVFAIL (a validating resolver's response to a broken chain).
//
// Every other name/type answers NOERROR/no-answer. The returned cleanup closes
// the socket. It mirrors tlsaDNSServer's structure.
func dnssecDNSServer(t *testing.T, target string, dsKeyTags []uint16, keyState string) (string, func()) {
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
				for _, tag := range dsKeyTags {
					resp.Answer = append(resp.Answer, &dns.DS{
						Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
						KeyTag:     tag,
						Algorithm:  13, // ECDSAP256SHA256
						DigestType: 2,  // SHA-256
						Digest:     "0000000000000000000000000000000000000000000000000000000000000000",
					})
				}
			case q.Qtype == dns.TypeDNSKEY && name == dns.Fqdn(target):
				switch keyState {
				case "present":
					resp.Answer = append(resp.Answer, &dns.DNSKEY{
						Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
						Flags:     257, // KSK
						Protocol:  3,
						Algorithm: 13,
						PublicKey: "AwEAAa==",
					})
				case "servfail":
					resp.Rcode = dns.RcodeServerFailure
				default: // "absent": NOERROR, no answer
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
