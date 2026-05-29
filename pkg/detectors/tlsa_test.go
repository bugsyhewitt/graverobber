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

// tlsaDNSServer starts an in-process UDP DNS server for the TLSA detector tests.
// It publishes:
//   - an MX record set for target (the supplied mxHosts),
//   - a TLSA record at _25._tcp.<host> for each host listed in tlsaHosts,
//   - NXDOMAIN (TypeA/TypeCNAME) for each host listed in nxHosts.
//
// Everything else answers NOERROR/no-answer (i.e. "exists / no records"). It
// mirrors caaDNSServer's structure. The returned cleanup closes the socket.
func tlsaDNSServer(t *testing.T, target string, mxHosts, tlsaHosts, nxHosts []string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	tlsaSet := map[string]bool{}
	for _, h := range tlsaHosts {
		tlsaSet[dns.Fqdn(tlsaSMTPPrefix+h)] = true
	}
	nxSet := map[string]bool{}
	for _, h := range nxHosts {
		nxSet[dns.Fqdn(h)] = true
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
			case q.Qtype == dns.TypeMX && name == dns.Fqdn(target):
				for i, mx := range mxHosts {
					resp.Answer = append(resp.Answer, &dns.MX{
						Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
						Preference: uint16(10 + i),
						Mx:         dns.Fqdn(mx),
					})
				}
			case q.Qtype == dns.TypeTLSA && tlsaSet[name]:
				resp.Answer = append(resp.Answer, &dns.TLSA{
					Hdr:          dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
					Usage:        3, // DANE-EE
					Selector:     1, // SPKI
					MatchingType: 1, // SHA-256
					Certificate:  "0000000000000000000000000000000000000000000000000000000000000000",
				})
			case (q.Qtype == dns.TypeA || q.Qtype == dns.TypeCNAME) && nxSet[name]:
				resp.Rcode = dns.RcodeNameError
			default:
				// Everything else NOERROR/no-answer → exists / no records.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestTLSA_DanglingPinPotential drives the full detector: a TLSA pin published
// for an MX host that is NXDOMAIN must yield exactly one Potential finding keyed
// on the target, carrying the DANE owner name in TLSAName and the dangling mail
// host in MXHosts.
func TestTLSA_DanglingPinPotential(t *testing.T) {
	const (
		target = "example.com"
		mxHost = "mx.dead-vendor.invalid"
	)

	addr, cleanup := tlsaDNSServer(t, target,
		[]string{mxHost}, // MX
		[]string{mxHost}, // TLSA pin present at _25._tcp.mxHost
		[]string{mxHost}, // mxHost is NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorTLSA {
		t.Errorf("vector: got %q, want tlsa", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (TLSA is keyed on the target)", f.Subdomain, target)
	}
	if want := tlsaSMTPPrefix + mxHost; f.TLSAName != want {
		t.Errorf("tlsa_name: got %q, want %q", f.TLSAName, want)
	}
	if len(f.MXHosts) != 1 || f.MXHosts[0] != mxHost {
		t.Errorf("mx_hosts: got %v, want [%q]", f.MXHosts, mxHost)
	}
}

// TestTLSA_LiveHostNoFinding verifies that a TLSA pin published for an MX host
// that still resolves — the normal, healthy DANE deployment — produces no
// finding.
func TestTLSA_LiveHostNoFinding(t *testing.T) {
	const (
		target = "example.com"
		mxHost = "mx.example.com"
	)

	addr, cleanup := tlsaDNSServer(t, target,
		[]string{mxHost}, // MX
		[]string{mxHost}, // TLSA pin present
		nil,              // mxHost resolves (not NXDOMAIN)
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a live DANE-pinned host, got %d: %+v", len(findings), findings)
	}
}

// TestTLSA_NoPinNoFinding verifies that a dangling MX host with NO TLSA pin is
// NOT reported by the TLSA vector. (It is the MX detector's concern; the TLSA
// vector only fires when a DANE pin actually exists.)
func TestTLSA_NoPinNoFinding(t *testing.T) {
	const (
		target = "example.com"
		mxHost = "mx.dead-vendor.invalid"
	)

	addr, cleanup := tlsaDNSServer(t, target,
		[]string{mxHost}, // MX
		nil,              // NO TLSA pin published
		[]string{mxHost}, // mxHost is NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no DANE pin exists, got %d: %+v", len(findings), findings)
	}
}

// TestTLSA_NoMXNoFinding verifies that a domain with no MX records produces no
// finding — the vector keys off the mail exchangers, so there is nothing to
// probe.
func TestTLSA_NoMXNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := tlsaDNSServer(t, target, nil, nil, nil)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a domain with no MX records, got %d: %+v", len(findings), findings)
	}
}

// TestTLSA_MultipleMXDedup verifies that two MX records pointing at the SAME
// dangling, pinned host yield exactly one finding (dedup within a target), and
// that a second distinct dangling+pinned host yields its own finding.
func TestTLSA_MultipleMXDedup(t *testing.T) {
	const (
		target = "example.com"
		mxA    = "mx1.dead-vendor.invalid"
		mxB    = "mx2.dead-vendor.invalid"
	)

	addr, cleanup := tlsaDNSServer(t, target,
		[]string{mxA, mxA, mxB}, // mxA listed twice
		[]string{mxA, mxB},      // both pinned
		[]string{mxA, mxB},      // both NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings (one per distinct host), got %d: %+v", len(findings), findings)
	}
	got := map[string]bool{}
	for _, f := range findings {
		if len(f.MXHosts) == 1 {
			got[f.MXHosts[0]] = true
		}
	}
	if !got[mxA] || !got[mxB] {
		t.Errorf("expected findings for both %q and %q, got %v", mxA, mxB, got)
	}
}

// TestTLSA_EvidenceMentionsDANE pins the evidence wording so the human-readable
// signal cannot silently drift below the bar the other vectors set.
func TestTLSA_EvidenceMentionsDANE(t *testing.T) {
	const (
		target = "example.com"
		mxHost = "mx.dead-vendor.invalid"
	)

	addr, cleanup := tlsaDNSServer(t, target,
		[]string{mxHost}, []string{mxHost}, []string{mxHost})
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := TLSA(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "DANE") || !strings.Contains(ev, "NXDOMAIN") {
		t.Errorf("evidence %q should call out the DANE pin and the NXDOMAIN host", ev)
	}
}

// TestTLSAFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestTLSAFinding_VectorConstant(t *testing.T) {
	if finding.VectorTLSA != "tlsa" {
		t.Errorf("VectorTLSA = %q, want \"tlsa\"", finding.VectorTLSA)
	}
}
