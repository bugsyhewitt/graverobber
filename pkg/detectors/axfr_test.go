package detectors

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
	"github.com/miekg/dns"
)

// axfrTestServer wires up a resolver whose NS lookups return a loopback
// nameserver and whose AXFR dials a local TCP server:
//   - a UDP DNS server answers the NS query for `zone` with NS = "127.0.0.1"
//     (a plain hostname, as a real delegation carries);
//   - a TCP AXFR server on a separate ephemeral port streams `records` (when
//     allowAXFR) or REFUSES;
//   - resolver.SetAXFRPortForTest points ZoneTransfer's dial at that TCP port so
//     the test needs no privileged port 53.
//
// It returns the resolver and a cleanup func.
func axfrTestServer(t *testing.T, zone string, records []dns.RR, allowAXFR bool) (*resolver.Resolver, func()) {
	t.Helper()

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	udpPort := strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)

	// TCP AXFR server on its own ephemeral port.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = udp.Close()
		t.Fatalf("listen tcp: %v", err)
	}
	axfrPort := strconv.Itoa(tcpLn.Addr().(*net.TCPAddr).Port)
	restorePort := resolver.SetAXFRPortForTest(axfrPort)

	// UDP server: answer NS queries with the loopback nameserver.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := udp.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeNS {
				resp.Answer = []dns.RR{&dns.NS{
					Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					// Fully qualified (trailing dot) so the record packs; the
					// resolver strips the dot, yielding "127.0.0.1", which
					// ZoneTransfer dials on axfrPort.
					Ns: "127.0.0.1.",
				}}
			}
			packed, _ := resp.Pack()
			_, _ = udp.WriteTo(packed, addr)
		}
	}()

	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:     "ns1." + dns.Fqdn(zone),
		Mbox:   "hostmaster." + dns.Fqdn(zone),
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if !allowAXFR || len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAXFR {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope)
		go func() {
			rrs := []dns.RR{soa}
			rrs = append(rrs, records...)
			rrs = append(rrs, soa)
			ch <- &dns.Envelope{RR: rrs}
			close(ch)
		}()
		_ = tr.Out(w, req, ch)
	})
	srv := &dns.Server{Listener: tcpLn, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()

	r := resolver.New([]string{net.JoinHostPort("127.0.0.1", udpPort)}, 2*time.Second)
	cleanup := func() {
		restorePort()
		_ = srv.Shutdown()
		_ = udp.Close()
	}
	return r, cleanup
}

// TestAXFR_LeakConfirmed verifies a permissive nameserver yields a CONFIRMED
// VectorAXFR finding naming the nameserver and sampling the leaked hosts.
func TestAXFR_LeakConfirmed(t *testing.T) {
	const zone = "leaky.example.com"
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn("admin." + zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.1")},
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn("vpn." + zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.2")},
	}
	r, cleanup := axfrTestServer(t, zone, records, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := AXFR(ctx, zone, r)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorAXFR {
		t.Errorf("vector = %q, want %q", f.Vector, finding.VectorAXFR)
	}
	if f.Confidence != finding.Confirmed {
		t.Errorf("confidence = %q, want CONFIRMED (a successful transfer is proof)", f.Confidence)
	}
	if f.Subdomain != zone {
		t.Errorf("subdomain = %q, want %q", f.Subdomain, zone)
	}
	if f.Service == "" || len(f.Nameservers) != 1 {
		t.Errorf("expected the leaking nameserver in Service and Nameservers, got service=%q ns=%v", f.Service, f.Nameservers)
	}
	if len(f.LeakedHosts) != 2 {
		t.Errorf("expected 2 sampled leaked hosts, got %v", f.LeakedHosts)
	}
	if !strings.Contains(f.Evidence, "AXFR") {
		t.Errorf("evidence should describe the AXFR leak, got %q", f.Evidence)
	}
}

// TestAXFR_RefusedNoFinding verifies a correctly-configured nameserver that
// refuses the transfer produces no finding.
func TestAXFR_RefusedNoFinding(t *testing.T) {
	const zone = "secure.example.com"
	r, cleanup := axfrTestServer(t, zone, nil, false)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := AXFR(ctx, zone, r)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a refused transfer must produce no finding, got %+v", findings)
	}
}

// TestAXFR_NoNameserversNoFinding verifies that a target with no resolvable NS
// records yields no finding and no error (nothing to transfer).
func TestAXFR_NoNameserversNoFinding(t *testing.T) {
	// A resolver pointed at a closed port returns no NS records.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	r := resolver.New([]string{addr}, 200*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	findings, err := AXFR(ctx, "no-ns.example.com", r)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when NS resolution fails, got %+v", findings)
	}
}

// TestAXFRFinding_VectorConstant locks the vector tag so output formatters and
// downstream consumers cannot silently drift.
func TestAXFRFinding_VectorConstant(t *testing.T) {
	if finding.VectorAXFR != "axfr" {
		t.Errorf("VectorAXFR = %q, want \"axfr\"", finding.VectorAXFR)
	}
}
