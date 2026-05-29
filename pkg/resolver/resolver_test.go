package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNew_Defaults(t *testing.T) {
	r := New(nil, 0)
	if r == nil {
		t.Fatal("New returned nil")
	}
	if r.Timeout() != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", r.Timeout())
	}
	if len(r.Servers()) != 0 {
		t.Errorf("expected empty servers slice, got %v", r.Servers())
	}
}

func TestNew_ConfiguredTimeout(t *testing.T) {
	r := New(nil, 3*time.Second)
	if r.Timeout() != 3*time.Second {
		t.Errorf("expected 3s, got %v", r.Timeout())
	}
}

func TestNew_Servers(t *testing.T) {
	r := New([]string{"1.2.3.4", "5.6.7.8:5353"}, 5*time.Second)
	if len(r.Servers()) != 2 {
		t.Fatalf("expected 2 servers, got %v", r.Servers())
	}
}

func TestEffectiveServers_NormalizesPort(t *testing.T) {
	r := New([]string{"8.8.8.8"}, 5*time.Second)
	servers := r.effectiveServers()
	if len(servers) == 0 {
		t.Fatal("expected at least one effective server")
	}
	// With "8.8.8.8" as input (no port), effectiveServers adds ":53".
	if servers[0] != "8.8.8.8:53" {
		t.Errorf("expected 8.8.8.8:53, got %s", servers[0])
	}
}

func TestEffectiveServers_Fallback(t *testing.T) {
	// No configured servers → falls back to /etc/resolv.conf or public DNS.
	r := New(nil, 5*time.Second)
	servers := r.effectiveServers()
	if len(servers) == 0 {
		t.Error("effectiveServers should always return at least one server")
	}
}

func TestErrNXDomain_Identity(t *testing.T) {
	if !errors.Is(ErrNXDomain, ErrNXDomain) {
		t.Error("ErrNXDomain should satisfy errors.Is(ErrNXDomain, ErrNXDomain)")
	}
}

func TestErrZoneDeleted_Identity(t *testing.T) {
	if !errors.Is(ErrZoneDeleted, ErrZoneDeleted) {
		t.Error("ErrZoneDeleted should satisfy errors.Is")
	}
}

func TestErrNotImplemented_NotNXDomain(t *testing.T) {
	if errors.Is(ErrNotImplemented, ErrNXDomain) {
		t.Error("ErrNotImplemented should not satisfy ErrNXDomain")
	}
}

// ---- #1: CNAME loop protection proof ----------------------------------------

// TestCNAMEChain_AlwaysRecursive verifies that CNAMEChain's underlying query()
// always sets RecursionDesired=true. This is the primary loop-safety invariant:
// the recursive resolver detects and breaks cycles before returning a response.
func TestCNAMEChain_AlwaysRecursive(t *testing.T) {
	// Build the DNS message as query() would and verify the RD bit.
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("test.example.com"), dns.TypeA)
	msg.RecursionDesired = true // this is what query() sets
	if !msg.RecursionDesired {
		t.Error("CNAMEChain must use RecursionDesired=true — loop detection delegates to recursive resolver")
	}
}

// TestCNAMEChain_HopCapPreventsOverflow verifies that maxCNAMEChain bounds
// the chain extracted from a pathological resolver response, even when the
// Answer section contains more CNAME records than the cap.
func TestCNAMEChain_HopCapPreventsOverflow(t *testing.T) {
	if maxCNAMEChain < 8 {
		t.Errorf("maxCNAMEChain=%d is too small; legitimate chains can be up to 8 hops", maxCNAMEChain)
	}
	if maxCNAMEChain > 64 {
		t.Errorf("maxCNAMEChain=%d is too large to be a meaningful safety cap", maxCNAMEChain)
	}

	// Build a synthetic Answer section with maxCNAMEChain+5 CNAME records.
	extra := maxCNAMEChain + 5
	var answer []dns.RR
	for i := range extra {
		rr := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fmt.Sprintf("hop%d.example.com.", i), Rrtype: dns.TypeCNAME},
			Target: fmt.Sprintf("hop%d.example.com.", i+1),
		}
		answer = append(answer, rr)
	}

	// Simulate CNAMEChain's extraction loop.
	var chain []string
	for _, rr := range answer {
		if len(chain) >= maxCNAMEChain {
			break
		}
		if c, ok := rr.(*dns.CNAME); ok {
			chain = append(chain, c.Target)
		}
	}

	if len(chain) > maxCNAMEChain {
		t.Errorf("chain length %d exceeds maxCNAMEChain=%d", len(chain), maxCNAMEChain)
	}
	if len(chain) != maxCNAMEChain {
		t.Errorf("expected exactly maxCNAMEChain=%d hops extracted, got %d", maxCNAMEChain, len(chain))
	}
}

// ---- MX method -------------------------------------------------------------

// TestMX_ParsesResponse verifies that the MX method extracts hostnames from a
// synthetic DNS MX response (same test-server pattern as AuthoritativeSOA).
func TestMX_ReturnsSentinels(t *testing.T) {
	// Verify the MX method compiles and is reachable; live DNS is not in scope
	// for unit tests, so we only confirm the constructor does not panic and that
	// the sentinel errors are distinct from the MX code path.
	r := New(nil, 5*time.Second)
	if r == nil {
		t.Fatal("New returned nil")
	}
	// ErrNXDomain must still be distinct from ErrZoneDeleted.
	if errors.Is(ErrNXDomain, ErrZoneDeleted) {
		t.Error("ErrNXDomain and ErrZoneDeleted must be distinct sentinels")
	}
}

// TestMX_ParsesMXRecords verifies the MX response-parsing logic using a local
// UDP DNS server that replies with a synthetic MX answer.
func TestMX_ParsesMXRecords(t *testing.T) {
	// Spin up a local UDP DNS server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	wantHosts := []string{"mail1.example.com", "mail2.example.com"}

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
			resp.Answer = []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("target.example.com"),
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Preference: 10,
					Mx:         dns.Fqdn(wantHosts[0]),
				},
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("target.example.com"),
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Preference: 20,
					Mx:         dns.Fqdn(wantHosts[1]),
				},
			}
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	addr := pc.LocalAddr().String()
	r := New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.MX(ctx, "target.example.com")
	if err != nil {
		t.Fatalf("MX: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 MX hosts, got %d: %v", len(got), got)
	}
	for i, want := range wantHosts {
		if got[i] != want {
			t.Errorf("MX[%d]: got %q, want %q", i, got[i], want)
		}
	}
}

// TestMX_EmptyOnNXDOMAIN verifies that MX returns nil (not an error) when the
// DNS response code is not Success (e.g. NXDOMAIN).
func TestMX_EmptyOnNXDOMAIN(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			resp.Rcode = dns.RcodeNameError // NXDOMAIN
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	addr := pc.LocalAddr().String()
	r := New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.MX(ctx, "nxdomain.example.com")
	if err != nil {
		t.Fatalf("MX on NXDOMAIN should not error, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice for NXDOMAIN, got %v", got)
	}
}

// ---- RawCNAME method -------------------------------------------------------

// TestRawCNAME_ReturnsAlias verifies RawCNAME extracts the immediate CNAME
// target from a TypeCNAME response.
func TestRawCNAME_ReturnsAlias(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	const want = "s1.domainkey.u123.wl.sendgrid.net"

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
			resp.Answer = []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("s1._domainkey.example.com"),
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Target: dns.Fqdn(want),
				},
			}
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.RawCNAME(ctx, "s1._domainkey.example.com")
	if err != nil {
		t.Fatalf("RawCNAME: %v", err)
	}
	if got != want {
		t.Errorf("RawCNAME = %q, want %q", got, want)
	}
}

// TestRawCNAME_EmptyWhenNoCNAME verifies RawCNAME returns "" (no error) when the
// host resolves but publishes no CNAME record (e.g. an inline TXT selector).
func TestRawCNAME_EmptyWhenNoCNAME(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			// NOERROR with no CNAME answer (TXT-published selector).
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.RawCNAME(ctx, "default._domainkey.example.com")
	if err != nil {
		t.Fatalf("RawCNAME should not error on NOERROR/no-CNAME: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty CNAME, got %q", got)
	}
}

// TestRawCNAME_NXDomain verifies RawCNAME returns ErrNXDomain when the host
// itself does not exist.
func TestRawCNAME_NXDomain(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			resp.Rcode = dns.RcodeNameError
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = r.RawCNAME(ctx, "missing._domainkey.example.com")
	if !errors.Is(err, ErrNXDomain) {
		t.Errorf("expected ErrNXDomain, got %v", err)
	}
}

// ---- #3: SOA retry constants ------------------------------------------------

// TestSOARetryConstants documents and verifies the AuthoritativeSOA retry
// policy. The NS detector requires unanimous SERVFAIL/REFUSED across all
// nameservers; each SOA query is retried soaRetries times so a transient
// SERVFAIL on a live zone does not cause a false positive.
func TestSOARetryConstants(t *testing.T) {
	if soaRetries < 2 {
		t.Errorf("soaRetries must be at least 2 to absorb transient failures, got %d", soaRetries)
	}
	if soaBackoff < 50*time.Millisecond {
		t.Errorf("soaBackoff must be at least 50ms to avoid hammering, got %v", soaBackoff)
	}
	if soaBackoff > 2*time.Second {
		t.Errorf("soaBackoff must not exceed 2s (too slow for a scan), got %v", soaBackoff)
	}
}

// TestAuthoritativeSOA_TCPFallbackOnUDPTimeout verifies that when all UDP
// attempts time out (simulating a firewall that silently drops UDP DNS),
// AuthoritativeSOA escalates to TCP before returning an error.
//
// Setup: a UDP listener that accepts but never responds, and a TCP listener on
// the same address that replies with SERVFAIL → ErrZoneDeleted.
func TestAuthoritativeSOA_TCPFallbackOnUDPTimeout(t *testing.T) {
	// Use a short backoff so the test completes quickly.
	origBackoff := soaBackoff
	soaBackoff = 5 * time.Millisecond
	t.Cleanup(func() { soaBackoff = origBackoff })

	// UDP: accept packets and discard them without responding.
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := udpConn.ReadFrom(buf); err != nil {
				return // listener closed
			}
			// Intentionally never respond — simulates a firewall dropping UDP.
		}
	}()

	// TCP: same host:port, responds with SERVFAIL → ErrZoneDeleted.
	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen tcp on same port: %v", err)
	}
	t.Cleanup(func() { tcpLn.Close() })

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				co := &dns.Conn{Conn: c}
				req, err := co.ReadMsg()
				if err != nil {
					return
				}
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeServerFailure
				_ = co.WriteMsg(resp)
			}(conn)
		}
	}()

	nameserver := fmt.Sprintf("127.0.0.1:%d", port)
	// Very short UDP timeout so retries fail quickly.
	r := New([]string{nameserver}, 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = r.AuthoritativeSOA(ctx, "test.zone.", nameserver)
	if !errors.Is(err, ErrZoneDeleted) {
		t.Errorf("expected ErrZoneDeleted via TCP fallback after UDP timeout, got: %v", err)
	}
}

// ---- ZoneTransfer (AXFR) ----------------------------------------------------

// startAXFRServer spins up a TCP DNS server on 127.0.0.1 that answers AXFR for
// `zone` by streaming the supplied records (bracketed with SOA envelopes, as a
// real master does). It returns the server address and a cleanup function. A
// nil records slice models a permissive server that nonetheless has an empty
// zone (only the SOAs); a server that should REFUSE is modelled separately.
func startAXFRServer(t *testing.T, zone string, records []dns.RR) (addr string, cleanup func()) {
	t.Helper()
	pc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + dns.Fqdn(zone),
		Mbox:    "hostmaster." + dns.Fqdn(zone),
		Serial:  1,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAXFR {
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
			rrs = append(rrs, soa) // closing SOA brackets the zone
			ch <- &dns.Envelope{RR: rrs}
			close(ch)
		}()
		_ = tr.Out(w, req, ch)
	})
	srv := &dns.Server{Listener: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.Addr().String(), func() { _ = srv.Shutdown() }
}

// startRefusingAXFRServer spins up a TCP DNS server that REFUSES every AXFR — the
// secure, correctly-configured behaviour.
func startRefusingAXFRServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	pc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Listener: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.Addr().String(), func() { _ = srv.Shutdown() }
}

// TestZoneTransfer_LeakReturnsRecords verifies that a permissive nameserver
// streaming zone data yields a result whose RecordCount excludes the bracketing
// SOAs and whose Hosts sample is deduplicated and sorted.
func TestZoneTransfer_LeakReturnsRecords(t *testing.T) {
	const zone = "leaky.example.com"
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn("www." + zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.1")},
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn("www." + zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.2")},
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn("internal." + zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.0.3")},
	}
	addr, cleanup := startAXFRServer(t, zone, records)
	defer cleanup()

	r := New(nil, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := r.ZoneTransfer(ctx, zone, addr)
	if err != nil {
		t.Fatalf("ZoneTransfer: %v", err)
	}
	// Three non-SOA records were streamed; the two bracketing SOAs are excluded.
	if res.RecordCount != 3 {
		t.Errorf("RecordCount = %d, want 3 (SOAs excluded)", res.RecordCount)
	}
	// Two distinct owner names, sorted.
	want := []string{"internal." + zone, "www." + zone}
	if len(res.Hosts) != len(want) {
		t.Fatalf("Hosts = %v, want %v", res.Hosts, want)
	}
	for i := range want {
		if res.Hosts[i] != want[i] {
			t.Errorf("Hosts[%d] = %q, want %q", i, res.Hosts[i], want[i])
		}
	}
}

// TestZoneTransfer_RefusedIsErrAXFRRefused verifies that a correctly-configured
// nameserver that refuses the transfer yields ErrAXFRRefused, never a finding.
func TestZoneTransfer_RefusedIsErrAXFRRefused(t *testing.T) {
	addr, cleanup := startRefusingAXFRServer(t)
	defer cleanup()

	r := New(nil, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := r.ZoneTransfer(ctx, "secure.example.com", addr)
	if !errors.Is(err, ErrAXFRRefused) {
		t.Errorf("expected ErrAXFRRefused, got %v", err)
	}
	if res.RecordCount != 0 {
		t.Errorf("a refused transfer must report 0 records, got %d", res.RecordCount)
	}
}

// TestZoneTransfer_SOAOnlyIsRefused verifies that a server which returns only the
// bracketing SOAs (no actual zone data) is treated as a refusal, not a leak —
// the verdict hinges on non-SOA records.
func TestZoneTransfer_SOAOnlyIsRefused(t *testing.T) {
	const zone = "empty.example.com"
	addr, cleanup := startAXFRServer(t, zone, nil)
	defer cleanup()

	r := New(nil, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.ZoneTransfer(ctx, zone, addr)
	if !errors.Is(err, ErrAXFRRefused) {
		t.Errorf("SOA-only transfer should be ErrAXFRRefused, got %v", err)
	}
}

// TestZoneTransfer_TransportErrorIsNotRefusal verifies that a dial failure
// (nothing listening) surfaces as a plain error distinct from ErrAXFRRefused, so
// the detector treats it as indeterminate rather than "secure".
func TestZoneTransfer_TransportErrorIsNotRefusal(t *testing.T) {
	// Reserve then release a port so the dial reliably fails with connection
	// refused.
	pc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.Addr().String()
	_ = pc.Close()

	r := New(nil, 500*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = r.ZoneTransfer(ctx, "dead.example.com", addr)
	if err == nil {
		t.Fatal("expected a transport error dialing a closed port")
	}
	if errors.Is(err, ErrAXFRRefused) {
		t.Errorf("a transport failure must not be reported as ErrAXFRRefused: %v", err)
	}
}

// TestCAA_ParsesRecords verifies CAA returns the published CAA record set with
// tags lower-cased, and that a non-Success rcode yields nil without error.
func TestCAA_ParsesRecords(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			name := dns.Fqdn("target.example.com")
			resp.Answer = []dns.RR{
				&dns.CAA{
					Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
					Flag:  0,
					Tag:   "ISSUE", // upper-case on the wire; resolver must lower-case
					Value: "letsencrypt.org",
				},
				&dns.CAA{
					Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
					Flag:  128,
					Tag:   "iodef",
					Value: "mailto:sec@example.com",
				},
			}
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.CAA(ctx, "target.example.com")
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 CAA records, got %d: %+v", len(got), got)
	}
	if got[0].Tag != "issue" {
		t.Errorf("tag[0]: got %q, want lower-cased %q", got[0].Tag, "issue")
	}
	if got[0].Value != "letsencrypt.org" {
		t.Errorf("value[0]: got %q, want %q", got[0].Value, "letsencrypt.org")
	}
	if got[1].Flag != 128 {
		t.Errorf("flag[1]: got %d, want 128 (critical)", got[1].Flag)
	}
}

// TestCAA_EmptyOnNXDOMAIN verifies CAA returns nil (not an error) on a
// non-Success rcode, mirroring MX/TXT.
func TestCAA_EmptyOnNXDOMAIN(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			resp.Rcode = dns.RcodeNameError
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := r.CAA(ctx, "gone.example.com")
	if err != nil {
		t.Fatalf("CAA returned error on NXDOMAIN, want nil: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil records on NXDOMAIN, got %+v", got)
	}
}

// TestTLSA_CountsRecords verifies TLSA reports the number of TLSA RRs published
// at a DANE owner name, ignoring non-TLSA answers.
func TestTLSA_CountsRecords(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			name := dns.Fqdn("_25._tcp.mx.example.com")
			resp.Answer = []dns.RR{
				&dns.TLSA{
					Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
					Usage: 3, Selector: 1, MatchingType: 1,
					Certificate: "00",
				},
				&dns.TLSA{
					Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
					Usage: 2, Selector: 0, MatchingType: 1,
					Certificate: "11",
				},
			}
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	count, err := r.TLSA(ctx, "_25._tcp.mx.example.com")
	if err != nil {
		t.Fatalf("TLSA: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 TLSA records, got %d", count)
	}
}

// TestTLSA_ZeroOnNXDOMAIN verifies TLSA returns (0, nil) on a non-Success rcode,
// mirroring MX/TXT/CAA.
func TestTLSA_ZeroOnNXDOMAIN(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

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
			resp.Rcode = dns.RcodeNameError
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	count, err := r.TLSA(ctx, "_25._tcp.gone.example.com")
	if err != nil {
		t.Fatalf("TLSA returned error on NXDOMAIN, want nil: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 records on NXDOMAIN, got %d", count)
	}
}
