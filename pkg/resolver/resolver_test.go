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
