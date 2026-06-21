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

// nsDelegationServer spins up a local UDP DNS server that answers the NS query
// for `target` with the supplied nameserver hostnames (NS records are returned
// in the Answer section, the production path). Other queries return NOERROR
// with no answer. It is the parent-side resolver: the test then stands up one
// "child" UDP DNS server per nameserver that returns either an authoritative
// SOA (live) or SERVFAIL (lame), and installs a SetSOANameserverRewriteForTest
// rewrite so AuthoritativeSOA dials the per-NS test server.
//
// nameservers is a name→behaviour map: behaviour "live" makes the child server
// return an authoritative SOA NOERROR; "lame" makes it return SERVFAIL (which
// the resolver maps to ErrZoneDeleted). The returned resolver is wired to the
// parent UDP server; cleanup tears down every spawned listener and restores
// any test rewrites.
func nsDelegationServer(t *testing.T, target string, behaviours map[string]string) (*resolver.Resolver, func()) {
	t.Helper()

	parent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen parent udp: %v", err)
	}

	// Stable ordering so tests against the parent get NS records in a
	// deterministic order.
	names := make([]string, 0, len(behaviours))
	for n := range behaviours {
		names = append(names, n)
	}
	// sort.Strings would be unnecessary — the answer order does not affect the
	// detector's lame/live partition, since AuthoritativeSOA is queried per NS.

	// Bring up one child UDP server per nameserver.
	childAddrs := make(map[string]string, len(behaviours))
	childConns := make([]net.PacketConn, 0, len(behaviours))
	for _, name := range names {
		behaviour := behaviours[name]
		conn, listenErr := net.ListenPacket("udp", "127.0.0.1:0")
		if listenErr != nil {
			_ = parent.Close()
			for _, c := range childConns {
				_ = c.Close()
			}
			t.Fatalf("listen child udp for %s: %v", name, listenErr)
		}
		childConns = append(childConns, conn)
		childAddrs[name] = conn.LocalAddr().String()

		go runChildNS(conn, target, behaviour)
	}

	// Install the rewrite so AuthoritativeSOA(nameserver) dials the matching
	// child server instead of the real nameserver hostname.
	restoreRewrite := resolver.SetSOANameserverRewriteForTest(childAddrs)

	// Parent server: answer NS queries with the supplied nameserver hostnames.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := parent.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeNS && req.Question[0].Name == dns.Fqdn(target) {
				for _, name := range names {
					resp.Answer = append(resp.Answer, &dns.NS{
						Hdr: dns.RR_Header{Name: dns.Fqdn(target), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
						Ns:  dns.Fqdn(name),
					})
				}
			}
			packed, _ := resp.Pack()
			_, _ = parent.WriteTo(packed, addr)
		}
	}()

	r := resolver.New([]string{parent.LocalAddr().String()}, 500*time.Millisecond)

	cleanup := func() {
		restoreRewrite()
		_ = parent.Close()
		for _, c := range childConns {
			_ = c.Close()
		}
	}
	return r, cleanup
}

// runChildNS serves one nameserver's worth of SOA responses. behaviour:
//   - "live": NOERROR + AA bit + a synthetic SOA record (the authoritative
//     answer real nameservers return).
//   - "lame": SERVFAIL (mapped to ErrZoneDeleted by AuthoritativeSOA).
//
// Any other behaviour silently drops the request to simulate a transport
// error / timeout (neither live nor lame — the "unknown" partition the
// detector deliberately excludes from both findings).
func runChildNS(conn net.PacketConn, zone, behaviour string) {
	buf := make([]byte, 4096)
	for {
		n, addr, rErr := conn.ReadFrom(buf)
		if rErr != nil {
			return
		}
		req := new(dns.Msg)
		if req.Unpack(buf[:n]) != nil {
			continue
		}
		if behaviour == "unknown" {
			continue // do not respond
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		switch behaviour {
		case "live":
			resp.Authoritative = true
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeSOA {
				resp.Answer = []dns.RR{&dns.SOA{
					Hdr: dns.RR_Header{
						Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA,
						Class: dns.ClassINET, Ttl: 300,
					},
					Ns: "ns1." + dns.Fqdn(zone), Mbox: "hostmaster." + dns.Fqdn(zone),
					Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
				}}
			}
		case "lame":
			resp.Rcode = dns.RcodeServerFailure
		}
		packed, _ := resp.Pack()
		_, _ = conn.WriteTo(packed, addr)
	}
}

// TestNS_PartialLamePotential is the headline test for R32's partial-lame
// sub-case: two delegated nameservers, one authoritative and one returning
// SERVFAIL. The detector must emit one POTENTIAL ns finding listing ONLY the
// lame nameserver, with Evidence naming the partial lameness.
func TestNS_PartialLamePotential(t *testing.T) {
	const target = "partial.example.com"
	r, cleanup := nsDelegationServer(t, target, map[string]string{
		"ns1.live.test":   "live",
		"ns2.broken.test": "lame",
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := NS(ctx, target, r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorNS {
		t.Errorf("vector: got %q, want ns", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL (no provider match)", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, target)
	}
	if len(f.Nameservers) != 1 || f.Nameservers[0] != "ns2.broken.test" {
		t.Errorf("nameservers: got %v, want [ns2.broken.test] (only the lame NS)", f.Nameservers)
	}
	if !strings.Contains(f.Evidence, "partial lame delegation") {
		t.Errorf("evidence: got %q, want contains 'partial lame delegation'", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "1 of 2") {
		t.Errorf("evidence: got %q, want contains '1 of 2'", f.Evidence)
	}
}

// TestNS_PartialLameKnownProviderConfirmed: when at least one lame nameserver
// belongs to a known takeoverable provider (the indianajson list), the
// finding is upgraded to CONFIRMED — re-creating the zone at that provider
// partially hijacks the delegation.
func TestNS_PartialLameKnownProviderConfirmed(t *testing.T) {
	const target = "partial-hijack.example.com"
	// "awsdns" is a known-vulnerable provider suffix in the default
	// indianajson snapshot used by the NS detector.
	r, cleanup := nsDelegationServer(t, target, map[string]string{
		"ns1.live.test":         "live",
		"ns-1234.awsdns-12.org": "lame",
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := NS(ctx, target, r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != finding.Confirmed {
		t.Errorf("confidence: got %q, want CONFIRMED (lame NS matches takeoverable provider)", f.Confidence)
	}
	if f.Service == "" {
		t.Errorf("service: got empty, want the matched provider suffix")
	}
	if len(f.Nameservers) != 1 || f.Nameservers[0] != "ns-1234.awsdns-12.org" {
		t.Errorf("nameservers: got %v, want only the lame NS", f.Nameservers)
	}
	if !strings.Contains(f.Evidence, "takeoverable provider") {
		t.Errorf("evidence: got %q, want contains 'takeoverable provider'", f.Evidence)
	}
}

// TestNS_AllLameZoneDeletedSubCase confirms the existing strict-unanimity
// sub-case still fires when EVERY delegated nameserver is lame. The finding
// lists ALL nameservers (not just a subset), and Evidence is the original
// "all nameservers returned SERVFAIL/REFUSED" wording.
func TestNS_AllLameZoneDeletedSubCase(t *testing.T) {
	const target = "deleted.example.com"
	r, cleanup := nsDelegationServer(t, target, map[string]string{
		"ns1.gone.test": "lame",
		"ns2.gone.test": "lame",
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := NS(ctx, target, r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL (unknown provider)", f.Confidence)
	}
	if len(f.Nameservers) != 2 {
		t.Errorf("nameservers: got %v, want both", f.Nameservers)
	}
	if !strings.Contains(f.Evidence, "all nameservers returned SERVFAIL/REFUSED") {
		t.Errorf("evidence: got %q, want zone-deleted wording", f.Evidence)
	}
}

// TestNS_AllLiveNoFinding: the healthy case — every delegated nameserver
// answers authoritatively. No finding.
func TestNS_AllLiveNoFinding(t *testing.T) {
	const target = "healthy.example.com"
	r, cleanup := nsDelegationServer(t, target, map[string]string{
		"ns1.healthy.test": "live",
		"ns2.healthy.test": "live",
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := NS(ctx, target, r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on a healthy delegation, got %d: %+v", len(findings), findings)
	}
}

// TestNS_TransportErrorIsNotLame: a nameserver that fails to respond at the
// transport level (timeout) is classified as "unknown" — neither lame nor
// live — so a single unreachable nameserver alongside one live nameserver
// must NOT produce a finding. The detector errs toward false negatives over
// false positives.
func TestNS_TransportErrorIsNotLame(t *testing.T) {
	// Reduce the SOA retry/backoff to keep the test fast; the resolver still
	// performs its retry sequence on the unreachable nameserver.
	const target = "flaky.example.com"
	r, cleanup := nsDelegationServer(t, target, map[string]string{
		"ns1.live.test":        "live",
		"ns2.unreachable.test": "unknown",
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := NS(ctx, target, r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when the only non-live NS is a transport-error 'unknown', got %d: %+v", len(findings), findings)
	}
}

// TestNS_NoDelegationNoFinding: the resolver returns no NS records (the
// target is undelegated or the lookup errored). The detector returns no
// findings without attempting any SOA probes.
func TestNS_NoDelegationNoFinding(t *testing.T) {
	// Stand up a UDP DNS server that answers every query with NOERROR + no
	// answer — so r.NS returns no nameservers.
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
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := resolver.New([]string{pc.LocalAddr().String()}, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	findings, err := NS(ctx, "undelegated.example.com", r)
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no NS records, got %d", len(findings))
	}
}

// TestMatchProviderInList exercises the cache-aware provider matcher used by
// the partial-lame sub-case. The default provider list ships with awsdns
// among its suffixes; an unknown registrar must not match.
func TestMatchProviderInList(t *testing.T) {
	cases := []struct {
		ns        []string
		wantMatch bool
	}{
		{[]string{"ns1.awsdns-01.com"}, true},
		{[]string{"ns1.cloudflare.com"}, true},
		{[]string{"ns1.completely-unknown-registrar.com"}, false},
		{[]string{"ns1.live.test", "ns-1234.awsdns-12.org"}, true}, // mixed
	}
	for _, c := range cases {
		got := matchProviderInList(c.ns) != ""
		if got != c.wantMatch {
			t.Errorf("matchProviderInList(%v) match=%v, want=%v", c.ns, got, c.wantMatch)
		}
	}
}

// guard against the strconv import being elided by future refactors — the
// partial-lame Evidence string depends on it.
var _ = strconv.Itoa
