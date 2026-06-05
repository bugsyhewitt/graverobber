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

// autodiscoverDNSServer starts an in-process UDP DNS server for the Autodiscover
// detector tests. It publishes:
//   - an optional CNAME at each host in cnames (map host -> CNAME target) that
//     resolves (the target gets an A record too, so the chain is "live"),
//   - NXDOMAIN (any qtype) for each host listed in nxHosts,
//   - an optional CNAME at each host in danglingCNAMEs (map host -> CNAME target)
//     whose chain ends in NXDOMAIN at the target.
//
// Everything else answers NOERROR/no-answer (i.e. "exists / no records"). It
// mirrors mtaStsDNSServer's structure. The returned cleanup closes the socket.
func autodiscoverDNSServer(t *testing.T, cnames, danglingCNAMEs map[string]string, nxHosts []string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	nxSet := map[string]bool{}
	for _, h := range nxHosts {
		nxSet[dns.Fqdn(h)] = true
	}
	live := map[string]string{}
	for h, tgt := range cnames {
		live[dns.Fqdn(h)] = dns.Fqdn(tgt)
	}
	dangling := map[string]string{}
	for h, tgt := range danglingCNAMEs {
		dangling[dns.Fqdn(h)] = dns.Fqdn(tgt)
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
			case nxSet[name]:
				// NXDOMAIN for the dangling host (any qtype).
				resp.Rcode = dns.RcodeNameError
			case q.Qtype == dns.TypeA && live[name] != "":
				// Healthy host published as a CNAME that resolves.
				tgt := live[name]
				resp.Answer = append(resp.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: tgt,
				})
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: tgt, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.20"),
				})
			case q.Qtype == dns.TypeA && dangling[name] != "":
				// CNAME hop to a provider host, then NXDOMAIN at that target.
				resp.Answer = append(resp.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dangling[name],
				})
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

// TestAutodiscover_DanglingHostPotential drives the full detector: an
// autodiscover.<domain> host that is NXDOMAIN must yield exactly one Potential
// finding keyed on the target, carrying the dangling host in Service.
func TestAutodiscover_DanglingHostPotential(t *testing.T) {
	const target = "example.com"

	addr, cleanup := autodiscoverDNSServer(t, nil, nil,
		[]string{"autodiscover." + target}, // autodiscover.example.com NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorAutodiscover {
		t.Errorf("vector: got %q, want autodiscover", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (keyed on the target)", f.Subdomain, target)
	}
	if want := "autodiscover." + target; f.Service != want {
		t.Errorf("service: got %q, want %q (the dangling host)", f.Service, want)
	}
	// With no CNAME chain, the claimable target is the host itself.
	if want := "autodiscover." + target; f.CNAME != want {
		t.Errorf("cname: got %q, want %q", f.CNAME, want)
	}
}

// TestAutodiscover_DanglingViaCNAMETarget verifies that when the host is a CNAME
// to a gone provider host, the finding records the final CNAME target (the
// resource the attacker would actually reclaim) in CNAME.
func TestAutodiscover_DanglingViaCNAMETarget(t *testing.T) {
	const (
		target   = "example.com"
		provider = "example.mail.dead-tenant.invalid"
	)

	addr, cleanup := autodiscoverDNSServer(t,
		nil,
		map[string]string{"autoconfig." + target: provider}, // CNAME -> provider, NXDOMAIN at provider
		nil,
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].CNAME != provider {
		t.Errorf("cname: got %q, want %q (the claimable CNAME target)", findings[0].CNAME, provider)
	}
	if want := "autoconfig." + target; findings[0].Service != want {
		t.Errorf("service: got %q, want %q", findings[0].Service, want)
	}
}

// TestAutodiscover_BothHostsDanglingTwoFindings verifies that when BOTH
// autoconfiguration hosts are NXDOMAIN, the detector emits one finding per host
// (each is an independently reclaimable takeover surface).
func TestAutodiscover_BothHostsDanglingTwoFindings(t *testing.T) {
	const target = "example.com"

	addr, cleanup := autodiscoverDNSServer(t, nil, nil,
		[]string{"autodiscover." + target, "autoconfig." + target},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per dangling host), got %d: %+v", len(findings), findings)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Service] = true
		if f.Vector != finding.VectorAutodiscover || f.Confidence != finding.Potential {
			t.Errorf("unexpected finding shape: %+v", f)
		}
	}
	for _, want := range []string{"autodiscover." + target, "autoconfig." + target} {
		if !got[want] {
			t.Errorf("missing finding for dangling host %q; got services %v", want, got)
		}
	}
}

// TestAutodiscover_LiveHostsNoFinding verifies that a domain whose
// autoconfiguration hosts still resolve — the normal, healthy case — produces no
// finding.
func TestAutodiscover_LiveHostsNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := autodiscoverDNSServer(t,
		map[string]string{
			"autodiscover." + target: "autodiscover.outlook.com",
			"autoconfig." + target:   "autoconfig.thunderbird.example.net",
		},
		nil, nil,
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for live autoconfiguration hosts, got %d: %+v", len(findings), findings)
	}
}

// TestAutodiscover_NoRecordNoFinding verifies that a domain that publishes
// neither autoconfiguration host (both resolve NOERROR/no-answer, the
// internet-wide default for a domain not using hosted mail autoconfig) is not
// flagged — only an NXDOMAIN host is a dangling host.
func TestAutodiscover_NoRecordNoFinding(t *testing.T) {
	const target = "example.com"

	// Empty server: every name answers NOERROR/no-answer (exists / no records).
	addr, cleanup := autodiscoverDNSServer(t, nil, nil, nil)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no autoconfiguration host is NXDOMAIN, got %d: %+v", len(findings), findings)
	}
}

// TestAutodiscover_MixedOnlyDanglingFlagged verifies that when one host is live
// and the other is NXDOMAIN, only the dangling host is flagged.
func TestAutodiscover_MixedOnlyDanglingFlagged(t *testing.T) {
	const target = "example.com"

	addr, cleanup := autodiscoverDNSServer(t,
		map[string]string{"autodiscover." + target: "autodiscover.outlook.com"}, // live
		nil,
		[]string{"autoconfig." + target}, // NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (only the dangling host), got %d: %+v", len(findings), findings)
	}
	if want := "autoconfig." + target; findings[0].Service != want {
		t.Errorf("service: got %q, want %q (the dangling host, not the live one)", findings[0].Service, want)
	}
}

// TestAutodiscover_EmptyTargetNoFinding verifies the blank-target guard: a blank
// or whitespace-only target produces no finding and no DNS probe.
func TestAutodiscover_EmptyTargetNoFinding(t *testing.T) {
	r := resolver.New([]string{"127.0.0.1:0"}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, "   ", r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a blank target, got %d: %+v", len(findings), findings)
	}
}

// TestAutodiscover_DeadApexNoFinding verifies the apex gate: when the target
// domain itself is NXDOMAIN (a dead domain), its autoconfiguration hosts are
// trivially NXDOMAIN too, but that is not an autoconfiguration-host takeover and
// must not be flagged.
func TestAutodiscover_DeadApexNoFinding(t *testing.T) {
	const target = "dead-domain.invalid"

	addr, cleanup := autodiscoverDNSServer(t, nil, nil,
		[]string{
			target, // the apex itself is NXDOMAIN
			"autodiscover." + target,
			"autoconfig." + target,
		},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a dead (NXDOMAIN) apex, got %d: %+v", len(findings), findings)
	}
}

// TestAutodiscover_EvidenceMentionsHostAndNXDOMAIN pins the evidence wording so
// the human-readable signal cannot silently drift below the bar the other
// vectors set.
func TestAutodiscover_EvidenceMentionsHostAndNXDOMAIN(t *testing.T) {
	const target = "example.com"

	addr, cleanup := autodiscoverDNSServer(t, nil, nil,
		[]string{"autodiscover." + target})
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := Autodiscover(ctx, target, r)
	if err != nil {
		t.Fatalf("Autodiscover: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "autodiscover."+target) || !strings.Contains(ev, "NXDOMAIN") {
		t.Errorf("evidence %q should call out the dangling host and the NXDOMAIN state", ev)
	}
}

// TestAutodiscoverFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestAutodiscoverFinding_VectorConstant(t *testing.T) {
	if finding.VectorAutodiscover != "autodiscover" {
		t.Errorf("VectorAutodiscover = %q, want \"autodiscover\"", finding.VectorAutodiscover)
	}
}
