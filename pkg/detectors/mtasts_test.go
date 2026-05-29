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

// mtaStsDNSServer starts an in-process UDP DNS server for the MTA-STS detector
// tests. It publishes:
//   - a TXT record at _mta-sts.<target> with the given value (empty means none),
//   - an optional CNAME at mta-sts.<target> pointing at policyCNAME,
//   - NXDOMAIN (TypeA/TypeCNAME) for each host listed in nxHosts.
//
// Everything else answers NOERROR/no-answer (i.e. "exists / no records"). It
// mirrors tlsaDNSServer's structure. The returned cleanup closes the socket.
func mtaStsDNSServer(t *testing.T, target, txtValue, policyCNAME string, nxHosts []string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	txtName := dns.Fqdn(mtaStsTXTPrefix + target)
	policyHost := dns.Fqdn(mtaStsPolicyPrefix + target)
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
			case q.Qtype == dns.TypeTXT && name == txtName && txtValue != "":
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{txtValue},
				})
			case nxSet[name]:
				// NXDOMAIN for the dangling policy host (any qtype).
				resp.Rcode = dns.RcodeNameError
			case q.Qtype == dns.TypeA && name == policyHost && policyCNAME != "":
				// Healthy policy host published as a CNAME that resolves.
				resp.Answer = append(resp.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dns.Fqdn(policyCNAME),
				})
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(policyCNAME), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.10"),
				})
			default:
				// Everything else NOERROR/no-answer → exists / no records.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestMTASTS_DanglingPolicyHostPotential drives the full detector: an MTA-STS
// TXT policy signal published for a domain whose policy host (mta-sts.<domain>)
// is NXDOMAIN must yield exactly one Potential finding keyed on the target,
// carrying the policy host in Service.
func TestMTASTS_DanglingPolicyHostPotential(t *testing.T) {
	const target = "example.com"

	addr, cleanup := mtaStsDNSServer(t, target,
		"v=STSv1; id=20231201T000000Z",        // _mta-sts TXT signal present
		"",                                    // policy host is NOT a live CNAME
		[]string{mtaStsPolicyPrefix + target}, // mta-sts.example.com is NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorMTASTS {
		t.Errorf("vector: got %q, want mtasts", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (MTA-STS is keyed on the target)", f.Subdomain, target)
	}
	if want := mtaStsPolicyPrefix + target; f.Service != want {
		t.Errorf("service: got %q, want %q (the dangling policy host)", f.Service, want)
	}
	// With no CNAME chain, the claimable target is the policy host itself.
	if want := mtaStsPolicyPrefix + target; f.CNAME != want {
		t.Errorf("cname: got %q, want %q", f.CNAME, want)
	}
}

// TestMTASTS_DanglingViaCNAMETarget verifies that when the policy host is a
// CNAME to a gone provider host, the finding records the final CNAME target (the
// resource the attacker would actually reclaim) in CNAME.
func TestMTASTS_DanglingViaCNAMETarget(t *testing.T) {
	const (
		target   = "example.com"
		provider = "policy.dead-mta-sts-vendor.invalid"
	)

	// Custom server: policy host is a CNAME whose target is NXDOMAIN.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	txtName := dns.Fqdn(mtaStsTXTPrefix + target)
	policyHost := dns.Fqdn(mtaStsPolicyPrefix + target)
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
			q := req.Question[0]
			switch {
			case q.Qtype == dns.TypeTXT && q.Name == txtName:
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{"v=STSv1; id=42"},
				})
			case q.Qtype == dns.TypeA && q.Name == policyHost:
				// CNAME hop to the provider, then NXDOMAIN at the target.
				resp.Answer = append(resp.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dns.Fqdn(provider),
				})
				resp.Rcode = dns.RcodeNameError
			}
			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	r := resolver.New([]string{pc.LocalAddr().String()}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].CNAME != provider {
		t.Errorf("cname: got %q, want %q (the claimable CNAME target)", findings[0].CNAME, provider)
	}
	if want := mtaStsPolicyPrefix + target; findings[0].Service != want {
		t.Errorf("service: got %q, want %q", findings[0].Service, want)
	}
}

// TestMTASTS_LivePolicyHostNoFinding verifies that an MTA-STS deployment whose
// policy host still resolves — the normal, healthy case — produces no finding.
func TestMTASTS_LivePolicyHostNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := mtaStsDNSServer(t, target,
		"v=STSv1; id=20231201T000000Z",
		"mta-sts.provider.example.net", // policy host resolves via CNAME
		nil,                            // nothing NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a live MTA-STS policy host, got %d: %+v", len(findings), findings)
	}
}

// TestMTASTS_NoPolicySignalNoFinding verifies that a domain with NO _mta-sts TXT
// signal is not flagged even when mta-sts.<domain> happens to be NXDOMAIN — the
// domain never advertised MTA-STS, so there is nothing to dangle.
func TestMTASTS_NoPolicySignalNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := mtaStsDNSServer(t, target,
		"", // NO _mta-sts TXT record
		"",
		[]string{mtaStsPolicyPrefix + target}, // policy host NXDOMAIN, but no signal
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no MTA-STS policy is advertised, got %d: %+v", len(findings), findings)
	}
}

// TestMTASTS_NonMTASTSTXTIgnored verifies that an unrelated TXT record at
// _mta-sts.<domain> (one that does not begin with v=STSv1) is not treated as an
// MTA-STS policy signal, so it does not trigger a finding even with a dangling
// policy host.
func TestMTASTS_NonMTASTSTXTIgnored(t *testing.T) {
	const target = "example.com"

	addr, cleanup := mtaStsDNSServer(t, target,
		"some-unrelated-verification-token=abc123", // not an MTA-STS record
		"",
		[]string{mtaStsPolicyPrefix + target},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a non-MTA-STS TXT record, got %d: %+v", len(findings), findings)
	}
}

// TestMTASTS_EvidenceMentionsMTASTS pins the evidence wording so the
// human-readable signal cannot silently drift below the bar the other vectors
// set.
func TestMTASTS_EvidenceMentionsMTASTS(t *testing.T) {
	const target = "example.com"

	addr, cleanup := mtaStsDNSServer(t, target,
		"v=STSv1; id=20231201T000000Z", "",
		[]string{mtaStsPolicyPrefix + target})
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := MTASTS(ctx, target, r)
	if err != nil {
		t.Fatalf("MTASTS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "MTA-STS") || !strings.Contains(ev, "NXDOMAIN") {
		t.Errorf("evidence %q should call out the MTA-STS policy host and the NXDOMAIN state", ev)
	}
}

// TestMTASTS_CaseInsensitiveVersion verifies the version-token match tolerates
// case and whitespace, so "V=STSv1 ; id=..." is still recognised as a policy
// signal (RFC 8461 field names are case-insensitive in practice).
func TestMTASTS_CaseInsensitiveVersion(t *testing.T) {
	cases := []struct {
		txt  string
		want bool
	}{
		{"v=STSv1; id=1", true},
		{"V=STSv1 ; id=1", true},
		{"  v=stsv1; id=1", true},
		{"v=STSv2; id=1", false},
		{"google-site-verification=xyz", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hasMTASTSPolicySignal([]string{c.txt}); got != c.want {
			t.Errorf("hasMTASTSPolicySignal(%q) = %v, want %v", c.txt, got, c.want)
		}
	}
}

// TestMTASTSFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestMTASTSFinding_VectorConstant(t *testing.T) {
	if finding.VectorMTASTS != "mtasts" {
		t.Errorf("VectorMTASTS = %q, want \"mtasts\"", finding.VectorMTASTS)
	}
}
