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

// bimiDNSServer starts an in-process UDP DNS server for the BIMI detector tests.
// It publishes a TXT record at default._bimi.<target> with the given value
// (empty means none) and answers NXDOMAIN (any qtype) for each host in nxHosts.
// Everything else answers NOERROR/no-answer (i.e. "exists / no records"). The
// returned cleanup closes the socket.
func bimiDNSServer(t *testing.T, target, txtValue string, nxHosts []string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	txtName := dns.Fqdn(bimiDefaultSelector + bimiTXTSuffix + target)
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
				// NXDOMAIN for the dangling asset host (any qtype).
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

// TestBIMI_DanglingLogoHostPotential drives the full detector: a BIMI TXT record
// whose l= logo URL points at a host that is NXDOMAIN must yield exactly one
// Potential finding keyed on the target, carrying the BIMI owner name in Service
// and the dangling logo host in BIMIURIHost.
func TestBIMI_DanglingLogoHostPotential(t *testing.T) {
	const (
		target   = "example.com"
		logoHost = "images.dead-bimi-vendor.invalid"
	)

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=https://"+logoHost+"/brand/logo.svg",
		[]string{logoHost},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorBIMI {
		t.Errorf("vector: got %q, want bimi", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (BIMI is keyed on the target)", f.Subdomain, target)
	}
	if want := bimiDefaultSelector + bimiTXTSuffix + target; f.Service != want {
		t.Errorf("service: got %q, want %q (the BIMI owner name)", f.Service, want)
	}
	if f.BIMIURIHost != logoHost {
		t.Errorf("bimi_uri_host: got %q, want %q (the dangling logo host)", f.BIMIURIHost, logoHost)
	}
	if !strings.Contains(f.Evidence, "l=") {
		t.Errorf("evidence %q should name the l= tag", f.Evidence)
	}
}

// TestBIMI_DanglingVMCHostPotential verifies the a= (VMC certificate) URL host is
// probed independently: an l= host that resolves but an a= host that is NXDOMAIN
// must produce one finding for the dangling VMC host only.
func TestBIMI_DanglingVMCHostPotential(t *testing.T) {
	const (
		target   = "example.com"
		logoHost = "images.example.com" // resolves (healthy)
		vmcHost  = "certs.dead-vmc-vendor.invalid"
	)

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=https://"+logoHost+"/logo.svg; a=https://"+vmcHost+"/vmc.pem",
		[]string{vmcHost}, // only the VMC host is NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].BIMIURIHost != vmcHost {
		t.Errorf("bimi_uri_host: got %q, want %q (the dangling VMC host)", findings[0].BIMIURIHost, vmcHost)
	}
	if !strings.Contains(findings[0].Evidence, "a=") {
		t.Errorf("evidence %q should name the a= tag", findings[0].Evidence)
	}
}

// TestBIMI_SharedHostSingleFinding verifies that when the l= and a= URLs share a
// single dangling host, the detector emits ONE finding (deduplicated by host)
// that attributes both tags rather than two findings for the same host.
func TestBIMI_SharedHostSingleFinding(t *testing.T) {
	const (
		target = "example.com"
		host   = "assets.dead-bimi-vendor.invalid"
	)

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=https://"+host+"/logo.svg; a=https://"+host+"/vmc.pem",
		[]string{host},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d: %+v", len(findings), findings)
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "l=") || !strings.Contains(ev, "a=") {
		t.Errorf("evidence %q should attribute both the l= and a= tags to the shared host", ev)
	}
}

// TestBIMI_LiveAssetHostsNoFinding verifies that a BIMI deployment whose l= and
// a= asset hosts both resolve — the normal, healthy case — produces no finding.
func TestBIMI_LiveAssetHostsNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=https://images.example.com/logo.svg; a=https://certs.example.com/vmc.pem",
		nil, // nothing NXDOMAIN
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for live BIMI asset hosts, got %d: %+v", len(findings), findings)
	}
}

// TestBIMI_NoRecordNoFinding verifies that a domain with NO BIMI TXT record is
// not flagged — the domain never advertised BIMI, so there is nothing to dangle.
func TestBIMI_NoRecordNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := bimiDNSServer(t, target,
		"", // NO BIMI TXT record
		[]string{"images.dead-bimi-vendor.invalid"},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no BIMI record is advertised, got %d: %+v", len(findings), findings)
	}
}

// TestBIMI_NonBIMITXTIgnored verifies that an unrelated TXT record at the BIMI
// owner name (one that does not begin with v=BIMI1) is not treated as a BIMI
// record, so it does not trigger a finding even with a dangling host referenced.
func TestBIMI_NonBIMITXTIgnored(t *testing.T) {
	const target = "example.com"

	addr, cleanup := bimiDNSServer(t, target,
		"some-unrelated-token=abc123; l=https://images.dead-bimi-vendor.invalid/logo.svg",
		[]string{"images.dead-bimi-vendor.invalid"},
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a non-BIMI TXT record, got %d: %+v", len(findings), findings)
	}
}

// TestBIMI_SelfAndEmptyValuesIgnored verifies that a BIMI record with no remote
// asset URL — an empty l= and a= self (the VMC-less / self-asserted forms) —
// yields no finding: there is no remote host to dangle.
func TestBIMI_SelfAndEmptyValuesIgnored(t *testing.T) {
	const target = "example.com"

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=; a=self",
		[]string{"self"}, // even if "self" were NXDOMAIN, it must not be probed
	)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty l= and a=self, got %d: %+v", len(findings), findings)
	}
}

// TestBIMI_EvidenceMentionsBIMI pins the evidence wording so the human-readable
// signal cannot silently drift below the bar the other vectors set.
func TestBIMI_EvidenceMentionsBIMI(t *testing.T) {
	const (
		target   = "example.com"
		logoHost = "images.dead-bimi-vendor.invalid"
	)

	addr, cleanup := bimiDNSServer(t, target,
		"v=BIMI1; l=https://"+logoHost+"/logo.svg",
		[]string{logoHost})
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := BIMI(ctx, target, r)
	if err != nil {
		t.Fatalf("BIMI: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "BIMI") || !strings.Contains(ev, "NXDOMAIN") {
		t.Errorf("evidence %q should call out the BIMI asset host and the NXDOMAIN state", ev)
	}
}

// TestBIMI_CaseInsensitiveVersion verifies the version-token match tolerates case
// and whitespace, so "V=BIMI1 ; l=..." is still recognised as a BIMI record.
func TestBIMI_CaseInsensitiveVersion(t *testing.T) {
	cases := []struct {
		txt  string
		want bool
	}{
		{"v=BIMI1; l=https://x.example/logo.svg", true},
		{"V=BIMI1 ; l=https://x.example/logo.svg", true},
		{"  v=bimi1; l=https://x.example/logo.svg", true},
		{"v=BIMI2; l=https://x.example/logo.svg", false},
		{"google-site-verification=xyz", false},
		{"", false},
	}
	for _, c := range cases {
		if _, got := parseBIMIRecord([]string{c.txt}); got != c.want {
			t.Errorf("parseBIMIRecord(%q) = %v, want %v", c.txt, got, c.want)
		}
	}
}

// TestBIMI_URLHost pins bimiURLHost's parsing: it extracts the lower-cased host
// from absolute http(s) URLs and rejects empty, non-http, and hostless values.
func TestBIMI_URLHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://Images.Example.COM/logo.svg", "images.example.com"},
		{"http://cdn.example.net/brand/logo.svg", "cdn.example.net"},
		{"https://host.example.com:8443/logo.svg", "host.example.com"},
		{"self", ""},
		{"", ""},
		{"  ", ""},
		{"ftp://files.example.com/logo.svg", ""},
		{"/relative/logo.svg", ""},
	}
	for _, c := range cases {
		if got := bimiURLHost(c.in); got != c.want {
			t.Errorf("bimiURLHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBIMIFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestBIMIFinding_VectorConstant(t *testing.T) {
	if finding.VectorBIMI != "bimi" {
		t.Errorf("VectorBIMI = %q, want \"bimi\"", finding.VectorBIMI)
	}
}
