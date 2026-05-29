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

// tlsRptDNSServer starts an in-process UDP DNS server for the TLSRPT detector
// tests. It publishes a TXT record at _smtp._tls.<target> with the given value
// (empty means none) and answers NXDOMAIN (any qtype) for each host in nxHosts.
// Everything else answers NOERROR/no-answer (i.e. "exists / no records"). The
// returned cleanup closes the socket.
func tlsRptDNSServer(t *testing.T, target, txtValue string, nxHosts []string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	txtName := dns.Fqdn(tlsRptOwnerPrefix + target)
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
				// NXDOMAIN for the dangling report-destination host (any qtype).
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

// newTLSRPTResolver builds a resolver pointed at addr with a short timeout and a
// bounded context, returning both plus a cancel func, to keep each test terse.
func newTLSRPTResolver(t *testing.T, addr string) (*resolver.Resolver, context.Context, context.CancelFunc) {
	t.Helper()
	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	return r, ctx, cancel
}

// TestTLSRPT_DanglingMailtoDomainPotential drives the full detector: a TLSRPT
// record whose rua= mailto: destination names a domain that is NXDOMAIN must
// yield exactly one Potential finding keyed on the target, carrying the TLSRPT
// owner name in Service and the dangling report domain in TLSRPTURIHost.
func TestTLSRPT_DanglingMailtoDomainPotential(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "tls-reports.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=mailto:tlsrpt@"+reportHost,
		[]string{reportHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorTLSRPT {
		t.Errorf("vector: got %q, want tlsrpt", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (TLSRPT is keyed on the target)", f.Subdomain, target)
	}
	if want := tlsRptOwnerPrefix + target; f.Service != want {
		t.Errorf("service: got %q, want %q (the TLSRPT owner name)", f.Service, want)
	}
	if f.TLSRPTURIHost != reportHost {
		t.Errorf("tlsrpt_uri_host: got %q, want %q (the dangling report domain)", f.TLSRPTURIHost, reportHost)
	}
}

// TestTLSRPT_DanglingHTTPSHostPotential verifies an https: collector destination
// is probed: a rua=https:// URL whose host is NXDOMAIN yields one finding naming
// that host.
func TestTLSRPT_DanglingHTTPSHostPotential(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "collector.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=https://"+reportHost+"/v1/tlsrpt",
		[]string{reportHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].TLSRPTURIHost != reportHost {
		t.Errorf("tlsrpt_uri_host: got %q, want %q (the dangling https collector host)",
			findings[0].TLSRPTURIHost, reportHost)
	}
}

// TestTLSRPT_MixedDestinationsOnlyDanglingFlagged verifies that when rua= lists
// several destinations, a live one is not flagged and only the NXDOMAIN one
// produces a finding — proving each destination is probed independently.
func TestTLSRPT_MixedDestinationsOnlyDanglingFlagged(t *testing.T) {
	const (
		target   = "example.com"
		liveHost = "reports.live-vendor.example" // resolves (healthy)
		deadHost = "reports.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=mailto:a@"+liveHost+",https://"+deadHost+"/r",
		[]string{deadHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].TLSRPTURIHost != deadHost {
		t.Errorf("tlsrpt_uri_host: got %q, want the dangling host %q", findings[0].TLSRPTURIHost, deadHost)
	}
}

// TestTLSRPT_SharedHostSingleFinding verifies that when two destinations name the
// same dangling host (e.g. mailto: and https: on one vendor), exactly one finding
// is emitted (deduplicated by host).
func TestTLSRPT_SharedHostSingleFinding(t *testing.T) {
	const (
		target   = "example.com"
		deadHost = "reports.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=mailto:a@"+deadHost+",https://"+deadHost+"/r",
		[]string{deadHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 deduplicated finding, got %d: %+v", len(findings), findings)
	}
}

// TestTLSRPT_LiveDestinationsNoFinding verifies that a TLSRPT deployment whose
// rua= destinations all resolve is the healthy case and is NOT flagged.
func TestTLSRPT_LiveDestinationsNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=mailto:tls@reports.live-vendor.example",
		nil, // no NXDOMAIN hosts → everything resolves
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a healthy TLSRPT deployment, got %d: %+v", len(findings), findings)
	}
}

// TestTLSRPT_NoRecordNoFinding verifies that a domain with NO TLSRPT TXT record is
// not flagged (nothing is advertised, so nothing can dangle).
func TestTLSRPT_NoRecordNoFinding(t *testing.T) {
	const target = "example.com"

	addr, cleanup := tlsRptDNSServer(t, target, "", nil)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when no TLSRPT record exists, got %d: %+v", len(findings), findings)
	}
}

// TestTLSRPT_NonTLSRPTTXTIgnored verifies that an unrelated TXT record at the
// TLSRPT owner name (one that does not begin with v=TLSRPTv1) is ignored, so the
// detector never fires on a non-TLSRPT record that happens to share the name.
func TestTLSRPT_NonTLSRPTTXTIgnored(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "reports.dead-vendor.invalid"
	)

	// A record that looks structurally similar but lacks the v=TLSRPTv1 version.
	addr, cleanup := tlsRptDNSServer(t, target,
		"some-other-policy; rua=mailto:x@"+reportHost,
		[]string{reportHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a non-TLSRPT TXT record, got %d: %+v", len(findings), findings)
	}
}

// TestTLSRPT_CaseInsensitiveVersion verifies the version-token match tolerates
// case (RFC 8460 publishers vary), so "V=TLSRPTv1" is still recognised.
func TestTLSRPT_CaseInsensitiveVersion(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "reports.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"V=TLSRPTv1; rua=mailto:tls@"+reportHost,
		[]string{reportHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a case-variant version token, got %d: %+v", len(findings), findings)
	}
}

// TestTLSRPT_EvidenceMentionsTLSRPT pins the evidence wording so the
// human-readable output names the vector and the interception risk.
func TestTLSRPT_EvidenceMentionsTLSRPT(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "reports.dead-vendor.invalid"
	)

	addr, cleanup := tlsRptDNSServer(t, target,
		"v=TLSRPTv1; rua=mailto:tls@"+reportHost,
		[]string{reportHost},
	)
	defer cleanup()

	r, ctx, cancel := newTLSRPTResolver(t, addr)
	defer cancel()

	findings, err := TLSRPT(ctx, target, r)
	if err != nil {
		t.Fatalf("TLSRPT: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "TLSRPT") {
		t.Errorf("evidence %q should name TLSRPT", ev)
	}
	if !strings.Contains(ev, reportHost) {
		t.Errorf("evidence %q should name the dangling report host %q", ev, reportHost)
	}
}

// TestTLSRPT_ReportHosts pins tlsRptReportHosts's parsing: it extracts the
// mailto: address domain and the https: URL host, lower-cases them, and skips
// destinations that name no remote host (malformed mailto, non-http(s) scheme).
func TestTLSRPT_ReportHosts(t *testing.T) {
	cases := []struct {
		name   string
		record string
		want   []string
	}{
		{
			name:   "single mailto",
			record: "v=TLSRPTv1; rua=mailto:tls@reports.example.net",
			want:   []string{"reports.example.net"},
		},
		{
			name:   "single https",
			record: "v=TLSRPTv1; rua=https://collector.example.net/v1",
			want:   []string{"collector.example.net"},
		},
		{
			name:   "mixed comma-separated",
			record: "v=TLSRPTv1; rua=mailto:a@A.example.net,https://B.example.net/r",
			want:   []string{"a.example.net", "b.example.net"},
		},
		{
			name:   "malformed mailto (no domain) skipped",
			record: "v=TLSRPTv1; rua=mailto:bare-local-part",
			want:   nil,
		},
		{
			name:   "non-http(s) scheme skipped",
			record: "v=TLSRPTv1; rua=ftp://files.example.net/report",
			want:   nil,
		},
		{
			name:   "no rua tag",
			record: "v=TLSRPTv1; v=TLSRPTv1",
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tlsRptReportHosts(tc.record)
			if len(got) != len(tc.want) {
				t.Fatalf("hosts: got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("host[%d]: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestTLSRPTFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contract and the documented summary breakdown stay stable.
func TestTLSRPTFinding_VectorConstant(t *testing.T) {
	if finding.VectorTLSRPT != "tlsrpt" {
		t.Errorf("VectorTLSRPT: got %q, want %q", finding.VectorTLSRPT, "tlsrpt")
	}
}
