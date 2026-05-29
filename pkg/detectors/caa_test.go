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

// caaRecord is a single CAA record the hermetic test DNS server should publish
// for the target.
type caaRecord struct {
	flag  uint8
	tag   string
	value string
}

// caaDNSServer starts an in-process UDP DNS server that answers CAA queries for
// target with the supplied records, returns NXDOMAIN (TypeA/TypeCNAME) for
// nxDomain, and answers NOERROR/no-answer (i.e. "exists") for everything else.
// It mirrors dmarcDNSServer's structure. The returned cleanup closes the socket.
func caaDNSServer(t *testing.T, target string, records []caaRecord, nxDomain string) (string, func()) {
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
			case q.Qtype == dns.TypeCAA && name == dns.Fqdn(target):
				for _, rec := range records {
					resp.Answer = append(resp.Answer, &dns.CAA{
						Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
						Flag:  rec.flag,
						Tag:   rec.tag,
						Value: rec.value,
					})
				}
			case nxDomain != "" && q.Qtype == dns.TypeA && name == dns.Fqdn(nxDomain):
				resp.Rcode = dns.RcodeNameError
			case nxDomain != "" && q.Qtype == dns.TypeCNAME && name == dns.Fqdn(nxDomain):
				resp.Rcode = dns.RcodeNameError
			default:
				// Everything else NOERROR/no-answer → exists.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestCAAIssuerDomain unit-tests the issue/issuewild value parser: the
// issuer-domain-name is taken before the first ";", trimmed, lower-cased; the
// deny-all ";" and empty values yield ""; the any-CA "*" is preserved.
func TestCAAIssuerDomain(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"letsencrypt.org", "letsencrypt.org"},
		{"DigiCert.com", "digicert.com"},                                 // lower-cased
		{"letsencrypt.org; validationmethods=dns-01", "letsencrypt.org"}, // params stripped
		{" sectigo.com ", "sectigo.com"},                                 // trimmed
		{";", ""},                                                        // deny-all
		{"", ""},                                                         // empty
		{"  ; account=123", ""},                                          // deny-all with params
		{"*", "*"},                                                       // any CA
		{"*; account=123", "*"},                                          // any CA with params
	}
	for _, c := range cases {
		if got := caaIssuerDomain(c.value); got != c.want {
			t.Errorf("caaIssuerDomain(%q) = %q, want %q", c.value, got, c.want)
		}
	}
}

// TestCAA_DanglingIssuerPotential drives the full detector: an issue= tag naming
// a CA domain that is NXDOMAIN must yield exactly one Potential finding keyed on
// the target, carrying the claimable domain in CAAIssuer.
func TestCAA_DanglingIssuerPotential(t *testing.T) {
	const (
		target   = "example.com"
		caDomain = "ca.dead-vendor.invalid"
	)
	records := []caaRecord{{tag: "issue", value: caDomain}}

	addr, cleanup := caaDNSServer(t, target, records, caDomain)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorCAA {
		t.Errorf("vector: got %q, want caa", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.CAAIssuer != caDomain {
		t.Errorf("caa_issuer: got %q, want %q", f.CAAIssuer, caDomain)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (CAA is keyed on the target)", f.Subdomain, target)
	}
}

// TestCAAIodefHost unit-tests the iodef URL host parser: mailto: yields the host
// after the "@", http(s):// yields the URL authority host, both lower-cased; other
// schemes, host-less values, and malformed addresses yield "".
func TestCAAIodefHost(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"mailto:sec@reports.example.com", "reports.example.com"},
		{"mailto:Sec@Reports.Example.COM", "reports.example.com"}, // lower-cased
		{"MAILTO:sec@reports.example.com", "reports.example.com"}, // scheme case-insensitive
		{"https://iodef.example.com/report", "iodef.example.com"},
		{"http://Iodef.Example.com:8080/r", "iodef.example.com"}, // port stripped, lower-cased
		{"mailto:sec@", ""},              // no host after @
		{"mailto:nobody", ""},            // no @ at all
		{"ftp://iodef.example.com/", ""}, // unsupported scheme
		{"", ""},                         // empty
		{"   ", ""},                      // whitespace only
	}
	for _, c := range cases {
		if got := caaIodefHost(c.value); got != c.want {
			t.Errorf("caaIodefHost(%q) = %q, want %q", c.value, got, c.want)
		}
	}
}

// TestCAA_DanglingIodefMailtoPotential drives the full detector: an iodef= tag
// whose mailto: report host is NXDOMAIN must yield exactly one Potential finding
// keyed on the target, carrying the claimable report host in CAAIssuer with
// evidence that names the iodef report-interception case.
func TestCAA_DanglingIodefMailtoPotential(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "reports.dead-vendor.invalid"
	)
	records := []caaRecord{{tag: "iodef", value: "mailto:sec@" + reportHost}}

	addr, cleanup := caaDNSServer(t, target, records, reportHost)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorCAA {
		t.Errorf("vector: got %q, want caa", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.CAAIssuer != reportHost {
		t.Errorf("caa_issuer: got %q, want %q", f.CAAIssuer, reportHost)
	}
	if f.Subdomain != target {
		t.Errorf("subdomain: got %q, want %q (CAA is keyed on the target)", f.Subdomain, target)
	}
	if !strings.Contains(f.Evidence, "iodef") {
		t.Errorf("evidence %q does not name the iodef report-interception case", f.Evidence)
	}
}

// TestCAA_DanglingIodefHTTPSPotential verifies the http(s):// iodef variant: a
// report URL whose host is NXDOMAIN yields one Potential finding carrying the host.
func TestCAA_DanglingIodefHTTPSPotential(t *testing.T) {
	const (
		target     = "example.com"
		reportHost = "iodef.dead-vendor.invalid"
	)
	records := []caaRecord{{tag: "iodef", value: "https://" + reportHost + "/report"}}

	addr, cleanup := caaDNSServer(t, target, records, reportHost)
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].CAAIssuer != reportHost {
		t.Errorf("caa_issuer: got %q, want %q", findings[0].CAAIssuer, reportHost)
	}
}

// TestCAA_LiveIodefNoFinding verifies that an iodef= tag whose report host
// resolves (the normal, correctly-configured case) produces no finding.
func TestCAA_LiveIodefNoFinding(t *testing.T) {
	const target = "example.com"
	records := []caaRecord{{tag: "iodef", value: "mailto:sec@reports.example.com"}}

	// nxDomain is an unrelated host, so the report host answers NOERROR (exists).
	addr, cleanup := caaDNSServer(t, target, records, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a live iodef report host, got %d: %+v", len(findings), findings)
	}
}

// TestCAA_PermissiveAnyCAPotential verifies that an issue= tag with value "*"
// (authorise any CA) yields a Potential permissive finding with no CAAIssuer.
func TestCAA_PermissiveAnyCAPotential(t *testing.T) {
	const target = "example.com"
	records := []caaRecord{{tag: "issue", value: "*"}}

	addr, cleanup := caaDNSServer(t, target, records, "")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.CAAIssuer != "" {
		t.Errorf("caa_issuer: got %q, want empty for the permissive sub-case", f.CAAIssuer)
	}
	if !strings.Contains(f.Evidence, "any CA") {
		t.Errorf("evidence %q does not call out the any-CA permissive case", f.Evidence)
	}
}

// TestCAA_LiveIssuerNoFinding verifies that a CAA issue= tag naming a CA domain
// that resolves (exists) — the normal, correctly-configured case — produces no
// finding. The deny-all ";" record is also exercised and must be silent.
func TestCAA_LiveIssuerNoFinding(t *testing.T) {
	const target = "example.com"
	records := []caaRecord{
		{tag: "issue", value: "letsencrypt.org"},
		{tag: "issuewild", value: ";"}, // deny-all wildcard: secure, never flagged
		{tag: "iodef", value: "mailto:sec@example.com"},
	}

	addr, cleanup := caaDNSServer(t, target, records, "unused.invalid")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a live issuer + deny-all wildcard, got %d: %+v", len(findings), findings)
	}
}

// TestCAA_NoRecordNoFinding verifies that a domain with no CAA record set (the
// permissive internet-wide default) produces no finding — the vector is
// intentionally low-noise and only reports present-but-broken policies.
func TestCAA_NoRecordNoFinding(t *testing.T) {
	const target = "example.com"
	// No CAA records published; the server answers NOERROR/no-answer.
	addr, cleanup := caaDNSServer(t, target, nil, "")
	defer cleanup()

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := CAA(ctx, target, r)
	if err != nil {
		t.Fatalf("CAA: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when no CAA record is published, got %d: %+v", len(findings), findings)
	}
}

// TestCAAFinding_VectorConstant pins the vector tag so the JSON/SARIF/CSV
// contracts cannot drift.
func TestCAAFinding_VectorConstant(t *testing.T) {
	if finding.VectorCAA != "caa" {
		t.Errorf("VectorCAA = %q, want \"caa\"", finding.VectorCAA)
	}
}
