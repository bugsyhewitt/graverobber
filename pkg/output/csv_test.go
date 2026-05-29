package output

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// runCSV writes the findings through a CSVWriter and parses the result back into
// records so assertions work on structured rows, not raw text.
func runCSV(t *testing.T, findings ...finding.Finding) [][]string {
	t.Helper()
	var buf bytes.Buffer
	w := NewCSV(&buf)
	for _, f := range findings {
		if err := w.Write(f); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	return recs
}

// colIndex returns the column position of name in csvHeader, failing the test if
// the column is missing so the assertions below stay decoupled from order.
func colIndex(t *testing.T, name string) int {
	t.Helper()
	for i, h := range csvHeader {
		if h == name {
			return i
		}
	}
	t.Fatalf("no %q column in csvHeader", name)
	return -1
}

// TestCSV_HeaderThenRow confirms the writer emits the fixed header first, then
// one row per finding, with the row's cells matching the finding's fields.
func TestCSV_HeaderThenRow(t *testing.T) {
	recs := runCSV(t, finding.Finding{
		Subdomain:  "dev.example.com",
		Vector:     finding.VectorCNAME,
		Service:    "AWS/S3",
		Confidence: finding.Confirmed,
		CNAME:      "x.s3.amazonaws.com",
		Scheme:     "https",
		Timestamp:  fixedTime,
	})

	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (header + 1 row)", len(recs))
	}
	for i, h := range csvHeader {
		if recs[0][i] != h {
			t.Errorf("header[%d] = %q, want %q", i, recs[0][i], h)
		}
	}

	row := recs[1]
	want := map[string]string{
		"subdomain":  "dev.example.com",
		"vector":     "cname",
		"confidence": "CONFIRMED",
		"service":    "AWS/S3",
		"target":     "x.s3.amazonaws.com",
		"scheme":     "https",
	}
	for col, exp := range want {
		if got := row[colIndex(t, col)]; got != exp {
			t.Errorf("column %q = %q, want %q", col, got, exp)
		}
	}
}

// TestCSV_EmptyScanEmitsHeaderOnly confirms that a scan with no findings still
// produces a valid header-only CSV, so a downstream importer never chokes on an
// empty file.
func TestCSV_EmptyScanEmitsHeaderOnly(t *testing.T) {
	recs := runCSV(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1 (header only)", len(recs))
	}
	if len(recs[0]) != len(csvHeader) {
		t.Fatalf("header has %d columns, want %d", len(recs[0]), len(csvHeader))
	}
}

// TestCSV_TargetColumnPerVector confirms each vector's identifying datum lands
// in the single flat `target` column, including the space-joined multi-host
// vectors (NS, MX) and the composed DKIM cell.
func TestCSV_TargetColumnPerVector(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want string
	}{
		{"cname", finding.Finding{Vector: finding.VectorCNAME, CNAME: "x.s3.amazonaws.com"}, "x.s3.amazonaws.com"},
		{"spf", finding.Finding{Vector: finding.VectorSPF, SPFInclude: "claimable.net"}, "claimable.net"},
		{"spf-lookup-limit", finding.Finding{Vector: finding.VectorSPF, SPFLookups: 12}, "12 DNS lookups (permerror)"},
		{"ns", finding.Finding{Vector: finding.VectorNS, Nameservers: []string{"ns1.gone.net", "ns2.gone.net"}}, "ns1.gone.net ns2.gone.net"},
		{"mx", finding.Finding{Vector: finding.VectorMX, MXHosts: []string{"mail.gone.net"}}, "mail.gone.net"},
		{"dkim", finding.Finding{Vector: finding.VectorDKIM, DKIMSelector: "s1", CNAME: "s1.domainkey.gone.sendgrid.net"}, "s1._domainkey -> s1.domainkey.gone.sendgrid.net"},
		{"dmarc", finding.Finding{Vector: finding.VectorDMARC, DMARCURI: "reports.gone.net"}, "reports.gone.net"},
		{"axfr", finding.Finding{Vector: finding.VectorAXFR, Service: "ns1.example.com", Nameservers: []string{"ns1.example.com"}}, "ns1.example.com"},
		{"bimi", finding.Finding{Vector: finding.VectorBIMI, Service: "default._bimi.example.com", BIMIURIHost: "images.gone.net"}, "images.gone.net (NXDOMAIN)"},
		{"dnssec", finding.Finding{Vector: finding.VectorDNSSEC, DSKeyTags: []uint16{12345}}, "orphaned DS key tag 12345 (no child DNSKEY)"},
		{"tlsrpt", finding.Finding{Vector: finding.VectorTLSRPT, Service: "_smtp._tls.example.com", TLSRPTURIHost: "reports.gone.net"}, "reports.gone.net (NXDOMAIN)"},
	}
	ti := colIndex(t, "target")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.Subdomain = "example.com"
			tc.f.Confidence = finding.Potential
			tc.f.Timestamp = fixedTime
			recs := runCSV(t, tc.f)
			if len(recs) != 2 {
				t.Fatalf("got %d records, want 2", len(recs))
			}
			if got := recs[1][ti]; got != tc.want {
				t.Errorf("vector %s: target = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestCSV_QuotesCommaBearingFields confirms RFC 4180 quoting kicks in when a
// field (e.g. an evidence string) contains a comma, so the row never splits
// into the wrong number of columns.
func TestCSV_QuotesCommaBearingFields(t *testing.T) {
	recs := runCSV(t, finding.Finding{
		Subdomain:  "example.com",
		Vector:     finding.VectorNS,
		Confidence: finding.Confirmed,
		Evidence:   "NXDOMAIN on ns1.gone.net, ns2.gone.net",
		Timestamp:  fixedTime,
	})
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if len(recs[1]) != len(csvHeader) {
		t.Fatalf("row split into %d columns, want %d — comma quoting failed", len(recs[1]), len(csvHeader))
	}
	if got := recs[1][colIndex(t, "evidence")]; got != "NXDOMAIN on ns1.gone.net, ns2.gone.net" {
		t.Errorf("evidence = %q, want the comma-bearing string intact", got)
	}
}

// TestCSV_TimestampIsRFC3339UTC confirms the timestamp column is a stable,
// importer-friendly RFC 3339 UTC string.
func TestCSV_TimestampIsRFC3339UTC(t *testing.T) {
	recs := runCSV(t, finding.Finding{
		Subdomain: "example.com", Vector: finding.VectorCNAME,
		Confidence: finding.Confirmed, CNAME: "x.s3.amazonaws.com",
		Timestamp: fixedTime,
	})
	got := recs[1][colIndex(t, "timestamp")]
	if !strings.HasSuffix(got, "Z") || !strings.Contains(got, "2026-05-28T12:00:00") {
		t.Errorf("timestamp = %q, want RFC 3339 UTC for fixedTime", got)
	}
}
