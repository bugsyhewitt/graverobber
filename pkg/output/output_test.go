package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// fixedTime keeps JSONL output deterministic across runs.
var fixedTime = time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

// TestJSONLWriter_RoundTrip confirms a finding serializes to a single JSON line
// that decodes back into an equal value, preserving every vector-specific field.
func TestJSONLWriter_RoundTrip(t *testing.T) {
	in := finding.Finding{
		Subdomain:  "reports.deleted-vendor.net",
		Vector:     finding.VectorDMARC,
		Confidence: finding.Potential,
		DMARCURI:   "reports.deleted-vendor.net",
		Evidence:   "DMARC rua/ruf report domain is NXDOMAIN",
		Timestamp:  fixedTime,
	}

	var buf bytes.Buffer
	w := NewJSONL(&buf)
	if err := w.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := buf.String()
	if strings.Count(strings.TrimRight(line, "\n"), "\n") != 0 {
		t.Fatalf("expected exactly one line, got %q", line)
	}

	var out finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Subdomain != in.Subdomain || out.Vector != in.Vector ||
		out.Confidence != in.Confidence || out.DMARCURI != in.DMARCURI {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

// TestJSONLWriter_OmitsEmptyVectorFields confirms a CNAME finding does not leak
// the email-vector fields (mx_hosts, dkim_selector, dmarc_uri) via omitempty.
func TestJSONLWriter_OmitsEmptyVectorFields(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONL(&buf)
	_ = w.Write(finding.Finding{
		Subdomain:  "dev.example.com",
		Vector:     finding.VectorCNAME,
		Service:    "AWS/S3",
		Confidence: finding.Confirmed,
		CNAME:      "x.s3.amazonaws.com",
		Timestamp:  fixedTime,
	})

	got := buf.String()
	for _, leaked := range []string{"mx_hosts", "dkim_selector", "dmarc_uri", "spf_include", "nameservers"} {
		if strings.Contains(got, leaked) {
			t.Errorf("CNAME finding leaked %q field: %s", leaked, got)
		}
	}
}

// TestTerminalWriter_RendersDetailForEveryVector is the regression guard for the
// R10 fix: before it, MX/DKIM/DMARC findings rendered with an empty detail in the
// default (non-JSON) terminal output. Every vector must surface its identifying
// datum on the human-readable line.
func TestTerminalWriter_RendersDetailForEveryVector(t *testing.T) {
	cases := []struct {
		name    string
		f       finding.Finding
		wantSub []string // substrings that must appear in the rendered line
	}{
		{
			name: "cname",
			f: finding.Finding{
				Subdomain: "dev.example.com", Vector: finding.VectorCNAME,
				Service: "AWS/S3", Confidence: finding.Confirmed,
				CNAME: "x.s3.amazonaws.com",
			},
			wantSub: []string{"dev.example.com", "AWS/S3", "x.s3.amazonaws.com"},
		},
		{
			name: "spf",
			f: finding.Finding{
				Subdomain: "example.com", Vector: finding.VectorSPF,
				Confidence: finding.Potential, SPFInclude: "claimable.net",
			},
			wantSub: []string{"example.com", "claimable.net"},
		},
		{
			name: "ns",
			f: finding.Finding{
				Subdomain: "example.com", Vector: finding.VectorNS,
				Confidence: finding.Confirmed, Nameservers: []string{"ns1.gone.net"},
			},
			wantSub: []string{"example.com", "ns1.gone.net"},
		},
		{
			name: "mx",
			f: finding.Finding{
				Subdomain: "example.com", Vector: finding.VectorMX,
				Confidence: finding.Confirmed, MXHosts: []string{"mail.gone.net"},
			},
			wantSub: []string{"example.com", "mail.gone.net"},
		},
		{
			name: "dkim",
			f: finding.Finding{
				Subdomain: "example.com", Vector: finding.VectorDKIM,
				Confidence: finding.Confirmed, DKIMSelector: "s1",
				CNAME: "s1.domainkey.gone.sendgrid.net",
			},
			wantSub: []string{"example.com", "s1", "s1.domainkey.gone.sendgrid.net"},
		},
		{
			name: "dmarc",
			f: finding.Finding{
				Subdomain: "example.com", Vector: finding.VectorDMARC,
				Confidence: finding.Potential, DMARCURI: "reports.gone.net",
			},
			wantSub: []string{"example.com", "reports.gone.net"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewTerminal(&buf, false) // colour off for plain-substring assertions
			if err := w.Write(tc.f); err != nil {
				t.Fatalf("Write: %v", err)
			}
			line := buf.String()
			for _, want := range tc.wantSub {
				if !strings.Contains(line, want) {
					t.Errorf("vector %s: rendered line %q missing %q", tc.name, strings.TrimSpace(line), want)
				}
			}
			// Every line must carry the vector tag and confidence tier.
			if !strings.Contains(line, string(tc.f.Vector)) {
				t.Errorf("vector %s: line missing vector tag: %q", tc.name, line)
			}
			if !strings.Contains(line, string(tc.f.Confidence)) {
				t.Errorf("vector %s: line missing confidence tier: %q", tc.name, line)
			}
		})
	}
}

// TestTerminalWriter_NoColourOmitsANSI confirms the non-tty path emits no escape
// sequences, so piped/file output stays clean.
func TestTerminalWriter_NoColourOmitsANSI(t *testing.T) {
	var buf bytes.Buffer
	w := NewTerminal(&buf, false)
	_ = w.Write(finding.Finding{
		Subdomain: "dev.example.com", Vector: finding.VectorCNAME,
		Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "x.s3.amazonaws.com",
	})
	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("colour=false output contained ANSI escapes: %q", buf.String())
	}
}

// TestTerminalWriter_ColourWrapsTiers confirms the colour path actually paints
// the tier and host (the inverse guard for the no-colour test).
func TestTerminalWriter_ColourWrapsTiers(t *testing.T) {
	var buf bytes.Buffer
	w := NewTerminal(&buf, true)
	_ = w.Write(finding.Finding{
		Subdomain: "dev.example.com", Vector: finding.VectorCNAME,
		Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "x.s3.amazonaws.com",
	})
	if !strings.Contains(buf.String(), "\033[") {
		t.Errorf("colour=true output had no ANSI escapes: %q", buf.String())
	}
}
