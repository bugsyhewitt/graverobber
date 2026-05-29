package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// decodeSARIF runs the given findings through a SarifWriter and decodes the
// emitted log into the minimal SARIF document types for assertion.
func decodeSARIF(t *testing.T, version string, findings ...finding.Finding) (sarifLog, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := NewSARIF(&buf, version)
	for _, f := range findings {
		if err := w.Write(f); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Unmarshal SARIF: %v\n%s", err, buf.String())
	}
	return log, buf.Bytes()
}

// TestSARIF_DocumentEnvelope confirms the top-level SARIF 2.1.0 envelope: the
// $schema, version, single run, and tool driver metadata are all present and
// well-formed so a Code Scanning upload is not rejected.
func TestSARIF_DocumentEnvelope(t *testing.T) {
	log, _ := decodeSARIF(t, "v1.2.3", finding.Finding{
		Subdomain: "dev.example.com", Vector: finding.VectorCNAME,
		Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "x.s3.amazonaws.com",
	})

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	d := log.Runs[0].Tool.Driver
	if d.Name != "graverobber" {
		t.Errorf("driver.name = %q, want graverobber", d.Name)
	}
	if d.Version != "v1.2.3" {
		t.Errorf("driver.version = %q, want v1.2.3", d.Version)
	}
	if d.InformationURI == "" {
		t.Error("driver.informationUri is empty")
	}
}

// TestSARIF_EmptyScanIsValid confirms a scan with zero findings still emits a
// valid SARIF log (empty results, empty rule catalogue) rather than nothing —
// Code Scanning treats a missing/invalid log as a failed upload.
func TestSARIF_EmptyScanIsValid(t *testing.T) {
	log, raw := decodeSARIF(t, "")
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if !bytes.Contains(raw, []byte(`"results"`)) {
		t.Errorf("empty log omitted results array:\n%s", raw)
	}
}

// TestSARIF_RuleCatalogueDedupesByVector confirms one rule per distinct vector,
// regardless of how many findings share a vector, and that each result's
// ruleIndex points at the matching rule in the catalogue.
func TestSARIF_RuleCatalogueDedupesByVector(t *testing.T) {
	log, _ := decodeSARIF(t, "",
		finding.Finding{Subdomain: "a.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "a.s3.amazonaws.com"},
		finding.Finding{Subdomain: "b.example.com", Vector: finding.VectorCNAME, Service: "GitHub Pages", Confidence: finding.Likely, CNAME: "b.github.io"},
		finding.Finding{Subdomain: "example.com", Vector: finding.VectorMX, Confidence: finding.Confirmed, MXHosts: []string{"mail.gone.net"}},
	)

	run := log.Runs[0]
	rules := run.Tool.Driver.Rules
	if len(rules) != 2 { // cname + mx, deduped
		t.Fatalf("rules = %d, want 2 (cname, mx)", len(rules))
	}
	// Every result's ruleIndex must resolve to a rule whose ID matches the
	// result's ruleId — the core SARIF index/ID consistency invariant.
	for _, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) {
			t.Fatalf("ruleIndex %d out of range for %d rules", r.RuleIndex, len(rules))
		}
		if rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d -> rule %q but result.ruleId = %q",
				r.RuleIndex, rules[r.RuleIndex].ID, r.RuleID)
		}
	}
}

// TestSARIF_LevelFromConfidence confirms CONFIRMED maps to error and the lower
// tiers map to warning, so Code Scanning severity tracks graverobber confidence.
func TestSARIF_LevelFromConfidence(t *testing.T) {
	cases := []struct {
		conf      finding.Confidence
		wantLevel string
	}{
		{finding.Confirmed, "error"},
		{finding.Likely, "warning"},
		{finding.Potential, "warning"},
	}
	for _, tc := range cases {
		t.Run(string(tc.conf), func(t *testing.T) {
			log, _ := decodeSARIF(t, "", finding.Finding{
				Subdomain: "x.example.com", Vector: finding.VectorCNAME,
				Service: "AWS/S3", Confidence: tc.conf, CNAME: "x.s3.amazonaws.com",
			})
			got := log.Runs[0].Results[0].Level
			if got != tc.wantLevel {
				t.Errorf("confidence %s -> level %q, want %q", tc.conf, got, tc.wantLevel)
			}
		})
	}
}

// TestSARIF_ResultLocationAndFingerprint confirms each result carries the
// subdomain as its location and a stable partial fingerprint keyed on
// (subdomain, vector) so re-scans dedupe instead of re-alerting.
func TestSARIF_ResultLocationAndFingerprint(t *testing.T) {
	log, _ := decodeSARIF(t, "", finding.Finding{
		Subdomain: "reports.gone.net", Vector: finding.VectorDMARC,
		Confidence: finding.Potential, DMARCURI: "reports.gone.net",
	})
	r := log.Runs[0].Results[0]

	if len(r.Locations) == 0 {
		t.Fatal("result has no locations")
	}
	if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "reports.gone.net" {
		t.Errorf("location URI = %q, want reports.gone.net", uri)
	}
	fp := r.PartialFingerprints["graverobberCandidate/v1"]
	if fp != "reports.gone.net|dmarc" {
		t.Errorf("partial fingerprint = %q, want reports.gone.net|dmarc", fp)
	}
}

// TestSARIF_MessageSurfacesVectorDetail confirms the result message carries the
// vector-specific dangling target for every vector, mirroring the terminal
// writer's detail rendering so a reviewer sees the evidence in the alert body.
func TestSARIF_MessageSurfacesVectorDetail(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want string
	}{
		{"cname", finding.Finding{Subdomain: "a.example.com", Vector: finding.VectorCNAME, Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "a.s3.amazonaws.com"}, "a.s3.amazonaws.com"},
		{"spf", finding.Finding{Subdomain: "example.com", Vector: finding.VectorSPF, Confidence: finding.Potential, SPFInclude: "claimable.net"}, "claimable.net"},
		{"ns", finding.Finding{Subdomain: "example.com", Vector: finding.VectorNS, Confidence: finding.Confirmed, Nameservers: []string{"ns1.gone.net"}}, "ns1.gone.net"},
		{"mx", finding.Finding{Subdomain: "example.com", Vector: finding.VectorMX, Confidence: finding.Confirmed, MXHosts: []string{"mail.gone.net"}}, "mail.gone.net"},
		{"dkim", finding.Finding{Subdomain: "example.com", Vector: finding.VectorDKIM, Confidence: finding.Confirmed, DKIMSelector: "s1", CNAME: "s1.domainkey.gone.sendgrid.net"}, "s1.domainkey.gone.sendgrid.net"},
		{"dmarc", finding.Finding{Subdomain: "example.com", Vector: finding.VectorDMARC, Confidence: finding.Potential, DMARCURI: "reports.gone.net"}, "reports.gone.net"},
		{"axfr", finding.Finding{Subdomain: "example.com", Vector: finding.VectorAXFR, Confidence: finding.Confirmed, Service: "ns1.example.com", Nameservers: []string{"ns1.example.com"}, LeakedHosts: []string{"admin.example.com"}}, "ns1.example.com"},
		{"bimi", finding.Finding{Subdomain: "example.com", Vector: finding.VectorBIMI, Confidence: finding.Potential, Service: "default._bimi.example.com", BIMIURIHost: "images.gone.net"}, "images.gone.net"},
		{"dnssec", finding.Finding{Subdomain: "example.com", Vector: finding.VectorDNSSEC, Confidence: finding.Potential, DSKeyTags: []uint16{12345}}, "12345"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := decodeSARIF(t, "", tc.f)
			msg := log.Runs[0].Results[0].Message.Text
			if !strings.Contains(msg, tc.want) {
				t.Errorf("vector %s: message %q missing %q", tc.name, msg, tc.want)
			}
			if !strings.Contains(msg, string(tc.f.Vector)) {
				t.Errorf("vector %s: message %q missing vector tag", tc.name, msg)
			}
		})
	}
}

// TestSARIF_RuleIDNamespaced confirms rule IDs are namespaced under graverobber/
// so they never collide with other tools' rules in a multi-tool Code Scanning
// configuration.
func TestSARIF_RuleIDNamespaced(t *testing.T) {
	log, _ := decodeSARIF(t, "", finding.Finding{
		Subdomain: "x.example.com", Vector: finding.VectorCNAME,
		Service: "AWS/S3", Confidence: finding.Confirmed, CNAME: "x.s3.amazonaws.com",
	})
	id := log.Runs[0].Tool.Driver.Rules[0].ID
	if !strings.HasPrefix(id, "graverobber/") {
		t.Errorf("rule ID %q not namespaced under graverobber/", id)
	}
}
