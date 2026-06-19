package engine

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// TestPromoteNS lifts a dangling-NS detector finding into the critical
// takeover.ns class (D7): rule takeover.ns.<provider>, severity critical, state
// detected — and is a no-op on a non-NS finding (A8/A9 guard).
func TestPromoteNS(t *testing.T) {
	in := finding.Finding{
		Subdomain:   "zone.example.com",
		Vector:      finding.VectorNS,
		Service:     "AWS Route 53",
		Confidence:  finding.Confirmed,
		Nameservers: []string{"ns-1.awsdns-00.org", "ns-2.awsdns-00.co.uk"},
		Evidence:    "all nameservers returned SERVFAIL/REFUSED for zone SOA",
	}
	out := PromoteNS(in)

	if out.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical (whole-zone takeover)", out.Severity)
	}
	if out.State != finding.StateDetected {
		t.Errorf("state = %q, want detected", out.State)
	}
	if out.Rule != "takeover.ns.aws-route-53" {
		t.Errorf("rule = %q, want takeover.ns.aws-route-53", out.Rule)
	}
	// Detection certainty must be preserved (only the takeover classification is
	// added).
	if out.Confidence != finding.Confirmed {
		t.Errorf("confidence = %q, want CONFIRMED (preserved)", out.Confidence)
	}
	if !IsNSTakeover(out) {
		t.Error("IsNSTakeover should report true for the promoted finding")
	}
}

// TestPromoteNS_NotNS: PromoteNS must not touch a CNAME finding (A8: do not
// flatten/confuse the classes).
func TestPromoteNS_NotNS(t *testing.T) {
	in := finding.Finding{
		Subdomain:  "assets.example.com",
		Vector:     finding.VectorCNAME,
		Service:    "GitHub Pages",
		Severity:   finding.SeverityHigh,
		Rule:       "takeover.github-pages",
		Confidence: finding.Likely,
	}
	out := PromoteNS(in)
	if out.Severity != finding.SeverityHigh || out.Rule != "takeover.github-pages" {
		t.Errorf("PromoteNS must be a no-op on a non-NS finding, got severity=%q rule=%q", out.Severity, out.Rule)
	}
	if IsNSTakeover(out) {
		t.Error("a CNAME finding is not an NS takeover")
	}
}

// TestNSRule covers the rule slugging and the unknown-provider fallback.
func TestNSRule(t *testing.T) {
	cases := map[string]string{
		"AWS Route 53":      "takeover.ns.aws-route-53",
		"Google Cloud DNS":  "takeover.ns.google-cloud-dns",
		"Azure DNS":         "takeover.ns.azure-dns",
		"":                  "takeover.ns.unknown",
		"NS1 (ns)":          "takeover.ns.ns1",
		"DigitalOcean (NS)": "takeover.ns.digitalocean",
	}
	for in, want := range cases {
		if got := NSRule(in); got != want {
			t.Errorf("NSRule(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNSBlastRadius confirms the whole-zone blast radius names the categorical
// escalations (email, wildcards, sub-delegations) that make NS critical.
func TestNSBlastRadius(t *testing.T) {
	for _, want := range []string{"whole-zone", "MX", "wildcard", "sub-delegation"} {
		if !strings.Contains(strings.ToLower(NSBlastRadius), strings.ToLower(want)) {
			t.Errorf("NSBlastRadius missing %q: %q", want, NSBlastRadius)
		}
	}
}
