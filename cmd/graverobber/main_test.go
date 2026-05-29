package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// TestParseSelectors verifies the --selectors comma-list parser: trimming,
// lower-casing, blank-dropping, and the empty-input → nil (use defaults) case.
func TestParseSelectors(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"s1", []string{"s1"}},
		{"s1,s2", []string{"s1", "s2"}},
		{" S1 , Selector2 ", []string{"s1", "selector2"}},
		{"k1,,k2,", []string{"k1", "k2"}},
	}
	for _, c := range cases {
		got := parseSelectors(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseSelectors(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestRunScan_RejectsInvalidMinConfidence verifies runScan fails fast on a
// malformed --min-confidence value, before opening any I/O. A valid tier (and
// the empty default) must not trip this guard.
func TestRunScan_RejectsInvalidMinConfidence(t *testing.T) {
	bad := runScan(context.Background(), &cliFlags{target: "x.example.com", minConfidence: "high"})
	if bad == nil {
		t.Fatal("runScan with --min-confidence=high: want error, got nil")
	}
	if !strings.Contains(bad.Error(), "invalid --min-confidence") {
		t.Errorf("runScan error = %q, want it to mention invalid --min-confidence", bad.Error())
	}

	// A valid tier must pass the validation guard. We cannot run a full scan
	// without network, so we assert only that the error (if any) is NOT the
	// validation error — i.e. it got past the parse step.
	for _, tier := range []string{"", "confirmed", "LIKELY", " potential "} {
		err := runScan(context.Background(), &cliFlags{target: "", list: "/graverobber-nonexistent-list", minConfidence: tier})
		if err != nil && strings.Contains(err.Error(), "invalid --min-confidence") {
			t.Errorf("valid --min-confidence=%q tripped the validation guard: %v", tier, err)
		}
	}
}

// TestRunScan_RejectsConflictingFormats verifies runScan fails fast when more
// than one machine-output format is requested, before opening any I/O — they
// write incompatible documents to the same sink. Every pairwise combination of
// --json/--sarif/--csv must be rejected.
func TestRunScan_RejectsConflictingFormats(t *testing.T) {
	cases := []struct {
		name string
		f    cliFlags
	}{
		{"json+sarif", cliFlags{target: "x.example.com", json: true, sarif: true}},
		{"json+csv", cliFlags{target: "x.example.com", json: true, csv: true}},
		{"sarif+csv", cliFlags{target: "x.example.com", sarif: true, csv: true}},
		{"all-three", cliFlags{target: "x.example.com", json: true, sarif: true, csv: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runScan(context.Background(), &tc.f)
			if err == nil {
				t.Fatalf("runScan %s: want error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("runScan %s error = %q, want it to mention mutually exclusive", tc.name, err.Error())
			}
		})
	}
}

// TestScanSummary_EmptyPrintsCountOnly verifies a zero-finding scan still emits
// the bare count line and no breakdown — preserving the prior behaviour and
// keeping a clean scan from printing empty "by tier" / "by vector" lines.
func TestScanSummary_EmptyPrintsCountOnly(t *testing.T) {
	var s scanSummary
	var buf bytes.Buffer
	s.write(&buf)

	got := buf.String()
	if got != "graverobber: 0 finding(s)\n" {
		t.Errorf("empty summary = %q, want just the count line", got)
	}
	if strings.Contains(got, "by tier") || strings.Contains(got, "by vector") {
		t.Errorf("empty summary leaked a breakdown line: %q", got)
	}
}

// TestScanSummary_BreaksDownByTierAndVector verifies the breakdown counts each
// finding into the right tier and vector buckets and that the totals add up.
func TestScanSummary_BreaksDownByTierAndVector(t *testing.T) {
	var s scanSummary
	for _, f := range []finding.Finding{
		{Vector: finding.VectorCNAME, Confidence: finding.Confirmed},
		{Vector: finding.VectorCNAME, Confidence: finding.Likely},
		{Vector: finding.VectorNS, Confidence: finding.Confirmed},
		{Vector: finding.VectorSPF, Confidence: finding.Potential},
		{Vector: finding.VectorSPF, Confidence: finding.Potential},
	} {
		s.tally(f)
	}

	if s.total != 5 {
		t.Fatalf("total = %d, want 5", s.total)
	}

	var buf bytes.Buffer
	s.write(&buf)
	got := buf.String()

	for _, want := range []string{
		"graverobber: 5 finding(s)",
		"by tier:",
		"CONFIRMED=2", "LIKELY=1", "POTENTIAL=2",
		"by vector:",
		"cname=2", "ns=1", "spf=2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q missing %q", got, want)
		}
	}
}

// TestScanSummary_OmitsAbsentCategories verifies the breakdown lists only the
// tiers and vectors that actually occurred, so a single-vector scan stays
// uncluttered (no "mx=0", "dkim=0", etc.).
func TestScanSummary_OmitsAbsentCategories(t *testing.T) {
	var s scanSummary
	s.tally(finding.Finding{Vector: finding.VectorCNAME, Confidence: finding.Confirmed})

	var buf bytes.Buffer
	s.write(&buf)
	got := buf.String()

	for _, absent := range []string{"=0", "LIKELY", "POTENTIAL", "ns=", "spf=", "mx=", "dkim=", "dmarc="} {
		if strings.Contains(got, absent) {
			t.Errorf("single-finding summary %q should not contain %q", got, absent)
		}
	}
}

// TestScanSummary_BreakdownOrderIsStable verifies the tier breakdown reads
// strongest-first and the vector breakdown follows the detector pipeline order,
// regardless of the order findings were tallied in.
func TestScanSummary_BreakdownOrderIsStable(t *testing.T) {
	var s scanSummary
	// Tally in a deliberately scrambled order.
	for _, f := range []finding.Finding{
		{Vector: finding.VectorDMARC, Confidence: finding.Potential},
		{Vector: finding.VectorCNAME, Confidence: finding.Likely},
		{Vector: finding.VectorNS, Confidence: finding.Confirmed},
	} {
		s.tally(f)
	}

	var buf bytes.Buffer
	s.write(&buf)
	got := buf.String()

	if iC, iL, iP := strings.Index(got, "CONFIRMED"), strings.Index(got, "LIKELY"), strings.Index(got, "POTENTIAL"); !(iC < iL && iL < iP) {
		t.Errorf("tier order not strongest-first in %q (CONFIRMED@%d LIKELY@%d POTENTIAL@%d)", got, iC, iL, iP)
	}
	if iCname, iNs, iDmarc := strings.Index(got, "cname="), strings.Index(got, "ns="), strings.Index(got, "dmarc="); !(iCname < iNs && iNs < iDmarc) {
		t.Errorf("vector order not pipeline-order in %q (cname@%d ns@%d dmarc@%d)", got, iCname, iNs, iDmarc)
	}
}

// TestBoolCount guards the helper behind the format mutual-exclusion check.
func TestBoolCount(t *testing.T) {
	cases := []struct {
		in   []bool
		want int
	}{
		{nil, 0},
		{[]bool{false, false, false}, 0},
		{[]bool{true, false, false}, 1},
		{[]bool{true, true, false}, 2},
		{[]bool{true, true, true}, 3},
	}
	for _, tc := range cases {
		if got := boolCount(tc.in...); got != tc.want {
			t.Errorf("boolCount(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
