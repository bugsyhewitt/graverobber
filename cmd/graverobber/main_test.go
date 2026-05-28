package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
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
