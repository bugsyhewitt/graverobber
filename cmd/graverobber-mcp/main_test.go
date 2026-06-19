package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bugsyhewitt/graverobber/internal/nmc"
	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
)

// testServer builds the fully-wired MCP server against the embedded fingerprint
// DB. It fails the test rather than the operator if wiring is broken.
func testServer(t *testing.T) (*nmc.Server, *fingerprints.DB) {
	t.Helper()
	db, err := fingerprints.Embedded()
	if err != nil {
		t.Fatalf("load embedded fingerprint DB: %v", err)
	}
	s, err := build()
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return s, db
}

// --- pure helper tests ------------------------------------------------------

// TestDistinctServices asserts the enumerator returns a sorted, de-duplicated,
// blank-free service set from a hand-built DB.
func TestDistinctServices(t *testing.T) {
	db, err := fingerprints.Load([]byte(`[
		{"service":"GitHub Pages","cname":["github.io"]},
		{"service":"AWS/S3","cname":["s3.amazonaws.com"]},
		{"service":"GitHub Pages","cname":["github.map.fastly.net"]},
		{"service":"","cname":["blank.example"]}
	]`))
	if err != nil {
		t.Fatalf("load DB: %v", err)
	}
	got := distinctServices(db)
	want := []string{"AWS/S3", "GitHub Pages"}
	if len(got) != len(want) {
		t.Fatalf("distinctServices = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("distinctServices = %v, want %v (sorted, deduped, no blanks)", got, want)
		}
	}
}

// TestBoundedErr asserts evidence strings are capped (§9/A5).
func TestBoundedErr(t *testing.T) {
	short := boundedErr(errString("brief"))
	if short != "brief" {
		t.Errorf("boundedErr(short) = %q, want %q", short, "brief")
	}
	big := boundedErr(errString(strings.Repeat("x", maxEvidence+500)))
	if len(big) > maxEvidence+len("…[truncated]") {
		t.Errorf("boundedErr did not bound a large string: len=%d", len(big))
	}
	if !strings.HasSuffix(big, "…[truncated]") {
		t.Errorf("boundedErr large string should be marked truncated, got suffix %q", big[len(big)-20:])
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestScanFindingToNMC asserts the engine→nmc mapping fills provenance and
// stays in the detected state with bounded, structured fields.
func TestScanFindingToNMC(t *testing.T) {
	s := nmc.New("graverobber", "9.9.9")
	f := finding.Finding{
		Subdomain:   "dangling.example.com",
		Vector:      finding.VectorCNAME,
		Service:     "GitHub Pages",
		Confidence:  finding.Likely,
		Fingerprint: "https://github.com/EdOverflow/can-i-take-over-xyz#github-pages",
		CNAME:       "ghost.github.io",
		Evidence:    "404 from GitHub Pages",
	}
	out := scanFindingToNMC(s, f)

	if out.State != nmc.StateDetected {
		t.Errorf("State = %q, want detected (scan is detect-only)", out.State)
	}
	if out.Active {
		t.Error("Active = true, want false (scan_takeover is safe)")
	}
	if out.Tool != "graverobber" || out.ToolVersion != "9.9.9" {
		t.Errorf("provenance not stamped: tool=%q ver=%q", out.Tool, out.ToolVersion)
	}
	if out.Verb != "scan_takeover" {
		t.Errorf("Verb = %q, want scan_takeover", out.Verb)
	}
	if out.Target != "dangling.example.com" {
		t.Errorf("Target = %q", out.Target)
	}
	if out.Surface != "GitHub Pages" {
		t.Errorf("Surface = %q, want GitHub Pages", out.Surface)
	}
	if out.Raw["confidence"] != "LIKELY" || out.Raw["cname"] != "ghost.github.io" {
		t.Errorf("raw provenance wrong: %#v", out.Raw)
	}
}

// --- handler-level tests (direct invocation) --------------------------------

// TestScanTakeoverRejectsEmptyTargets asserts a no-target call is a PROTOCOL
// error (Appendix D), not a finding.
func TestScanTakeoverRejectsEmptyTargets(t *testing.T) {
	s, db := testServer(t)
	h := scanTakeover(s, db)
	_, _, err := h(context.Background(), &mcp.CallToolRequest{}, ScanIn{Targets: nil})
	if err == nil {
		t.Fatal("scan_takeover with no targets must return a protocol error")
	}
}

// TestScanTakeoverRejectsBadConfidence asserts an invalid min_confidence is a
// protocol error.
func TestScanTakeoverRejectsBadConfidence(t *testing.T) {
	s, db := testServer(t)
	h := scanTakeover(s, db)
	_, _, err := h(context.Background(), &mcp.CallToolRequest{}, ScanIn{
		Targets:       []string{"example.com"},
		MinConfidence: "definitely",
	})
	if err == nil {
		t.Fatal("scan_takeover with invalid min_confidence must return a protocol error")
	}
}

// TestConfirmTakeoverGatedWithoutConsent is the load-bearing safety assertion
// (D6/A3): the active verb refuses to act without confirm=true and returns the
// exact gate error, before any network I/O.
func TestConfirmTakeoverGatedWithoutConsent(t *testing.T) {
	s, _ := testServer(t)
	h := confirmTakeover(s)
	_, _, err := h(context.Background(), &mcp.CallToolRequest{}, ConfirmIn{
		Target:  "dangling.example.com",
		Service: "GitHub Pages",
		CNAME:   "ghost.github.io",
		Confirm: false, // no consent
	})
	if err == nil {
		t.Fatal("confirm_takeover without confirm=true must refuse (D6)")
	}
	if err != nmc.ErrActiveNotAuthorized {
		t.Fatalf("confirm_takeover refusal = %v, want ErrActiveNotAuthorized", err)
	}
}

// TestConfirmTakeoverRequiresTargetAndCNAME asserts argument validation runs
// after the consent gate but still as a protocol error.
func TestConfirmTakeoverRequiresTargetAndCNAME(t *testing.T) {
	s, _ := testServer(t)
	h := confirmTakeover(s)
	_, _, err := h(context.Background(), &mcp.CallToolRequest{}, ConfirmIn{
		Confirm: true,
		Service: "GitHub Pages",
		// Target and CNAME deliberately empty.
	})
	if err == nil {
		t.Fatal("confirm_takeover with empty target/cname must return a protocol error")
	}
}

// TestListFingerprints asserts the enumerator returns a non-empty, consistent
// service set from the embedded DB.
func TestListFingerprints(t *testing.T) {
	_, db := testServer(t)
	h := listFingerprints(db)
	_, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("list_fingerprints error: %v", err)
	}
	if out.Count == 0 || out.Count != len(out.Services) {
		t.Fatalf("list_fingerprints count=%d services=%d (want equal and non-zero)", out.Count, len(out.Services))
	}
}

// TestFingerprintsJSONResource asserts the read-only resource serialises the DB
// to valid JSON.
func TestFingerprintsJSONResource(t *testing.T) {
	_, db := testServer(t)
	body, err := fingerprintsJSON(db)
	if err != nil {
		t.Fatalf("fingerprintsJSON: %v", err)
	}
	var entries []fingerprints.Fingerprint
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("resource body is not valid JSON: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("resource body has no fingerprint entries")
	}
}
