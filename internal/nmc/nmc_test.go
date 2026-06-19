package nmc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Short aliases for the SDK handler request/result types, used only to keep the
// test handler signatures readable.
type (
	callToolReq = mcp.CallToolRequest
	callToolRes = mcp.CallToolResult
)

// TestValidName asserts the D5 naming policy: the base grammar plus the
// double-separator ban (Appendix B.2). This is the registration-time gate that
// AddTool enforces with a panic.
func TestValidName(t *testing.T) {
	ok := []string{"scan_lfi", "confirm-takeover", "a", "list_fingerprints", "read_file", "scan_rfi", "a1", "find_origin"}
	bad := []string{
		"Scan",      // uppercase
		"_x",        // leading separator
		"x_",        // trailing separator
		"scan lfi",  // space
		"scan/lfi",  // slash
		"scan.x",    // dot
		"scan__2",   // double underscore (banned, A4)
		"scan--rfi", // double hyphen (banned)
		"scan_-x",   // mixed double separator (banned)
		"",          // empty
		"-x",        // leading hyphen
		"x-",        // trailing hyphen
	}
	for _, n := range ok {
		if !validName(n) {
			t.Errorf("validName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validName(n) {
			t.Errorf("validName(%q) = true, want false", n)
		}
	}
}

// TestAddToolPanicsOnBadName asserts AddTool fails fast (panics at startup, A4)
// for a structurally illegal name rather than deferring the error to request time.
func TestAddToolPanicsOnBadName(t *testing.T) {
	type In struct{}
	type Out struct{}
	s := New("paniccheck", "0.0.0")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("AddTool with an illegal name must panic")
		}
	}()
	AddTool(s, "Bad Name", "desc", func(context.Context, *callToolReq, In) (*callToolRes, Out, error) {
		return nil, Out{}, nil
	})
}

// TestAddToolAcceptsGoodName asserts a legal name registers without panicking.
func TestAddToolAcceptsGoodName(t *testing.T) {
	type In struct {
		Target string `json:"target"`
	}
	type Out struct {
		Findings []Finding `json:"findings"`
	}
	s := New("okcheck", "0.0.0")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AddTool with a legal name must not panic, got %v", r)
		}
	}()
	AddTool(s, "scan_takeover", "desc", func(context.Context, *callToolReq, In) (*callToolRes, Out, error) {
		return nil, Out{}, nil
	})
}

// TestMustActive asserts the D6 chokepoint: refuse when active=false, allow when true.
func TestMustActive(t *testing.T) {
	if err := MustActive(false); err == nil {
		t.Fatal("MustActive(false) must return an error")
	}
	if err := MustActive(false); err != ErrActiveNotAuthorized {
		t.Fatalf("MustActive(false) = %v, want ErrActiveNotAuthorized", err)
	}
	if err := MustActive(true); err != nil {
		t.Fatalf("MustActive(true) = %v, want nil", err)
	}
}

// TestFindingPrefill asserts Finding pre-fills schema/tool/version/ts (D11) and
// carries the four required-by-policy fields through.
func TestFindingPrefill(t *testing.T) {
	s := New("graverobber", "1.0.1")
	before := time.Now().UTC().Add(-time.Second)
	f := s.Finding("confirm_takeover", "assets.example.com", StateConfirmed, true)

	if f.Schema != SchemaID {
		t.Errorf("Schema = %q, want %q", f.Schema, SchemaID)
	}
	if f.Tool != "graverobber" {
		t.Errorf("Tool = %q, want graverobber", f.Tool)
	}
	if f.ToolVersion != "1.0.1" {
		t.Errorf("ToolVersion = %q, want 1.0.1", f.ToolVersion)
	}
	if f.Verb != "confirm_takeover" {
		t.Errorf("Verb = %q", f.Verb)
	}
	if f.Target != "assets.example.com" {
		t.Errorf("Target = %q", f.Target)
	}
	if f.State != StateConfirmed {
		t.Errorf("State = %q, want %q", f.State, StateConfirmed)
	}
	if !f.Active {
		t.Error("Active = false, want true")
	}
	ts, err := time.Parse(time.RFC3339, f.TS)
	if err != nil {
		t.Fatalf("TS %q is not RFC3339: %v", f.TS, err)
	}
	if ts.Before(before) {
		t.Errorf("TS %v is implausibly old", ts)
	}
}

// TestIsLoopback covers the bind classifier that gates the D10 token requirement.
func TestIsLoopback(t *testing.T) {
	loop := []string{"127.0.0.1:9876", "localhost:9876", "[::1]:9876", "127.0.0.1", "localhost", ""}
	routable := []string{"0.0.0.0:9876", "192.168.1.10:9876", "10.0.0.5:8080", "100.68.209.55:9876"}
	for _, b := range loop {
		if !isLoopback(b) {
			t.Errorf("isLoopback(%q) = false, want true", b)
		}
	}
	for _, b := range routable {
		if isLoopback(b) {
			t.Errorf("isLoopback(%q) = true, want false", b)
		}
	}
}

// TestRunHTTPRefusesRoutableWithoutToken asserts D10: a routable bind with no
// bearer token is refused before the listener is ever opened.
func TestRunHTTPRefusesRoutableWithoutToken(t *testing.T) {
	s := New("d10check", "0.0.0")
	err := s.RunHTTP(context.Background(), "0.0.0.0:0", "")
	if err == nil {
		t.Fatal("RunHTTP on a routable bind without a token must return an error (D10)")
	}
	if !strings.Contains(err.Error(), "D10") {
		t.Errorf("error should cite D10, got %q", err.Error())
	}
}

// TestRunHTTPLoopbackStartsAndStops asserts a loopback bind with no token starts
// and then shuts down cleanly when the context is cancelled (no D10 trip, no hang).
func TestRunHTTPLoopbackStartsAndStops(t *testing.T) {
	s := New("httpcheck", "0.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.RunHTTP(ctx, "127.0.0.1:0", "") }()
	// Give the listener a moment to come up, then cancel.
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunHTTP returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunHTTP did not return after context cancel (hung)")
	}
}

// TestRedactSecret asserts credential redaction never echoes a recoverable value.
func TestRedactSecret(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"abcd":                 "••••[len=4]",
		"AKIAIOSFODNN7EXAMPLE": "AKIA…[len=20]",
		"ghp_1234567890":       "ghp_…[len=14]",
	}
	for in, want := range cases {
		if got := RedactSecret(in); got != want {
			t.Errorf("RedactSecret(%q) = %q, want %q", in, got, want)
		}
		// Hard invariant: the full secret must never survive redaction (except the
		// trivial empty case).
		if in != "" && len(in) > 4 && strings.Contains(RedactSecret(in), in) {
			t.Errorf("RedactSecret leaked the full secret for %q", in)
		}
	}
}
