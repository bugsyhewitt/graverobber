package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestStdoutIsPureJSONRPC is the Tier-2 stdout-hygiene gate (§11, D7/A2): it
// builds the graverobber-mcp binary, launches it under the stdio transport,
// sends a single initialize frame, and asserts the first line on stdout parses
// as JSON-RPC. A stray banner, log line, print, or panic traceback on stdout
// would corrupt the framing and fail this test — which is exactly the dominant
// stdio failure mode this guards against.
//
// The server is launched headless (stdio, no GUI, no network) and killed on a
// strict deadline so it can never become a runaway.
func TestStdoutIsPureJSONRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-build stdout test in -short mode")
	}

	bin := filepath.Join(t.TempDir(), "graverobber-mcp")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	// Build the server binary from this package.
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build graverobber-mcp: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin) // stdio transport is the default
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	// Diagnostics MUST go to stderr; route the child's stderr to the test log so
	// a contaminating log line is visible but does not pollute the stdout check.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Send a minimal, well-formed initialize request at protocol 2025-11-25.
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "stdout-clean-test", "version": "0"},
		},
	}
	enc, _ := json.Marshal(initReq)
	if _, err := stdin.Write(append(enc, '\n')); err != nil {
		t.Fatalf("write initialize: %v", err)
	}

	// Read the first line off stdout in a goroutine so a hung server hits the
	// test deadline instead of blocking forever.
	type lineResult struct {
		line []byte
		err  error
	}
	ch := make(chan lineResult, 1)
	go func() {
		r := bufio.NewReader(stdout)
		line, err := r.ReadBytes('\n')
		ch <- lineResult{line, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil && len(res.line) == 0 {
			t.Fatalf("reading stdout: %v (no bytes — server may have failed to start)", res.err)
		}
		// The single hard assertion: the first stdout line is valid JSON. Any
		// non-JSON byte (banner/log/print/traceback) makes this fail.
		var probe map[string]any
		if err := json.Unmarshal(trimNewline(res.line), &probe); err != nil {
			t.Fatalf("stdout line is not valid JSON-RPC (D7/A2 violation): %v\nline=%q", err, res.line)
		}
		if probe["jsonrpc"] != "2.0" {
			t.Errorf("stdout frame missing jsonrpc=2.0: %v", probe)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server produced no stdout frame within deadline (hung or contaminated)")
	}
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
