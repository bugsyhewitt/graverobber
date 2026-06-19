package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bugsyhewitt/graverobber/internal/nmc"
)

// connectInProc wires the built server to a client over an in-memory transport
// and returns an initialized client session. This is the headless Tier-1/Tier-3
// harness: no subprocess, no network, no GUI — an agent drives the real server
// in-process. The session and server are torn down via t.Cleanup.
func connectInProc(t *testing.T) *mcp.ClientSession {
	t.Helper()
	srv, err := build()
	if err != nil {
		t.Fatalf("build server: %v", err)
	}

	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()

	// Servers must connect before clients (the client initializes the session).
	serverSess, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSess.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "graverobber-smoke", Version: "0.1.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect (initialize): %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// TestSmoke_InitializeAndListTools is the Tier-1 conformance check (§11): the
// initialize handshake succeeds and tools/list returns exactly the §7
// graverobber verb surface with well-formed input schemas.
func TestSmoke_InitializeAndListTools(t *testing.T) {
	cs := connectInProc(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}

	got := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		got[tl.Name] = tl
	}
	for _, want := range []string{"scan_takeover", "confirm_takeover", "list_fingerprints"} {
		tl, ok := got[want]
		if !ok {
			t.Errorf("tools/list missing %q (have %v)", want, keys(got))
			continue
		}
		if tl.InputSchema == nil {
			t.Errorf("tool %q has no input schema", want)
		}
	}
}

// TestSmoke_ConfirmGatedOverProtocol asserts the D6 gate is visible to an agent
// over the wire: calling confirm_takeover without confirm=true comes back as an
// IsError result whose content cites the D6 consent requirement (Appendix D:
// it's a protocol error the agent must self-correct, not a finding).
func TestSmoke_ConfirmGatedOverProtocol(t *testing.T) {
	cs := connectInProc(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "confirm_takeover",
		Arguments: map[string]any{
			"target":  "dangling.example.com",
			"service": "GitHub Pages",
			"cname":   "ghost.github.io",
			// confirm omitted → false
		},
	})
	if err != nil {
		t.Fatalf("call confirm_takeover: unexpected transport error: %v", err)
	}
	if !res.IsError {
		t.Fatal("confirm_takeover without consent must surface IsError=true (D6)")
	}
	if !strings.Contains(contentText(res), "D6") {
		t.Errorf("gate error should cite D6, got content: %q", contentText(res))
	}
}

// TestSmoke_DetectThenConfirm is the Tier-3 acceptance bar adapted to the real
// engine (§11/A10): an agent drives scan_takeover then confirm_takeover{confirm:true}
// over MCP against a controlled, network-free target and gets back well-formed,
// schema-conformant findings the whole way. We use RFC 5737 / RFC 2606
// documentation names so the engine performs no real exploitation and the test
// is hermetic: confirm runs its active code path (the gate is open) and returns
// a structured finding whose provenance proves an active path was used.
func TestSmoke_DetectThenConfirm(t *testing.T) {
	cs := connectInProc(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1) scan_takeover — safe, returns structured content (possibly zero
	//    findings for a documentation host, which is itself a valid result).
	scanRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan_takeover",
		Arguments: map[string]any{"targets": []string{"takeover-test.example"}},
	})
	if err != nil {
		t.Fatalf("call scan_takeover: %v", err)
	}
	if scanRes.IsError {
		t.Fatalf("scan_takeover returned IsError: %s", contentText(scanRes))
	}
	var scanOut ScanOut
	decodeStructured(t, scanRes, &scanOut)
	for _, f := range scanOut.Findings {
		assertFindingShape(t, f, "scan_takeover", false)
		if f.State != nmc.StateDetected {
			t.Errorf("scan finding state = %q, want detected", f.State)
		}
	}

	// 2) confirm_takeover{confirm:true} — the ACTIVE path, gate open. Against a
	//    documentation CNAME the read-only verifier returns no definitive
	//    unclaimed signal, so we expect a structured finding in the
	//    not_vulnerable (or error) state with active=true provenance. The point
	//    of the acceptance bar is that the agent drove detect→confirm over MCP
	//    and got a schema-conformant, active-stamped finding back.
	confRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "confirm_takeover",
		Arguments: map[string]any{
			"target":  "takeover-test.example",
			"service": "GitHub Pages",
			"cname":   "takeover-test.example", // not a real github.io target → no claim signal
			"confirm": true,
		},
	})
	if err != nil {
		t.Fatalf("call confirm_takeover{confirm:true}: %v", err)
	}
	if confRes.IsError {
		t.Fatalf("confirm_takeover with consent returned IsError: %s", contentText(confRes))
	}
	var confOut nmc.Finding
	decodeStructured(t, confRes, &confOut)
	assertFindingShape(t, confOut, "confirm_takeover", true)
	switch confOut.State {
	case nmc.StateConfirmed, nmc.StateNotVulnerable, nmc.StateError:
		// all valid outcomes of an active confirmation probe
	default:
		t.Errorf("confirm_takeover state = %q, want confirmed|not_vulnerable|error", confOut.State)
	}

	// 3) list_fingerprints — the enumerator an agent uses to plan.
	listRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_fingerprints"})
	if err != nil {
		t.Fatalf("call list_fingerprints: %v", err)
	}
	if listRes.IsError {
		t.Fatalf("list_fingerprints returned IsError: %s", contentText(listRes))
	}
	var listOut ListOut
	decodeStructured(t, listRes, &listOut)
	if listOut.Count == 0 {
		t.Error("list_fingerprints returned an empty service set")
	}
}

// --- smoke helpers ----------------------------------------------------------

// assertFindingShape checks the interim Finding contract (§4.1): required
// schema/tool/version/verb/target/state and the active provenance flag (D11).
func assertFindingShape(t *testing.T, f nmc.Finding, wantVerb string, wantActive bool) {
	t.Helper()
	if f.Schema != nmc.SchemaID {
		t.Errorf("finding schema = %q, want %q", f.Schema, nmc.SchemaID)
	}
	if f.Tool != "graverobber" {
		t.Errorf("finding tool = %q, want graverobber", f.Tool)
	}
	if f.ToolVersion == "" {
		t.Error("finding tool_version is empty (D11)")
	}
	if f.Verb != wantVerb {
		t.Errorf("finding verb = %q, want %q", f.Verb, wantVerb)
	}
	if f.Target == "" {
		t.Error("finding target is empty (required)")
	}
	if f.State == "" {
		t.Error("finding state is empty (required)")
	}
	if f.Active != wantActive {
		t.Errorf("finding active = %v, want %v (D11 provenance)", f.Active, wantActive)
	}
	if _, err := time.Parse(time.RFC3339, f.TS); err != nil {
		t.Errorf("finding ts %q is not RFC3339: %v", f.TS, err)
	}
}

// decodeStructured round-trips a tool result's StructuredContent into v. The
// SDK delivers StructuredContent as a decoded any (map), so we re-marshal and
// unmarshal into the concrete output type — exactly what a typed client does.
func decodeStructured(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatal("tool result has no structuredContent (D8)")
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal structuredContent into %T: %v", v, err)
	}
}

// contentText concatenates the text content blocks of a result for assertions.
func contentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
