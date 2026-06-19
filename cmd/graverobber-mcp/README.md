# graverobber-mcp — MCP-native interface for graverobber

`graverobber-mcp` exposes graverobber's engine to an LLM agent over the
**Model Context Protocol (MCP)**. It is the **Go reference server** for the
`necromancer-mcp` contract (suite packet **P20-01**): the template every other
Go tool in the necromancer suite copies to become agent-callable.

The graverobber **CLI** (`cmd/graverobber`) and this **MCP server**
(`cmd/graverobber-mcp`) are two front ends over **one engine** —
`pkg/scanner`, `pkg/verifier`, `pkg/fingerprints`. The MCP layer reimplements no
detection logic; it validates input, calls the engine, and marshals the result
into a structured `Finding`.

---

## Tool surface

| MCP tool | Class | What it does |
|---|---|---|
| `scan_takeover` | **safe** | Detect candidate takeovers across the given targets (runs the real scanner). Returns one `Finding` per candidate in the `detected` state. |
| `confirm_takeover` | **active** `[A]` | Confirm a flagged candidate with a **read-only** service probe (S3 `NoSuchBucket` GET, GitHub Pages repo-existence GET, Azure NXDOMAIN). **Requires `confirm: true`.** Confirms a takeover; never claims the resource. |
| `list_fingerprints` | **safe** | Enumerate the distinct service fingerprints graverobber recognises (lets an agent plan before scanning). |

Plus a read-only **resource** — `fingerprints://can-i-take-over-xyz` — exposing
the full fingerprint database as JSON for direct inspection.

Tool names follow the suite verb taxonomy (`scan_*`, `confirm_*`, `list_*`) and
the `^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$` grammar with no repeated separators.

---

## Run it

```bash
make mcp                      # build bin/graverobber-mcp

# stdio (default — for Claude Code, a Pho3nix sidecar, or the MCP Inspector):
bin/graverobber-mcp

# Streamable HTTP, loopback (warehouse / remote orchestrator):
NMC_TRANSPORT=http NMC_BIND=127.0.0.1:9876 bin/graverobber-mcp
#   or: bin/graverobber-mcp --transport http --bind 127.0.0.1:9876

# Routable HTTP REQUIRES a bearer token (the server refuses otherwise):
bin/graverobber-mcp --transport http --bind 0.0.0.0:9876 --token "$NMC_TOKEN"
```

Transport is configuration, not code (env `NMC_TRANSPORT`/`NMC_BIND`/`NMC_TOKEN`,
overridable by `--transport`/`--bind`/`--token`). **Default is stdio.** Streamable
HTTP **binds loopback by default**; a routable bind without a token is rejected.

---

## Safety model (D-rules)

- **D6 — active is opt-in, per call.** `confirm_takeover` calls
  `nmc.MustActive(confirm)` as its first line and refuses without `confirm: true`.
  The refusal is an MCP protocol error the agent must self-correct (it is not a
  finding).
- **D7 — stdout is sacred.** Every diagnostic byte goes to **stderr**; stdout
  carries only JSON-RPC frames. The shared library routes the default logger to
  stderr; the `stdout_clean` test guards against regressions.
- **D9 / D10 — transport defaults safe.** stdio by default; Streamable HTTP is
  loopback-by-default and **requires a bearer token** on any routable bind.
- **D8 / D11 — structured, provenanced findings.** Every tool returns a typed
  `Finding` (so the SDK emits `structuredContent`) stamped with the tool name,
  version, the verb that produced it, and whether an active path was used.
- **Evidence is bounded** (≤ 2 KiB): the JSON-RPC channel is a control plane,
  not a file transfer.

---

## Add an MCP server to another Go tool in < 30 lines

The shared library (`internal/nmc`, vendored byte-identical from
`necromancer-mcp/go/nmc`) reduces a new tool's MCP front end to wiring:

```go
package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/bugsyhewitt/YOURTOOL/internal/nmc"
	"github.com/bugsyhewitt/YOURTOOL/pkg/engine" // your existing engine — DO NOT reimplement
)

type ScanIn struct{ Targets []string `json:"targets" jsonschema:"hosts to scan"` }
type ScanOut struct{ Findings []nmc.Finding `json:"findings"` }

func main() {
	s := nmc.New("yourtool", "1.0.0") // logger → stderr (D7); naming policy applied

	nmc.AddTool(s, "scan_thing", "Detect candidate issues (safe).",
		func(ctx context.Context, _ *mcp.CallToolRequest, in ScanIn) (*mcp.CallToolResult, ScanOut, error) {
			var out ScanOut
			for _, hit := range engine.Detect(ctx, in.Targets) { // call the engine
				f := s.Finding("scan_thing", hit.Target, nmc.StateDetected, false)
				f.Title, f.Evidence = hit.Title, hit.Evidence
				out.Findings = append(out.Findings, f)
			}
			return nil, out, nil
		})

	_ = s.Run(context.Background()) // stdio default; NMC_TRANSPORT=http for Streamable HTTP
}
```

For an **active** verb, add a `Confirm bool` argument and make
`nmc.MustActive(in.Confirm)` the handler's first statement.

---

## The three test tiers (`make mcp-test`)

A tool is not "MCP-ready" until all three pass:

1. **Protocol conformance** — `mcp_smoke_test.go` drives the server over an
   in-memory transport: `initialize` at protocol `2025-11-25`, `tools/list`
   returns the expected names with well-formed input schemas, and a safe call
   returns `structuredContent`. The MCP **Inspector** (`make mcp-inspect` /
   `make mcp-inspect-cli`) provides the external conformance view.
2. **Unit + hygiene** — `main_test.go` asserts the engine→`Finding` mapping,
   that `confirm_takeover` refuses without `confirm=true`, and argument
   validation; `stdout_clean_test.go` launches the built binary and asserts
   stdout is pure JSON-RPC (catches any stray print/banner/log on stdout). The
   vendored `internal/nmc` package carries the library-level tests (naming
   enforcement, `MustActive`, `Finding` prefill, loopback/token refusal).
3. **Detect → confirm smoke** — `TestSmoke_DetectThenConfirm` drives
   `scan_takeover` → `confirm_takeover{confirm:true}` → `list_fingerprints`
   over MCP and asserts schema-conformant, active-stamped findings end to end.
   Everything is **headless**: no GUI, no persistent server, in-memory transport,
   strict timeouts.

---

## Pho3nix catalog

`mcp.catalog.json` (repo root) is the manifest Pho3nix/gh0ulOS ingests: the bare
name (`graverobber`, no `gh0ul-` prefix), the stdio launch command, discovery
`tags`, the `active_tools` list (so the catalog can flag target-touching verbs),
and the full tool/resource surface.
