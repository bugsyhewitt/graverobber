# Packet P20-01 — deviations from the packet, as built

The packet (`claude-code-p20-packet-01-mcp-interface.md`) was written against an
assumed repo state that differs from the actual `~/dev/necromancer` tree in a few
places. This file records the adaptations (packet §11 acceptance criterion 5 /
§14: record any engine that resisted clean adaptation, with the interim
decision). None of these block the packet's intent; each is the most defensible
mapping of the contract onto the real code.

## D-A1 — `necromancer-mcp` Go library already existed; vendored, not re-authored
The canonical Go backend (`necromancer-mcp/go/nmc`: `nmc.go`, `safety.go`,
`transport.go`, `nmc_test.go`) was already present and high-quality, matching
packet §4.2 with safe improvements (constant-time bearer compare, a banned
double-separator name rule, `AddResource`). Per that module's own `go.mod`
directive ("each tool vendors package nmc as its own `internal/nmc` copy kept
byte-identical to this canonical source"), graverobber vendors it at
`internal/nmc/` rather than depending across repos. The vendored copy is
byte-identical to the canonical source and carries the library's own test suite,
which runs as part of `go test ./...`.

## D-A2 — There is no `github.com/bugsyhewitt/necromancer-mcp` remote
Confirmed via `gh repo view`. The shared lib is therefore consumed by vendoring
(D-A1), which is exactly what the lib's `go.mod` prescribes and what keeps each
tool independently buildable/`go install`-able in CI. No standalone push of the
lib is possible or intended this lap.

## D-A3 — `confirm_takeover` uses the real `ServiceVerifier`, not a "canary token"
Packet §5 sketches `engine.Confirm(...)` that "serves a canary token and checks
reflection." graverobber's real engine has no such method. Its actual active
confirmation is `pkg/verifier.ServiceVerifier`, which performs **read-only**
service probes (S3 `NoSuchBucket` GET, GitHub Pages repo-existence GET, Azure
NXDOMAIN) and only ever upgrades a candidate `LIKELY → CONFIRMED`. This is a
strictly better fit for the suite safety posture ("confirming a takeover is in
scope; performing one is not") and maps cleanly onto the gated `confirm_takeover`
verb. The verb still gates on `confirm=true` (D6) and stamps `active=true`
provenance (D11). It never claims a resource.

## D-A4 — `scan_takeover` drives `pkg/scanner` (streaming), not `engine.Detect`
The real safe path is `scanner.New(db, opts).Run(ctx, targetsChan) <-chan
finding.Finding`. The handler feeds the targets on a closed channel and collects
the streamed findings, mapping each to an interim `nmc.Finding` in the `detected`
state. `min_confidence` is exposed as an optional argument backed by the engine's
`Options.MinConfidence` filter.

## D-A5 — exhumed is a **Go** tool, not Python (affects packet §4.3 / §6)
The packet's §6 reference server B and §4.3 Python backend assume exhumed is a
Python tool driven from `necromancer_mcp` (the Python lib). In the actual repo,
**exhumed is Go** (`cmd/exhumed/main.go`, `internal/{engine,detect,inject,...}`),
as are graverobber, seance, possession, and unearth. There is no Python tool in
the wave-1 set to host the Python backend.

**Decision for this lap:** deliver the highest-leverage, fully-real reference
server — graverobber (Go) — end to end (this PR), wrapping the genuine engine
with all three test tiers green including an in-process detect→confirm smoke run
and external MCP Inspector conformance. The exhumed MCP server, when built, will
follow the SUBPROCESS engine-adapter recipe (packet §6.1): exhumed already
supports `exhumed scan --output json` emitting `ScanResultJSON`, so its MCP
server shells out and maps that JSON to `nmc.Finding` — no 1000-line CLI
orchestration needs to be refactored into an in-process API this lap.

**Open question surfaced to Bugsy:** the Python `necromancer-mcp/py` backend has
no wave-1 consumer. Options: (a) build `py/` + a tiny Python example server now to
keep the cross-language contract honest and tested; (b) defer `py/` until a
Python tool (e.g. a future llmfuzzer-derived ouija) actually needs it. This is a
scope/judgment call (no money/brand/legal dimension) — recommended to Bugsy
rather than decided autonomously, since it changes the packet's two-language
deliverable shape.
