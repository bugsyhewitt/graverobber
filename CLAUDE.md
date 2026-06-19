# graverobber — agent notes

graverobber is a library-first Go subdomain-takeover scanner. All detection logic
lives in `pkg/`; `cmd/graverobber` is a thin CLI wrapper. Leaf package `finding`
imports only the standard library (every other package depends on it). Tests are
per-file, table-driven, and use injectable seams (resolver/HTTP/TLS stubs) so the
suite runs without real network where possible. Run the ship-gate with
`go test ./...` (or `make test`).

> Note: two scanner tests (`TestRun_MinConfidenceFiltersWeakerFindings`,
> `TestRun_SecondRunDeduplicationIsIndependentOfFirst`) make real DNS/HTTP calls
> against `example.com`-class hosts and can flake under network latency in a
> sandbox; they pass on a stable network. They are unrelated to the takeover
> feature.

## Takeover confirmation (Packet 07) — see [`TAKEOVER.md`](TAKEOVER.md)

The headline capability beyond fingerprint detection: **multi-signal detection**
and **safe claim-confirmation**.

- **`pkg/engine`** — multi-signal detector. `Detect` reports `detected` only on a
  fingerprint match PLUS an independent unclaimed-backend signal (NXDOMAIN on the
  CNAME target, or a TLS mismatch). A bare fingerprint match is suppressed (the
  false-positive guard, D2). **`TestFingerprintAloneIsNotDetected` is a
  release-blocker** — keep it green. Note: "ends at a provider edge" is NOT an
  independent signal (a live owned site ends at the same edge); corroboration must
  be NXDOMAIN or TLS-mismatch. `PromoteNS` lifts a dangling-NS finding to the
  critical `takeover.ns.<provider>` class (D7).
- **`pkg/confirm`** — the `TakeoverConfirmer`: claim → serve canary → prove →
  release, behind a fail-closed `Gate` (active + allow-list), with an
  `ArtifactTracker` enforcing release (D8). **`TestConfirm_EvidenceInvariant` is a
  release-blocker** — no served-and-reflected canary, no `confirmed`. A release
  failure returns `*ErrReleaseFailed` (loud). `blast.go` characterizes cookie
  scope / OAuth-redirect / ACME (D5).
- **`pkg/confirm/adapters`** — `GitHubPagesAdapter`, the reference claim adapter
  (D9). **Dry-run by default**; a live claim requires the operator's own
  credentials AND a wired `GitHubOps` AND `Authorized`. graverobber does NOT
  perform a real provider registration autonomously (the scope boundary — see
  `problems.json#gr07-live-claim-scope`).
- **`pkg/fingerprints/augment.json` + `augment.go`** — the `claim_adapter`
  side-file, applied at load (`ApplyAugment`), preserved across upstream syncs
  (D1). Refresh with `make fpdb-sync` / `scripts/fpdb-sync.sh`.

### CLI verbs (Packet-01 MCP verbs realized as subcommands; no MCP server here)

- `scan-takeover` — multi-signal detect (safe).
- `confirm-takeover` — gated, dry-run-by-default safe-claim confirm.
- `list-fingerprints [--claimable]` — the DB + claim-adapter coverage.

### Walls

Never write secrets, never reference the Maine location or alienclaw.net work, and
do NOT modify the team-lead manual at `~/dev/necromancer/CLAUDE.md` (a protected
file; this graverobber-local CLAUDE.md is the right place for tool notes).
