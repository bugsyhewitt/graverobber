# graverobber — Multi-signal takeover detection + safe claim-confirmation (Packet 07)

> Every takeover scanner (subzy, nuclei takeover templates, dnsReaper, the legacy
> subjack graverobber resurrects) does fingerprint detection and stops at
> "potential takeover" — which on a bug-bounty program gets closed as unproven,
> because a fingerprint match is a *strong signal*, not proof. graverobber's edge
> is the step they don't take: **multi-signal detection** (to crush false
> positives) and **safe claim-confirmation** (to prove the takeover and get it
> paid).

This document describes the takeover-confirmation feature added in Packet 07 and
how it maps onto graverobber's existing `pkg/` architecture.

---

## TL;DR

1. **Multi-signal detection** (`pkg/engine`, the precision play). A candidate is
   reported `detected` only when a provider fingerprint match is corroborated by
   at least one *independent unclaimed-backend signal* — NXDOMAIN on the CNAME
   target, or a TLS certificate that is absent / default-provider / does not cover
   the host. A bare fingerprint match on a live, owned backend is **suppressed**.
   This is what separates graverobber from fingerprint-only tools (which flood
   triage with custom-404 and silently-fixed-provider false positives).

2. **Safe claim-confirmation** (`pkg/confirm`, the moat). The technique EdOverflow
   documents — "claim the subdomain discreetly and serve a harmless file on a
   hidden page" — realized as a confirmer: claim the dangling resource into the
   operator's own provider account → serve a unique canary on a hidden
   `/.well-known/nmc-<id>` path → prove control by fetching the FQDN → characterize
   the blast radius → **release** the resource. Only a served-and-reflected canary
   yields `confirmed`; every other branch is a real negative (`not_vulnerable`) or
   an error — never a false confirmation.

3. **Blast-radius characterization** (`pkg/confirm/blast.go`). A confirmed takeover
   records what it grants: shared-cookie scope (session theft), OAuth `redirect_uri`
   candidacy (account-takeover hand-off to the OAuth tool), and ACME-cert
   issuability (valid-TLS phishing). "Confirmed takeover" is half a finding;
   "confirmed takeover of a cookie-scoped subdomain in an OAuth allow-list" is the
   finding — and the severity.

4. **NS-takeover as a distinct critical class** (`pkg/engine/ns.go`). A dangling
   NS delegation grants whole-zone control (every record, MX/SPF, wildcards,
   sub-delegations), categorically worse than a single CNAME content takeover:
   `rule=takeover.ns.<provider>`, severity `critical`.

---

## How this maps onto the existing repo (adaptation notes)

Packet 07 was written against a hypothetical module layout (an `internal/` tree,
external shared libraries `necromancer-patterns/go` / `necromancer-findings/go` /
`necromancer-mcp/go`, and an MCP server). **The real `graverobber` repository has
none of those** — it is a mature, library-first Go tool under `pkg/` with its own
`finding`, `fingerprints`, `resolver`, `scanner`, `verifier`, and `output`
packages, and no MCP server. The feature was therefore adapted to the real code:

| Packet concept | Realized here as |
|---|---|
| `internal/engine/detect.go` (multi-signal) | `pkg/engine` (Detector, Signals, the D2 guard) |
| `internal/confirm` `TakeoverConfirmer` + `Gate` + `Canaries` + `ArtifactTracker` | `pkg/confirm` (same types, built against the real `finding.Finding`) |
| `ClaimAdapter` + per-provider adapters | `pkg/confirm` interface + `pkg/confirm/adapters` (GitHub Pages reference adapter) |
| `fingerprints.json` `claim_adapter` augmentation + sync | `pkg/fingerprints/augment.json` + `augment.go` (side-file applied at load) + `scripts/fpdb-sync.sh` |
| Packet-03 `nmc.finding/v1` `state`/`severity`/`confirmation` | additive fields on `finding.Finding` (`Rule`, `State`, `Severity`, `Confirmation`), omitempty — the v1.0 finding shape is unchanged |
| Packet-01 MCP verbs `scan_takeover` / `confirm_takeover` / `list_fingerprints` | CLI subcommands `scan-takeover` / `confirm-takeover` / `list-fingerprints` (no MCP server exists in this repo) |
| Packet-05 `Confidence`-less `detected/confirmed/not_vulnerable` | the new `finding.State` lifecycle, complementing the repo's existing `Confidence` tier |

The most important adaptation is a **deliberate scope boundary on the live claim**
(see Safety below).

---

## Safety: why the live claim is dry-run by default

Claiming a resource on a real provider whose name is bound to a target's dangling
DNS is the single most sensitive action in the suite — a successful claim, until
released, *makes the takeover real*. The existing repo states the boundary
plainly ("graverobber never attempts to claim a resource… performing one is not
[in scope]"), and a real claim requires live provider credentials plus a real
network registration that cannot be exercised in a headless test.

graverobber therefore ships the confirmer **dry-run by default**:

- The full state machine (claim → serve → prove → release, with the release
  discipline and the evidence invariant) is **real and fully tested** against an
  in-memory adapter (`pkg/confirm.MockAdapter`) and a dry-run GitHub Pages adapter.
- The live GitHub Pages adapter (`pkg/confirm/adapters.GitHubPagesAdapter`) is
  **gated twice**: it stays in dry-run unless the operator supplies (a) their own
  credentials *and* an explicit `Authorized` acknowledgement, *and* (b) a wired
  `GitHubOps` implementation. Absent a wired client it returns
  `ErrLiveAdapterNotWired` — graverobber does **not** perform a real provider
  registration autonomously.
- The `confirm-takeover` CLI is additionally gated (`--authorized`) and scoped
  (`--allow-apex`), fail-closed.

This is the honest seam: the *machine* is exemplary (D9); the *irreversible
external action* is gated and opt-in. To run a real confirmation, an operator
wires a `GitHubOps` (e.g. backed by `go-github`), supplies credentials, and
asserts authorization — only against targets they own or are authorized to test.

---

## CLI

```
# Multi-signal detection (SAFE — no claiming). Emits takeover.<service> findings.
graverobber scan-takeover -l subdomains.txt --json

# Safely confirm a takeover (DRY-RUN by default; gated + scoped).
graverobber confirm-takeover --target assets.example.com --service github-pages \
    --authorized --allow-apex example.com --json

# The fingerprint DB and which services have a safe claim adapter.
graverobber list-fingerprints --claimable
```

`scan-takeover` exit codes follow the repo convention: 1 when a candidate was
detected, 0 when none, 2 on error. `confirm-takeover` exits 1 on a `confirmed`
finding, 2 when refused (unauthorized / out-of-scope / release failure).

### A confirmed finding (dry-run)

```json
{"subdomain":"assets.example.com","vector":"cname","service":"github-pages",
 "confidence":"CONFIRMED","rule":"takeover.github-pages","state":"confirmed",
 "severity":"high",
 "confirmation":{"state":"confirmed","method":"canary_claim",
   "evidence":"served canary 1edf1729 at https://assets.example.com/.well-known/nmc-1edf1729 (control demonstrated); resource released",
   "reproduction":"claim a github-pages resource for assets.example.com in your own account; serve a file at /.well-known/nmc-1edf1729",
   "blast_radius":"content control of assets.example.com; ACME cert issuable (valid-TLS phishing surface)",
   "released":true,"confirmed_at":"..."}}
```

---

## The two release-blocking invariants (Appendix K)

Two tests, if green, guarantee graverobber stays a *confirmation* tool and not a
noise generator. A red here is a release-blocker.

- **`pkg/engine.TestFingerprintAloneIsNotDetected`** — a fingerprint match with NO
  independent signal must NOT be `detected`. graverobber cannot be made to emit a
  single-signal false positive. (Note: "the DNS chain ends at a provider edge" is
  *not* by itself an independent signal — a live, owned site on the same provider
  ends at the same edge — so corroboration must come from NXDOMAIN or a TLS
  mismatch. This is the precise reading of D2 the test enforces.)
- **`pkg/confirm.TestConfirm_EvidenceInvariant`** — a claim whose canary is not
  served-and-reflected must NOT be `confirmed`. No served canary, no proof.

Plus the release discipline (`TestConfirm_ReleaseFailureIsLoud`,
`TestConfirm_HappyPath`/`…ServeFails`): every claimed resource is released on
every path, and a release failure returns `*ErrReleaseFailed` (loud), keeping the
artifact tracked for manual cleanup.

---

## Fingerprint DB augmentation (D1)

graverobber's `claim_adapter` (and an optional `nxdomain` override) live in
`pkg/fingerprints/augment.json`, a **side-file applied at load**
(`fingerprints.ApplyAugment`). The synced upstream fingerprints cache stays
pure-upstream, so a `graverobber update` (or `scripts/fpdb-sync.sh`) re-pulls
upstream and can never clobber graverobber's additions — they are re-applied from
the embedded side-file. The DB is a *prior*, never the sole signal: detection
still requires live multi-signal corroboration (A5).

---

## NS takeover (D7)

A dangling NS delegation is promoted to the critical class by
`engine.PromoteNS` (a pure classification step over an already-detected
`finding.VectorNS` finding from the mature `pkg/detectors` NS detector — no
re-enumeration, A9): `rule=takeover.ns.<provider>`, `severity=critical`, with the
whole-zone blast radius (`engine.NSBlastRadius`). NS claim-confirmation
(registering the zone, adding a canary TXT, proving, releasing) is higher-risk and
intentionally left to operators with a clean zone-claim adapter; NS findings are
otherwise surfaced `detected` with manual-validation guidance.
