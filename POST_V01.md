# graverobber — Post-v0.1 Directions

Ranked improvement roadmap produced by a Phase 2 research lap (2026-05-26).
Each item is scoped to be implementable in one focused Phase 2 lap.

---

## Rank 1 — Parallel per-target vector execution — ✅ IMPLEMENTED (Phase 2, Rotation 2, 2026-05-26)

**Status:** Shipped. `scanner.scanTarget` now fans the enabled vectors out across
one goroutine each (`sync.WaitGroup`), collecting into per-vector slots and
joining before the unchanged dedup/emit pass. Per-target wall time is now
~max(CNAME, NS, SPF) instead of the sum. No public API or output-semantic
changes; the `emitted` dedup map is untouched. Guarded by
`TestRun_VectorsRunConcurrently` (timing + peak-concurrency assertions),
`TestRun_DisabledVectorsAreNotRun`, and `TestRun_AllVectorFindingsAreEmitted`
in `pkg/scanner/scanner_test.go`.

**What:** Each target currently runs CNAME → NS → SPF serially inside
`scanner.scanTarget`. The three vectors are independent: CNAME probes HTTP
(I/O-bound), NS probes authoritative nameservers with UDP retries (network-
latency-bound), SPF recurses TXT records (DNS-bound). Running them concurrently
cuts per-target wall time to roughly max(CNAME, NS, SPF) instead of the sum.

**Why now:** This is the single biggest throughput win with zero change to output
semantics or the public API. At the default concurrency of 50 workers, a target
list of 10,000 hosts with 10 s timeouts can block on NS retries across the board.

**Implementation sketch:**
- In `scanner.scanTarget`, launch three goroutines (or a `sync.WaitGroup` fan-
  out), one per enabled vector. Collect results via a local buffered channel.
- The existing `emitted` dedup map handles any cross-vector duplicates (unlikely
  but safe).
- Add a `TestRun_VectorsRunConcurrently` scanner test using channels and timing
  assertions to guard the invariant.

**Complexity:** Low — contained entirely in `pkg/scanner/scanner.go`.

---

## Rank 2 — Active verifier: S3, GitHub Pages, Azure service-specific probes

**What:** The `verifier` package ships `NoopVerifier` and an explicit seam
(`Scanner.SetVerifier`) reserved for v1.1. Implement concrete active-verification
logic for the three highest-signal services: AWS/S3, GitHub Pages, and Microsoft
Azure. For these services, a body-match alone (fingerprint present) is already
`CONFIRMED`; active verification would downgrade spurious `LIKELY` findings and
upgrade legitimate ones.

Verification approach per service:
- **AWS/S3**: Confirm bucket name via `https://<bucket>.s3.amazonaws.com/` HEAD;
  `NoSuchBucket` in body + HTTP 404 = confirmed claimable. Do not attempt actual
  bucket creation.
- **GitHub Pages**: Check whether the CNAME target repo exists via
  `https://api.github.com/repos/<user>/<repo>` (unauthenticated, rate-limited to
  60 req/h per IP); 404 = no repo = confirmed claimable.
- **Azure**: The NXDomain fingerprint path already handles most Azure cases;
  active check confirms the resource group is gone via DNS NXDOMAIN on the
  `azurewebsites.net` target itself.

**Why now:** Hazy Hawk (active since late 2023, still expanding to .edu domains as
of April 2026) exploits CNAME takeovers almost exclusively. High-confidence signal
on S3 and GitHub Pages directly maps to the attack pattern. Reducing false
positives is the top user-request category for takeover tools.

**Implementation sketch:**
- Add `pkg/verifier/service.go` with a `ServiceVerifier` struct that wraps a
  map[string]VerifyFn keyed by `f.Service`.
- Wire `scanner.New` to accept an optional `verifier.Verifier`; keep `NoopVerifier`
  as default. Library embedders call `SetVerifier`.
- Add flags `--verify` and `--github-token` (token boosts GH API to 5000 req/h).
- Tests: httptest stubs for each service's error response.

**Complexity:** Medium — new file in `pkg/verifier`, small scanner plumbing change,
flag additions.

---

## Rank 3 — MX record dangling-record detection (fourth vector) — ✅ IMPLEMENTED

**Status:** Shipped (commit b281002). `detectors.MX` adds `VectorMX` ("mx") with
`MXHosts` on `Finding` and the `--no-mx` flag; NXDOMAIN MX hosts are `CONFIRMED`,
known-cloud-provider hosts are `POTENTIAL`.


**What:** Add `VectorMX` as a fourth detection vector. A dangling MX record (MX
pointing to a hostname that is NXDOMAIN or belongs to a cloud provider whose
hosted zone has been deleted) lets an attacker receive all inbound email for the
subdomain, including password-reset links and 2FA codes. The SubdoMailing campaign
(8,000+ hijacked domains) and Hazy Hawk both showed MX abuse is live and high-
value.

BadDNS (Python, released Feb 2025) covers MX; no maintained Go tool does.
Adding this would extend graverobber's "only Go tool covering all vectors" claim
to a fourth vector.

**Algorithm:**
1. Resolve MX records for target (`resolver.MX` — new method, mirrors `NS`).
2. For each MX hostname, run `CNAMEChain`; if NXDOMAIN, the mail host is gone.
3. Optionally match MX hostnames against the existing `knownDNSProviders` list to
   detect zone deletions on cloud mail providers.
4. Emit `VectorMX` findings with `Confidence=Confirmed` for NXDOMAIN or
   `Confidence=Potential` for unrecognised provider.

**Schema additions:**
- `finding.VectorMX = "mx"` in `pkg/finding/finding.go`.
- `MXHosts []string json:"mx_hosts,omitempty"` field on `Finding`.
- `--no-mx` flag on the CLI.

**Why now:** MX takeover is the fastest-growing vector in bug bounty reports (2025
programs pay Critical for MX NXDOMAIN). Hazy Hawk's university campaign (April
2026) used SPF + MX combined to bypass DMARC p=reject policies.

**Complexity:** Medium — mirrors the NS detector in structure; ~150 lines of new
code plus tests.

---

## Rank 4 — NS provider list sync from indianajson/can-i-take-over-dns — ✅ IMPLEMENTED

**Status:** Shipped (commit 445bebe, PR #2). `pkg/nsproviders` fetches and caches
the indianajson provider list behind `graverobber update --ns-providers`, falling
back to the compiled-in defaults when no cache is present.


**What:** `ns.go` hardcodes `knownDNSProviders` (20 suffixes). The canonical
upstream source is `github.com/indianajson/can-i-take-over-dns`, which documents
which providers allow zone re-creation (and thus NS takeover). The list evolves:
NS1 is confirmed vulnerable; Google Cloud DNS added July 2023; Azure status is
uncertain. The hardcoded list has no staleness signal.

Add a `graverobber update --ns-providers` sub-flag (or fold into `update`) that
fetches the indianajson README, parses the provider table, and writes a local
cache at `~/.config/graverobber/ns_providers.json`. Fall back to compiled-in list
when cache absent.

**Why now:** A stale provider list produces false negatives (known-vulnerable
provider not in list → `Potential` instead of `Confirmed`) and false positives
(provider marked vulnerable but patched → incorrect `Confirmed`). The indianajson
repo is the only community-vetted source.

**Complexity:** Low-medium — the fetch/parse/cache pattern is already implemented
in `pkg/fingerprints/update.go`; adapt it. The main challenge is parsing a
Markdown table from README.md rather than structured JSON.

**Alternative:** Ask the indianajson maintainer to add a `providers.json` artifact
(similar to EdOverflow's `fingerprints.json`). Open a GitHub issue; proceed with
Markdown parsing as the fallback implementation.

---

## Rank 5 — Certificate Transparency (CT) log monitoring integration — ✅ IMPLEMENTED

**Status:** Shipped (commit 2e57d54, PR #3). `pkg/ct` + `cmd/graverobber/ct.go`
add the `graverobber ct` subcommand querying crt.sh and streaming certificate
JSONL with a takeover-candidate cross-reference.


**What:** Add a `graverobber ct` subcommand that queries `crt.sh` for recent
certificate issuances on target domains and flags any certificate issued for a
subdomain graverobber classifies as a takeover candidate. An unexpected cert for
a dangling subdomain is near-proof that a takeover has already occurred.

**Why now:** NIST SP 800-81 Rev. 3 (March 2026) formally calls out CT log
monitoring as a required control for organizations running DMARC/SPF. Integrating
CT into the takeover scanner closes the detection loop: graverobber finds
candidates; `ct` confirms whether exploitation already occurred. This would be a
unique feature across all Go takeover tools.

**API:** `crt.sh` exposes a simple JSON endpoint:
`https://crt.sh/?q=%.example.com&output=json` — no auth required. Fields needed:
`name_value`, `not_before`, `issuer_name`.

**Implementation sketch:**
- New `cmd/graverobber/ct.go` sub-command: reads targets from stdin/file/flag,
  queries crt.sh for each apex domain (deduped), streams certificates as JSONL
  with a `"takeover_candidate": true/false` field cross-referenced against a
  prior scan's output.
- Optional: pipe a graverobber JSONL output file in and filter to certs issued
  after the finding's timestamp.

**Complexity:** Medium — mostly a new subcommand with HTTP client + JSON parsing.
No changes to core scanner. The hard part is rate-limiting crt.sh queries
(~1 req/s is polite) and deduplicating apex domains from a noisy subdomain list.

---

## Rank 6 — DKIM selector dangling CNAME detection — ✅ IMPLEMENTED (Phase 2, Rotation 7)

**Status:** Shipped. `detectors.DKIM` adds `VectorDKIM` ("dkim") as the fifth
vector. For each selector in `DefaultDKIMSelectors` (overridable via the
`--selectors` flag) it builds `<selector>._domainkey.<target>`, resolves its
CNAME via the new `resolver.RawCNAME` (a TypeCNAME query that returns only the
immediate alias — distinguishing a delegated selector from an inline-TXT one),
then follows the alias with `CNAMEChain`; an `ErrNXDomain` target yields a
`CONFIRMED` finding carrying the dangling `CNAME` and the `dkim_selector`. Wired
into the scanner fan-out behind `Options.NoDKIM` / `--no-dkim` (opt-out, on by
default). Guarded by `TestDKIM_DanglingSelectorConfirmed`,
`TestDKIM_NoFindingsWhenNotDelegated`, `TestDKIM_DedupSelectors` (detectors),
`TestRawCNAME_*` (resolver), `TestRun_NoDKIMDisablesDKIMVector` (scanner), and
`TestParseSelectors` (cmd).

**What:** DKIM public keys are published as TXT records under
`<selector>._domainkey.<domain>`, but many organizations publish them as CNAME
records pointing to their ESP's infrastructure (e.g.,
`s1._domainkey.example.com → s1.domainkey.sendgrid.net`). If the ESP account
is closed or the selector is rotated, the CNAME is abandoned — an attacker who
claims the ESP resource can serve a DKIM key and sign email that passes DKIM
verification.

The SubdoMailing writeup (Guardio Labs, 2024) and subsequent analysis confirmed
this vector is exploited at scale.

**Algorithm:**
1. Resolve `_domainkey` TXT/CNAME records by trying common DKIM selectors
   (`default`, `google`, `k1`, `s1`, `s2`, `dkim`, `mail`) plus any selectors
   discovered via DMARC reporting URIs.
2. If a CNAME under `_domainkey` is NXDOMAIN, emit `VectorDKIM` finding.

**Schema:** `finding.VectorDKIM = "dkim"`. `--selectors` flag to override default
selector list.

**Why deferred to Rank 6:** The selector-guessing approach yields partial coverage;
full coverage requires knowing the actual selector in use, which requires reading
the DKIM signature from intercepted email (not feasible in a passive scanner). The
value is catching the lazy case (common selectors), not the complete case.

**Complexity:** Medium — new detector file, minimal schema additions.

---

## Rank 7 — Second-order subdomain takeover: JS reference scanning — ✅ IMPLEMENTED

**Status:** Shipped (commit da9a6c8, PR #5). `pkg/links` + `cmd/graverobber/links.go`
add the `graverobber links` subcommand that crawls live pages and extracts
cross-origin domain references for second-order takeover discovery.


**What:** Second-order subdomain takeover (documented by Patrik Hudak, implemented
in the `second-order` Go tool) occurs when a live web application references a
domain in its JavaScript, HTML, or JSON responses that is itself dangling —
typically a forgotten analytics endpoint, CDN URL, or legacy OAuth redirect URI.
The target subdomain is live and resolves; the vulnerability is one hop deeper.

`graverobber ct` and the main scanner operate on explicitly enumerated targets.
This would add an optional crawler mode: for each confirmed or likely finding,
fetch the live page and extract all cross-origin domain references, then feed
those domains through the scanner.

**Why Rank 7:** Second-order is powerful but operationally expensive (requires
HTTP crawling), widens the scope beyond the tool's design ethos (pipeline-
friendly, stdin→stdout), and overlaps with dedicated tools (`second-order`,
`gau`, `waybackurls`). Better positioned as an integration note (pipe `gau`
output into graverobber) than a native feature.

**Complexity:** High — crawler integration significantly increases dependency
surface and test complexity.

---

## Rank 8 — DMARC report-domain dangling detection (sixth vector) — ✅ IMPLEMENTED

**Status:** Shipped (Phase 2, Rotation 9). Added after Ranks 1–7 were all
complete; this is the natural completion of the email-authentication takeover
surface (SPF include:, DKIM selector CNAME, MX host, and now DMARC report URI).

`detectors.DMARC` adds `VectorDMARC` ("dmarc"). It resolves the TXT record at
`_dmarc.<target>`, extracts the policy (`v=DMARC1` prefix), parses the `rua=` and
`ruf=` reporting tags — handling comma-separated URI lists, mixed case, and the
optional `!<size>` report-size limit — and pulls the domain from each
`mailto:user@domain` URI. Each report domain is probed with `CNAMEChain`; an
`ErrNXDomain` target yields a `POTENTIAL` `VectorDMARC` finding carrying the
claimable domain in the new `DMARCURI` (`dmarc_uri`) field. POTENTIAL (not
CONFIRMED) mirrors the SPF `include:` classification: a DNS-only NXDOMAIN signal
with no fingerprint match.

Wired into the scanner fan-out behind `Options.NoDMARC` / `--no-dmarc` (opt-out,
on by default). Guarded by `TestDMARC_DanglingReportDomainPotential`,
`TestDMARC_LiveReportDomainNoFinding`, `TestDMARC_NoRecordNoFinding`,
`TestExtractDMARC`, `TestDMARCReportDomains`, `TestDMARCFinding_VectorConstant`
(detectors) and `TestRun_NoDMARCDisablesDMARCVector` (scanner).

**Why this vector:** A dangling DMARC `rua`/`ruf` domain lets an attacker who
claims it intercept every DMARC aggregate/forensic report sent for the target —
exposing the target's complete sending infrastructure, which spoofing attempts
pass or fail alignment, and source-IP reputation. It is a quiet reconnaissance
channel documented alongside the SPF/MX vectors in the SubdoMailing and Hazy Hawk
campaigns, and it is the only remaining email-auth record class graverobber did
not yet cover. DNS-only, no API keys, no new dependencies — fully on-ethos.

**Schema:** `finding.VectorDMARC = "dmarc"`; new `DMARCURI` field
(`json:"dmarc_uri,omitempty"`). `--no-dmarc` CLI flag.

**Complexity:** Low-medium — one new detector file mirroring SPF, two schema
additions, scanner option + CLI flag, seven new tests.

---

## Rank 9 — Terminal output detail for the email-auth vectors — ✅ IMPLEMENTED (Phase 2, Rotation 10)

**Status:** Shipped. After Ranks 1–8 added MX, DKIM, and DMARC vectors, the
default (non-JSON) `TerminalWriter` was never extended to render them: its detail
switch handled only CNAME, SPF, and NS, so MX/DKIM/DMARC findings printed with an
**empty detail field** — the operator saw the tier, vector tag, and host but not
the dangling mail host, the DKIM selector/delegation, or the claimable DMARC
report domain. Half the tool's vectors were effectively invisible in its default
output mode.

`pkg/output/output.go` now renders all six vectors:
- `mx`   → `mx [mail.gone.net]`
- `dkim` → `dkim s1._domainkey -> s1.domainkey.gone.sendgrid.net`
- `dmarc` → `dmarc rua/ruf:reports.gone.net`

The JSONL path was already correct (it serializes the full `Finding`); only the
human-readable path was incomplete. `pkg/output` had **zero test coverage** before
this rotation. Added `pkg/output/output_test.go` (5 test functions, 6 subtests):
`TestTerminalWriter_RendersDetailForEveryVector` is a table-driven regression
guard asserting every vector surfaces its identifying datum plus the vector tag
and confidence tier; `TestJSONLWriter_RoundTrip` and
`TestJSONLWriter_OmitsEmptyVectorFields` lock the JSONL contract (single line,
`omitempty` keeps a CNAME finding from leaking email-vector fields);
`TestTerminalWriter_NoColourOmitsANSI` / `_ColourWrapsTiers` pin the TTY-vs-pipe
colour behaviour.

**Why this over a new vector:** All six high-value takeover vectors are already
covered; the next-highest-value work is no longer breadth but correctness of what
ships. A default-mode output bug that hides three of six vectors is a higher-
impact, lower-risk fix than a seventh vector — and it closed the last untested
package in the tree. DNS-only, no new flags, no API change, no dependencies.

**Complexity:** Low — three switch arms in one file plus a new test file.

---

## Non-goals (explicitly out of scope)

- **WHOIS-based SPF include verification:** The SPF detector already uses DNS
  NXDOMAIN as the unregistered-domain signal. WHOIS is unreliable (rate limits,
  format variance, privacy proxies) and adds no precision over NXDOMAIN for
  the SPF vector.
- **Notification/alerting system:** graverobber is a pipeline tool. Alerting
  belongs to the orchestration layer (cron + diff | notify). Not a tool concern.
- **Authenticated cloud API probes (AWS SDK, Azure SDK):** Active verification
  (Rank 2) uses unauthenticated HTTP probes only. Credential handling is a
  footgun and an attack surface; the tool must remain credential-free by default.
- **Web UI / dashboards:** graverobber is a CLI tool in the httpx/subfinder
  family. Pipeline-friendliness is the product.

---

## Summary table

| Rank | Item | Effort | Impact | Changes API? |
|------|------|--------|--------|-------------|
| 1 | Parallel vector execution per target ✅ | Low | High (throughput) | No |
| 2 | Active verifier: S3, GitHub Pages, Azure | Medium | High (accuracy) | No (SetVerifier seam ready) |
| 3 | MX record fourth vector ✅ | Medium | High (new coverage) | Yes (new vector + flag) |
| 4 | NS provider list sync from indianajson ✅ | Low-Med | Medium (accuracy) | No |
| 5 | CT log monitoring subcommand ✅ | Medium | High (unique feature) | No (new subcommand) |
| 6 | DKIM selector dangling CNAME ✅ | Medium | Medium (new coverage) | Yes (new vector + flag) |
| 7 | Second-order JS reference scanning ✅ | High | Medium (niche) | Yes (new mode) |
| 8 | DMARC report-domain dangling vector ✅ | Low-Med | High (completes email-auth) | Yes (new vector + flag) |
| 9 | Terminal output detail for MX/DKIM/DMARC ✅ | Low | High (default-mode correctness) | No |
