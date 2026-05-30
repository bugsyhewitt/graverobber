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

## Rank 2 — Active verifier: S3, GitHub Pages, Azure service-specific probes — ✅ IMPLEMENTED

**Status:** Shipped. `pkg/verifier/service.go` adds `ServiceVerifier`, dispatching
on `f.Service` for the three highest-signal CNAME services: AWS/S3 (GET probe of
`<bucket>.s3.amazonaws.com`, `NoSuchBucket` + 404 → CONFIRMED), GitHub Pages
(`api.github.com/repos/<user>/<repo>` existence check, 404 → CONFIRMED), and
Microsoft Azure (DNS NXDOMAIN on the `azurewebsites.net`-class target →
CONFIRMED). It only ever upgrades LIKELY→CONFIRMED, never downgrades, and never
re-litigates a fingerprint-CONFIRMED finding. Wired into the scanner via
`SetVerifier` and exposed by the `--verify` / `--github-token` flags in
`cmd/graverobber/main.go`. Guarded by `pkg/verifier/service_test.go` (httptest
stubs per service). All probes are read-only and credential-free by default.

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

## Rank 10 — SARIF 2.1.0 output for CI / GitHub Code Scanning — ✅ IMPLEMENTED (Phase 2, Rotation 12)

**Status:** Shipped. After Ranks 1–9 exhausted the original research roadmap
(all six takeover vectors covered, active verification wired, terminal output
complete), R12 opened a new direction: **integration**, not breadth. The scanner
detects well but had no path into the DevSecOps loop — findings were a stream of
JSONL or console lines that scrolled away, not tracked alerts.

`pkg/output/sarif.go` adds `SarifWriter`, a third `output.Writer` that buffers
findings on `Write` and emits a single SARIF 2.1.0 log on `Close` (a SARIF log
is one document with a rule catalogue + results array, unlike the per-line JSONL
path). The CLI gains `--sarif` (mutually exclusive with `--json`), wired through
`openWriter` and a fast-fail validation guard in `runScan`.

Mapping: `CONFIRMED → error`, `LIKELY`/`POTENTIAL → warning`; the subdomain is
the result location; rules are namespaced `graverobber/<vector>` with per-vector
short/full descriptions; a stable `partialFingerprint` on `(subdomain, vector)`
lets Code Scanning dedupe candidates across re-scans. An empty scan still emits
a valid log so the `upload-sarif` step never fails. DNS-only ethos preserved:
std-lib `encoding/json` only, no new dependencies, no credentials.

Guarded by eight new tests in `pkg/output/sarif_test.go`
(`TestSARIF_DocumentEnvelope`, `_EmptyScanIsValid`,
`_RuleCatalogueDedupesByVector`, `_LevelFromConfidence`,
`_ResultLocationAndFingerprint`, `_MessageSurfacesVectorDetail`,
`_RuleIDNamespaced`) plus `TestRunScan_RejectsJSONAndSARIFTogether` in
`cmd/graverobber/main_test.go`.

**Why this over a seventh vector:** All high-value takeover vectors already ship.
The next marginal value is no longer detection coverage but getting the existing
findings in front of the people who fix them — and the standard channel for that
is SARIF into Code Scanning. Unique among Go takeover tools; one new Writer file,
one flag, no API or scanner change.

**Complexity:** Low-medium — one new file in `pkg/output`, a flag + two CLI
wiring lines, README section, eight tests.

---

## Rank 11 — CSV output for spreadsheet / ticket triage — ✅ IMPLEMENTED (Phase 2, Rotation 13)

**Status:** Shipped. With all six vectors, active verification, terminal detail,
and SARIF CI integration in place, the remaining output-format gap was the
spreadsheet-and-ticketing triage workflow that most security teams actually run.
JSONL serves programmatic consumers and SARIF serves Code Scanning, but neither
drops cleanly into Excel/Sheets, a Jira CSV import, or a `csvkit`/`pandas`
pipeline without a `jq` step.

`pkg/output/csv.go` adds `CSVWriter`, a fourth `output.Writer` emitting RFC 4180
CSV via std-lib `encoding/csv`: a fixed header row plus one row per finding. The
schema is intentionally flat and stable — every vector maps onto the same nine
columns (`timestamp,subdomain,vector,confidence,service,target,scheme,fingerprint,evidence`)
and the vector-specific dangling target (CNAME / SPF include / NS+MX hosts /
DKIM selector delegation / DMARC report domain) is normalised into a single
`target` column so the whole sheet sorts and filters uniformly. The header is
written exactly once, so an empty scan still yields a valid header-only file that
downstream importers accept. The CLI gains `--csv`, and the prior pairwise
`--json`/`--sarif` mutual-exclusion check generalised to an N-way `boolCount`
guard so all three machine formats reject each other.

Guarded by five new tests in `pkg/output/csv_test.go`
(`TestCSV_HeaderThenRow`, `_EmptyScanEmitsHeaderOnly`, `_TargetColumnPerVector`,
`_QuotesCommaBearingFields`, `_TimestampIsRFC3339UTC`) plus a generalised
`TestRunScan_RejectsConflictingFormats` (all pairwise + three-way combinations)
and `TestBoolCount` in `cmd/graverobber/main_test.go`.

**Why this over a seventh vector:** All high-value takeover vectors already ship;
the marginal value is now distribution, not detection. SARIF reaches the
CI/Code-Scanning audience; CSV reaches the analyst-in-a-spreadsheet audience,
which is the larger triage population. std-lib only, no new dependencies, no API
or scanner change.

**Complexity:** Low — one new file in `pkg/output`, a flag + two CLI wiring
lines, a small mutual-exclusion generalisation, README section, seven tests.

---

## Rank 12 — AXFR zone-transfer misconfiguration (seventh vector) — ✅ IMPLEMENTED (Phase 2, Rotation 15)

**Status:** Shipped. Ranks 1–11 exhausted the original research roadmap (six
takeover vectors, active verification, terminal/SARIF/CSV output) and R14 added
the end-of-scan triage summary. With the email-authentication surface complete
and the output story closed, the next natural gap is a new **DNS attack-surface**
vector rather than more output plumbing.

`detectors.AXFR` adds `VectorAXFR` ("axfr") as the seventh vector. It is the
secure-vs-misconfigured sibling of the NS vector: NS asks "is the hosted zone
deleted?"; AXFR asks "will the live nameservers hand me the whole zone?". Both
start from the same delegated NS set. The detector resolves the target's `NS`
records, then attempts an unauthenticated AXFR (TCP) against each via the new
`resolver.ZoneTransfer`; the first nameserver that streams zone data yields a
`CONFIRMED` `axfr` finding naming that nameserver, the record count, and a
deduplicated, sorted, capped sample of the leaked owner names (new
`LeakedHosts` / `leaked_hosts` field). A nameserver that refuses
(`ErrAXFRRefused`, the secure response) or fails at the transport level is
skipped — only an actual transfer is a finding, so there are no false positives.

**Why this vector:** An open AXFR is a classic, high-signal DNS misconfiguration
that is both a direct information disclosure and a force-multiplier for every
other graverobber vector — one permissive nameserver leaks the complete subdomain
list, which feeds straight back through CNAME/NS/SPF/MX/DKIM/DMARC to find the
dangling records inside it. It is fully on-ethos: DNS-only, no credentials, no
new dependencies (miekg/dns already ships `Transfer`), and pipeline-friendly. The
detector only reads the zone to confirm and sample the leak; it never writes,
modifies, or persists the records, and the transfer is bounded
(`maxAXFRRecords` / `maxAXFRHostsSampled`) so a large zone cannot exhaust memory
in a 50-worker scan.

Wired into the scanner fan-out behind `Options.NoAXFR` / `--no-axfr` (opt-out,
on by default). All four output paths render it: terminal detail
(`axfr <ns> leaked N host(s)`), JSONL (the full `Finding` with `leaked_hosts`),
SARIF (a `graverobber/axfr` rule, `CONFIRMED → error`), and CSV (the leaking
nameserver in the `target` column).

Guarded by `TestZoneTransfer_LeakReturnsRecords`,
`TestZoneTransfer_RefusedIsErrAXFRRefused`, `TestZoneTransfer_SOAOnlyIsRefused`,
`TestZoneTransfer_TransportErrorIsNotRefusal` (resolver), `TestAXFR_LeakConfirmed`,
`TestAXFR_RefusedNoFinding`, `TestAXFR_NoNameserversNoFinding`,
`TestAXFRFinding_VectorConstant` (detectors), `TestRun_NoAXFRDisablesAXFRVector`
(scanner), and new AXFR cases in the table-driven terminal/CSV/SARIF tests. The
detector tests use a hermetic local AXFR server via the test-only
`resolver.SetAXFRPortForTest` seam (mirroring the `soaBackoff` testability
pattern) so no privileged port 53 or live network is required.

**Complexity:** Medium — one resolver primitive (`ZoneTransfer` +
`ZoneTransferResult`), one new detector file, two schema additions
(`VectorAXFR`, `LeakedHosts`), scanner option + CLI flag, four output-path arms,
README sections.

---

## Rank 13 — SPF `redirect=` modifier dangling detection — ✅ IMPLEMENTED (Phase 2, Rotation 16)

**Status:** Shipped. Ranks 1–12 covered the seven takeover vectors, active
verification, and the full output story (terminal/JSONL/SARIF/CSV + triage
summary). The next-highest-value gap was not a new vector but a **completeness
hole inside an existing one**: the SPF detector handled only the `include:`
mechanism and silently ignored the `redirect=` modifier — the other RFC 7208
directive that hands a target's SPF policy to an external domain.

A policy like `v=spf1 redirect=_spf.gone-vendor.com` with an unregistered
redirect target produced **zero findings** before this rotation, despite being
the same SubdoMailing-class takeover as a dangling `include:` (and arguably
higher-impact: `redirect=` designates the target's record as *the* policy
wholesale, per RFC 7208 §6.1, rather than merely folding it in).

`detectors.SPF` now parses both directives in one pass via the new
`spfReferences` helper (returning `[]spfReference{domain, redirect}`), recurses
into the policies of domains that still exist (still bounded by `maxSPFDepth` =
the RFC 7208 ten-lookup cap), and emits a `POTENTIAL` `VectorSPF` finding for any
referenced domain that resolves `NXDOMAIN`. The claimable domain populates the
existing `SPFInclude` field for both directive kinds; only the `Evidence` string
differs (`SPF include: domain is NXDOMAIN (claimable)` vs.
`SPF redirect= domain is NXDOMAIN (claimable)`). No schema change, no new flag,
no new dependency — fully on-ethos (DNS-only, std-lib + miekg/dns).

Guarded by `TestSPFReferences` (table-driven parse: include/redirect/mixed-case/
ignorable-mechanisms), `TestSPF_DanglingRedirectPotential` (full detector against
a hermetic local DNS server, asserts one POTENTIAL finding whose evidence names
`redirect=`), and `TestSPF_LiveRedirectNoFinding` (a resolving redirect target
yields no finding). The existing `include:` tests remain unchanged and green.

**Why this over a new vector:** All high-value vector *classes* already ship; the
marginal value is now correctness-within-coverage. A directive the detector
parses-but-half — silently missing `redirect=` — is a higher-impact, lower-risk
fix than an eighth vector, and it closes the SPF surface to match the RFC. The
change is contained to one detector file plus tests.

**Complexity:** Low — one parse-helper refactor in `pkg/detectors/spf.go`, three
new tests, README directive/flag updates. No API, scanner, or output change.

---

## Rank 14 — DKIM weak inline-key detection — ✅ IMPLEMENTED (Phase 2, Rotation 17)

**Status:** Shipped. Ranks 1–13 covered the seven takeover vectors, active
verification, the full output story, and closed the SPF surface (`redirect=`).
The next-highest-value gap was, like R16, a **completeness hole inside an
existing vector**: the DKIM detector only inspected selectors *delegated by
CNAME* (the dangling-ESP case) and `continue`d past every selector whose key was
published *inline* as a TXT record — silently ignoring the second, equally
exploitable DKIM weakness: a short RSA key.

`detectors.DKIM` now takes the inline-key path whenever a selector has no CNAME:
it fetches the selector's TXT record, parses the DKIM key tags (`v`/`k`/`p`),
base64-decodes the `p=` public key (DER SubjectPublicKeyInfo or bare PKCS#1),
and emits a `LIKELY` `dkim` finding for any RSA modulus below the RFC 8301
1024-bit floor (`minDKIMKeyBits`). The new `DKIMKeyBits` (`dkim_key_bits`) field
carries the offending size and distinguishes the weak-key sub-case from the
dangling-CNAME sub-case (which is identified by `CNAME`). Confidence is `LIKELY`,
not `CONFIRMED`: a short key is a definitive cryptographic weakness but the
forge-and-deliver step is an active exploit, mirroring the tool's confidence
ladder. Non-RSA keys (ed25519), revoked keys (empty `p=`), keys at/above the
floor, and non-DKIM TXT records are never flagged — graverobber reports no
finding it cannot substantiate.

All four output paths render the new sub-case (terminal/CSV/SARIF detail show
`<sel>._domainkey weak <N>-bit RSA key`; JSONL serialises `dkim_key_bits`); the
SARIF `graverobber/dkim` rule description now covers both DKIM weaknesses.

**Why this over a new vector:** Every high-value vector *class* already ships;
the marginal value is correctness-within-coverage. A detector that parses DKIM
selectors but checks only half of the documented DKIM weaknesses is a
higher-impact, lower-risk fix than a new vector — and it requires no new flag, no
new resolver primitive (reuses `TXT`), and no new dependency (std-lib
`crypto/x509` + `encoding/base64`). Fully on-ethos: DNS-only, credential-free.

**Schema:** new `DKIMKeyBits int` (`json:"dkim_key_bits,omitempty"`) on
`Finding`. No new flag (folded into the existing `--no-dkim` / `--selectors`).

Guarded by `TestParseDKIMTags`, `TestRSAPublicKeyBits`, `TestWeakDKIMKeyBits`
(table-driven: weak 512/768, default-`k`, strong, revoked, non-RSA, non-DKIM,
wrong version), `TestDKIM_WeakInlineKeyLikely` and
`TestDKIM_StrongInlineKeyNoFinding` (full detector against a hermetic local DNS
server), plus a new `dkim-weak-key` case in the table-driven terminal output
test. The pre-generated sub-1024 keys are constants because modern Go's
`crypto/rsa` refuses to *generate* insecure keys (the very weakness flagged)
while `x509` still parses them.

**Complexity:** Low — one inline-key path + three parse helpers in
`pkg/detectors/dkim.go`, one schema field, three output-detail arms, README +
roadmap updates, seven new tests. No API, scanner, or flag change.

---

## Rank 15 — DMARC monitor-only (`p=none`) policy detection — ✅ IMPLEMENTED (Phase 2, Rotation 18)

**Status:** Shipped. Ranks 1–14 covered the seven takeover vectors, active
verification, the full output story (terminal/JSONL/SARIF/CSV + triage summary),
and closed the SPF (`redirect=`) and DKIM (weak inline key) surfaces. The
next-highest-value gap was, like R16 and R17, a **completeness hole inside an
existing vector**: the DMARC detector only inspected the `rua=`/`ruf=` *report
domains* (the dangling-report-interception case) and never read the `p=` policy
tag — so it silently passed over the most common, most exploited DMARC
weakness of all: a **monitor-only `p=none` policy**.

A `p=none` policy instructs receivers to take **no action** on a message that
fails DMARC alignment (RFC 7489 §6.3): spoofed mail that fails both SPF and DKIM
is delivered to the inbox anyway. `p=none` is the deployment-bootstrap state, not
a destination — a domain that publishes it indefinitely is spoofable by anyone,
which is the precondition every business-email-compromise and phishing campaign
relies on. Before this rotation a domain with `v=DMARC1; p=none` and no dangling
report address produced **zero findings**, despite being trivially spoofable.

`detectors.DMARC` now parses the `p=` tag via the new `dmarcPolicy` helper
(case-insensitive on tag and value, order-independent, and careful not to let the
subdomain-policy `sp=` tag shadow `p=`). When the policy is `none` it emits a
`POTENTIAL` `dmarc` finding keyed on the **target itself** (not a report domain),
carrying the policy token in the new `DMARCPolicy` (`dmarc_policy`) field. The
finding's `Evidence` distinguishes the merely-weak case (`p=none` with reporting)
from the worse no-visibility case (`p=none` **without** a `rua=` aggregate
address — neither enforcement nor visibility). Enforcing policies (`p=reject`,
`p=quarantine`) are never flagged, and the weak-policy and dangling-report
sub-cases fire independently and can both appear for the same record. Confidence
is `POTENTIAL`: a DNS-only policy-weakness signal with no fingerprint match,
consistent with the existing DMARC/SPF classification. The two DMARC sub-cases
are distinguished by which of `DMARCPolicy` / `DMARCURI` is set.

All four output paths render the new sub-case (terminal/CSV/SARIF detail show
`dmarc policy p=none (monitor-only)`; JSONL serialises `dmarc_policy`); the SARIF
`graverobber/dmarc` rule title and description now cover both DMARC weaknesses.

**Why this over a new vector:** Every high-value vector *class* already ships;
the marginal value is correctness-within-coverage. A detector that parses a DMARC
record but checks only half of the documented DMARC weaknesses — ignoring the
single most common one — is a higher-impact, lower-risk fix than a new vector. It
requires no new flag (folded into the existing `--no-dmarc`), no new resolver
primitive (reuses the `TXT` already fetched), and no new dependency. Fully
on-ethos: DNS-only, credential-free, pipeline-friendly.

**Schema:** new `DMARCPolicy string` (`json:"dmarc_policy,omitempty"`) on
`Finding`. No new flag.

Guarded by `TestDMARCPolicy` (table-driven parse: each enforcement level,
case-insensitivity, tag ordering, `sp=` non-shadowing, absence, non-DMARC),
`TestDMARC_WeakPolicyPotential` (full detector against a hermetic local DNS
server — one POTENTIAL finding keyed on the target, `DMARCPolicy=none`,
`DMARCURI` empty), `TestDMARC_WeakPolicyNoReportingEvidence` (evidence calls out
the missing `rua=`), `TestDMARC_StrongPolicyNoWeakFinding` (`p=reject` /
`p=quarantine` yield nothing), and `TestDMARC_WeakPolicyAndDanglingReport` (both
sub-cases fire together), plus a new `dmarc-weak-policy` case in the table-driven
terminal output test. The pre-existing `TestDMARC_LiveReportDomainNoFinding`
fixture was switched from `p=none` to `p=reject` so it continues to isolate the
dangling-report path.

**Complexity:** Low — one `p=` parse helper + one finding branch in
`pkg/detectors/dmarc.go`, one schema field, three output-detail arms, README +
roadmap updates, five new tests. No API, scanner, or flag change.

---

## Rank 16 — CAA (Certification Authority Authorization) misconfiguration (eighth vector) — ✅ IMPLEMENTED (Phase 2, Rotation 19)

**Status:** Shipped. Ranks 1–15 covered the seven takeover vectors (CNAME, NS,
SPF, MX, DKIM, DMARC, AXFR), active verification, the full output story
(terminal/JSONL/SARIF/CSV + triage summary), and closed the SPF (`redirect=`),
DKIM (weak inline key), and DMARC (`p=none`) completeness holes. With the
email-authentication surface complete and the DNS-misconfiguration surface opened
by AXFR, the next-highest-value gap was a **second DNS-security misconfiguration
class** that no maintained Go takeover tool covers: a broken CAA policy.

`detectors.CAA` adds `VectorCAA` ("caa") as the eighth vector. A CAA record set
(RFC 8659) restricts which Certificate Authorities may issue certificates for a
domain; without one (or with a broken one) any of the ~150 publicly-trusted CAs
will issue a certificate to anyone who passes its domain-control validation — the
precondition for a man-in-the-middle TLS certificate. The detector resolves the
target's CAA records via the new `resolver.CAA` (a `TypeCAA` query returning
`[]resolver.CAARecord{Flag, Tag, Value}`) and flags two misconfigurations:

- **Dangling issuer** (POTENTIAL): an `issue`/`issuewild` tag names a CA domain
  that is NXDOMAIN. This is the SubdoMailing-class takeover applied to CAA — an
  attacker who registers the unregistered CA domain can stand up an ACME/CA
  endpoint the target's policy explicitly authorises. The claimable domain is
  carried in the new `CAAIssuer` (`caa_issuer`) field. The NXDOMAIN probe reuses
  `CNAMEChain`, exactly as the SPF `include:` and DMARC report-domain detectors.
- **Permissive any-CA** (POTENTIAL): a CAA record set is present but an
  `issue`/`issuewild` tag uses the wildcard value `*`, re-opening the hole CAA
  exists to close while falsely signalling that issuance is controlled. `CAAIssuer`
  is empty; the sub-cases are distinguished by which is set.

Confidence is POTENTIAL (DNS-only, no fingerprint match), consistent with the
SPF/DMARC classification. A domain with **no** CAA record (the internet-wide
default) is intentionally NOT flagged, and the secure deny-all `;` value is never
flagged — the vector reports only a present-but-broken policy, keeping it
low-noise. Wired into the scanner fan-out behind `Options.NoCAA` / `--no-caa`
(opt-out, on by default). All four output paths render it: terminal detail
(`caa issuer <dom> NXDOMAIN (claimable)` / `caa authorises any CA (permissive)`),
JSONL (`caa_issuer`), SARIF (a `graverobber/caa` rule), and CSV (the claimable CA
in the `target` column). DNS-only ethos preserved: `miekg/dns` `TypeCAA` only, no
credentials, no new dependencies.

**Schema:** `finding.VectorCAA = "caa"`; new `CAAIssuer string`
(`json:"caa_issuer,omitempty"`). `--no-caa` CLI flag; `Options.NoCAA`.

Guarded by `TestCAAIssuerDomain` (table-driven value parser: deny-all/empty/
params/`*`/case), `TestCAA_DanglingIssuerPotential`,
`TestCAA_PermissiveAnyCAPotential`, `TestCAA_LiveIssuerNoFinding`,
`TestCAA_NoRecordNoFinding`, `TestCAAFinding_VectorConstant` (detectors, against a
hermetic local DNS server), `TestCAA_ParsesRecords`, `TestCAA_EmptyOnNXDOMAIN`
(resolver), `TestRun_NoCAADisablesCAAVector` (scanner), plus two new CAA cases in
the table-driven terminal output test.

**Complexity:** Low-medium — one resolver primitive (`CAA` + `CAARecord`), one new
detector file, two schema additions (`VectorCAA`, `CAAIssuer`), scanner option +
CLI flag, three output-path arms, README + roadmap updates, eleven new tests.

---

## Rank 17 — Triage summary by-vector breakdown completeness — ✅ IMPLEMENTED (Phase 2, Rotation 20)

**Status:** Shipped. Rotation 20's gap analysis found the entire ranked roadmap
(Ranks 1–16) already implemented — POST_V01.md was stale (Rank 2's active
verifier had shipped but its status line still read unimplemented). A fresh
codebase sweep surfaced a **correctness-within-coverage bug** in the default
(human-readable) output, exactly the class R9/R17/R18 targeted.

`cmd/graverobber/main.go`'s `summaryVectorOrder` — the fixed key list the
end-of-scan triage summary iterates to render the `by vector:` line — listed only
six of the eight vectors the scanner emits (`cname`, `ns`, `spf`, `mx`, `dkim`,
`dmarc`). It was never extended when Rank 12 (AXFR) and Rank 16 (CAA) added their
vectors. Because `summaryParts` iterates *only* over `summaryVectorOrder`, every
AXFR and CAA finding was counted in the total and in the `by tier:` breakdown but
**silently dropped from the `by vector:` line** — so on any scan that found an
open zone transfer or a broken CAA policy (two of the highest-severity DNS
findings the tool produces), the breakdown failed to reconcile with the reported
count. An operator triaging the summary would see, e.g., `8 finding(s)` whose
per-vector counts summed to 6.

The fix adds `VectorAXFR` and `VectorCAA` to `summaryVectorOrder` in pipeline
order (matching the scanner's dispatch sequence). Guarded by
`TestScanSummary_CountsEveryVector` (a structural regression guard asserting every
emittable vector surfaces in the breakdown — it fails if any future vector is
added without updating the summary) and `TestScanSummary_AXFRAndCAAReconcile` (the
direct case: an AXFR + CAA scan shows both and reconciles). Both tests were
verified to fail against the unfixed code. README triage-summary example updated.

**Why this over a new vector:** All high-value vector classes already ship; the
marginal value is correctness of what ships, not breadth. A default-mode summary
that undercounts two of eight vectors is a higher-impact, lower-risk fix than a
ninth vector. No API, scanner, flag, or output-format change — one slice literal
plus two regression tests.

**Complexity:** Trivial — two entries added to one slice in `cmd/graverobber`,
two new tests, one README example update. No new dependency.

---

## Rank 18 — BIMI dangling-asset-host detection (eleventh vector) — ✅ IMPLEMENTED (Phase 2, Rotation 24)

**Status:** Shipped. Rotation 24's directive offered two options — a **BIMI DNS
record check** or a **DKIM key-rotation-age detector** — with instructions to
assess the codebase first. Assessment found:

- Neither BIMI nor any rotation/age logic existed in the codebase (the prior
  roadmap, Ranks 1–17, was fully implemented).
- The **DKIM key-rotation-age detector is not feasible passively** and was
  rejected: a DKIM TXT key record carries no publication timestamp, and DNS
  exposes none. "Rotation age" cannot be determined from DNS alone, so any such
  detector would be guesswork or require out-of-band state — a poor fit for a
  stateless, DNS-only, pipeline scanner. (The existing DKIM vector already covers
  the two *exploitable* DKIM weaknesses: dangling CNAME and sub-1024-bit keys.)
- **BIMI is the strong fit** and was implemented. It is a clean DNS-only signal in
  exactly the SubdoMailing/dangling-host family the tool already specialises in.

BIMI (Brand Indicators for Message Identification) publishes a `v=BIMI1` TXT
record at `default._bimi.<domain>` whose `l=` (logo SVG URL) and optional `a=`
(VMC certificate URL) point at HTTPS asset hosts. BIMI-aware clients (Gmail,
Apple Mail, Yahoo, Fastmail) display the logo **only beside DMARC-passing mail**,
so the logo is a recipient-facing trust mark. When an asset host is
decommissioned but the BIMI record is left behind — a **dangling BIMI asset
host** — an attacker who reclaims that host serves a forged brand logo/VMC,
lending a spoofing campaign the exact visual trust signal BIMI exists to confer: a
brand-impersonation surface, the same dangling-host pattern as CNAME/MX/SPF-
include/DMARC-report/CAA-issuer/TLSA/MTA-STS, applied to the BIMI asset plane.

The detector (`pkg/detectors/bimi.go`, `detectors.BIMI`) resolves
`default._bimi.<target>` TXT, requires a `v=BIMI1` first field, parses the `l=`/`a=`
URLs, extracts their hostnames, and probes each with `CNAMEChain` (the
authoritative NXDOMAIN probe used by every other DNS-only vector). A dangling host
yields a `POTENTIAL` `bimi` finding carrying the BIMI owner name in `Service` and
the dangling host in the new `BIMIURIHost` field; the evidence names which tag
pointed at it. Hosts backing both `l=` and `a=` are deduplicated to one finding
that attributes both tags. The `a=self` and empty-value forms (no remote host) and
non-http(s) URLs are never probed. A domain with no BIMI record, or whose asset
hosts resolve, is the healthy case and is not flagged — low-noise, consistent with
the other vectors.

Wired end to end: new `finding.VectorBIMI` + `BIMIURIHost` field; `bimiVector` in
the scanner with the `NoBIMI` opt-out; `--no-bimi` CLI flag; rendering in the
terminal, CSV (`target` column), and SARIF (rule descriptor + message) outputs;
and the vector added to `summaryVectorOrder` so the by-vector triage summary
reconciles (the Rank 17 lesson). The stale `allEmittableVectors` test slice was
also corrected to include `mtasts` (already shipped) and `bimi`.

Guarded by 11 new detector tests (`pkg/detectors/bimi_test.go`): dangling logo
host, dangling VMC host, shared-host dedup, live hosts (no finding), no record,
non-BIMI TXT ignored, `self`/empty values ignored, evidence wording, case-
insensitive version, URL-host parsing, and the vector-constant pin. Plus a BIMI
case added to the terminal, CSV, and SARIF per-vector output tests. Suite grew
191 → 202 test functions; full suite green, `go vet` clean.

**Why this over the rotation detector:** A passive scanner cannot measure DKIM
key age from DNS; BIMI is a real, exploitable, DNS-only dangling-host vector that
extends the email-auth-trust surface the tool already owns. New API surface (one
vector, one field, one flag), no architectural change.

**Complexity:** Low-Med — one new detector file mirroring `mtasts.go`, one finding
field + vector constant, scanner/CLI/output wiring, 11 detector tests. No new
dependency (uses the existing `miekg/dns` resolver and stdlib `net/url`).

---

## Rank 19 — DNSSEC orphaned-DS detection (twelfth vector) — ✅ IMPLEMENTED (Phase 2, Rotation 25)

**Status:** Shipped. Rotation 25's directive offered two candidates — a **DMARC
aggregate report-URI dangling host** check or a **DNSSEC DS-record orphan** check
— with instructions to assess the codebase first. Assessment found:

- The **DMARC aggregate report-URI dangling host is already shipped.** The DMARC
  detector (`detectors.DMARC`, Ranks 8 + 15) already resolves every `rua=`/`ruf=`
  report domain and emits a `POTENTIAL dmarc` finding for any that is NXDOMAIN
  (the report-interception case, carried in `DMARCURI`). Re-implementing it would
  duplicate existing coverage, so it was rejected.
- The **DNSSEC DS-record orphan was not present** anywhere in the codebase (DNSSEC
  was referenced only as context for the DANE TLSA vector). It is a clean,
  purely-DNS-detectable, high-severity misconfiguration in exactly the
  dangling-delegation family the tool specialises in — applied to the DNSSEC
  chain-of-trust plane — so it was implemented.

An **orphaned DS** is a domain whose **parent** zone publishes a `DS` (Delegation
Signer, RFC 4034) record — committing every DNSSEC-validating resolver to build an
authenticated chain of trust into the domain's zone — while the domain's own zone
publishes **no `DNSKEY`**, so that chain cannot be completed. It is the classic
outcome of disabling DNSSEC at the child, or migrating DNS providers (which
generate fresh keys), without first removing the `DS` at the registrar. DNSSEC
fails closed: every validating resolver (the default at Google `8.8.8.8`,
Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`, and most ISPs) returns `SERVFAIL` for the
**entire zone**, taking the domain and all its services dark for a large share of
the internet while it resolves normally on non-validating resolvers — a
self-inflicted denial of service and one of the most common production DNSSEC
outages. Unlike the takeover vectors its harm is availability, not attacker
interception, but it is a high-severity finding an operator urgently needs
surfaced.

The detector (`pkg/detectors/dnssec.go`, `detectors.DNSSEC`) queries `DS` for the
target (answered by the parent). No `DS` → unsigned delegation, the common
default, nothing to orphan → no finding. With a `DS` present it queries `DNSKEY`
(answered by the child): a key present is the healthy signed case; **no `DNSKEY` —
or a `SERVFAIL` on the `DNSKEY` query, which a validating resolver returns
precisely because the chain is already broken** — yields a `POTENTIAL dnssec`
finding keyed on the target, carrying the orphaned `DS` key tags (deduplicated and
ascending-sorted) in the new `DSKeyTags` field so the operator knows exactly which
registrar records to remove. Two new resolver primitives back it: `DSKeyTags`
(parent `DS` key tags) and `HasDNSKEY` (child key presence, with `SERVFAIL` mapped
to `ErrZoneDeleted` so the break is treated as confirmation, not an indeterminate
error). The detector deliberately does NOT chase a `DS`/`DNSKEY` key-tag mismatch
(a far rarer, separately-classifiable case): the presence of ANY child key is the
low-noise, low-false-positive signal that the zone is signed.

Wired end to end: new `finding.VectorDNSSEC` + `DSKeyTags` field; `dnssecVector`
in the scanner with the `NoDNSSEC` opt-out; `--no-dnssec` CLI flag; rendering in
the terminal, CSV (`target` column), and SARIF (rule descriptor + message)
outputs; the vector added to `summaryVectorOrder` and `allEmittableVectors` so the
by-vector triage summary reconciles (the Rank 17 lesson); and the root command's
Short/Long descriptions updated. A shared `formatKeyTags` helper in `pkg/output`
keeps the key-tag wording identical across the three rendered formats.

Guarded by 9 new detector tests (`pkg/detectors/dnssec_test.go`): orphaned DS,
`SERVFAIL`-is-orphan, healthy signed zone (no finding), unsigned delegation (no
finding), multi-DS dedup+sort, evidence wording, blank-target safety, the
vector-constant pin, and the key-tag normaliser. Plus 5 resolver tests
(`DSKeyTags` returns/empty, `HasDNSKEY` present/absent/SERVFAIL) and a DNSSEC case
added to the terminal, CSV, and SARIF per-vector output tests. Full suite green,
`go vet` clean.

**Why this over re-implementing the DMARC report-URI check:** that check already
exists; the DNSSEC orphan is a genuinely new, exploitable-by-omission, DNS-only
vector that extends graverobber from the takeover surface into the availability
surface of the DNS control plane it already owns. New API surface (one vector, one
field, one flag, two resolver methods), no architectural change.

**Complexity:** Low-Med — one new detector file, two resolver primitives, one
finding field + vector constant, scanner/CLI/output wiring, 14 new tests. No new
dependency (uses the existing `miekg/dns` resolver, which already exposes `DS` and
`DNSKEY` record types).

---

## Rank 20 — CAA `iodef` dangling-report-host detection — ✅ IMPLEMENTED (Phase 2, Rotation 26)

**Status:** Shipped. Rotation 26's directive offered two candidates — a **CAA
dangling** check or an **SPF include-chain dangling host** check — as the 13th
vector, with instructions to assess the codebase first. Assessment found **both
directed candidates already shipped**, so per the directive the next logical
roadmap improvement was implemented:

- **CAA dangling-issuer is already shipped.** `detectors.CAA` (Rank 16) already
  resolves every `issue`/`issuewild` CA domain and emits a `POTENTIAL caa`
  finding for any that is NXDOMAIN (carried in `CAAIssuer`), plus the permissive
  `*` any-CA case. Re-implementing it would duplicate existing coverage.
- **SPF include-chain dangling is already shipped.** `detectors.SPF` (the apex
  detector plus Rank 13's `redirect=` work) already recurses `include:` and
  `redirect=` references up to `maxSPFDepth` and emits a `POTENTIAL spf` finding
  for any referenced domain that is NXDOMAIN. Re-implementing it would duplicate
  existing coverage.

The genuine gap found in the CAA detector: it explicitly **skipped the `iodef`
tag** (RFC 8659 §4.4), the URL where a CA reports a forbidden issuance attempt.
The `iodef` value is a `mailto:` address or an `http(s)://` endpoint (RFC 6546);
if its **host is NXDOMAIN**, an attacker who registers it **intercepts the CAA
violation reports** — a reconnaissance channel disclosing exactly which CAs are
being probed against the target's policy (mis-issuance/attack attempts). It is the
CAA analogue of the DMARC `rua`/`ruf` report-interception case (Rank 8), applied
to CAA's reporting plane rather than to certificate issuance — the same
dangling-host family graverobber specialises in.

This was implemented as a **third sub-case of the existing `caa` vector**, not a
new vector: no new vector constant, no new finding field (reuses `CAAIssuer` for
the claimable report host), no new CLI flag (covered by the existing `--no-caa`
opt-out). The detector now branches on the `iodef` tag, parses the report host
via a new `caaIodefHost` helper (a `mailto:` host-after-`@` parser plus a
`net/url` `http(s)://` authority parser, mirroring the DMARC mailto parser and the
BIMI URL parser already in the codebase, with a case-insensitive scheme match),
and emits a `POTENTIAL caa` finding when the host is NXDOMAIN — using the same
`CNAMEChain` (TypeA) NXDOMAIN probe as every other dangling-host detector. The
evidence string distinguishes the report-interception case from the issuance case.

Guarded by 5 new CAA tests (`pkg/detectors/caa_test.go`): the `caaIodefHost`
parser unit table (mailto/http(s), case-folding, port-strip, unsupported-scheme,
host-less, empty), full-detector `mailto:` dangling, full-detector `https://`
dangling, and a live-iodef-no-finding case. The pre-existing
`TestCAA_LiveIssuerNoFinding` (which already carried a live `iodef` record)
continues to pass, confirming no regression in the healthy path. Full suite green,
`go vet` clean. README CAA section, vector summary table, and `--no-caa` flag doc
updated; `VectorCAA` and `CAAIssuer` doc comments extended to the third sub-case.

**Why this over re-implementing a directed candidate:** both directed candidates
were already shipped (verified in-code), and the directive instructs picking the
next logical roadmap improvement in that case. The `iodef` host is a genuinely new,
exploitable-by-omission, DNS-only signal on a record class the detector already
parses but previously ignored — closing CAA coverage end to end (issuance +
reporting + permissive) with zero new API surface.

**Complexity:** Low — one detector branch, one parser helper, no new vector/field/
flag, 5 new tests, README + doc-comment updates. No new dependency (`net/url` is
stdlib; the `miekg/dns` resolver already returns `iodef` CAA records).

---

## Rank 21 — SPF `a:`/`mx:` mechanism dangling detection — ✅ IMPLEMENTED (Phase 2, Rotation 27)

**Status:** Shipped. Rotation 27's directive offered two candidates — a **TLSA/DANE
orphaned-pin for a new MX host** or a **DKIM selector dangling-key** check — as the
14th DNS attack vector, with instructions to assess the codebase first. Assessment
found **both directed candidates already shipped**, so per the directive (the same
disposition as Rank 20) the next logical roadmap improvement was implemented:

- **TLSA/DANE orphaned-pin is already shipped.** `detectors.TLSA` (the 9th vector)
  already iterates **every** MX host of the target, probes the DANE pin at
  `_25._tcp.<mxhost>`, and emits a `POTENTIAL tlsa` finding when the pinned MX host
  is NXDOMAIN. There is no "new MX host" case it omits — it already covers all of
  them, with per-host dedup. Re-implementing it would duplicate existing coverage.
- **DKIM selector dangling-key is already shipped.** `detectors.DKIM` already emits
  a `CONFIRMED dkim` finding for a selector whose `_domainkey` CNAME target is
  NXDOMAIN (Rank 6) and a `LIKELY dkim` finding for a weak inline RSA key below the
  RFC 8301 floor (Rank 14). Re-implementing it would duplicate existing coverage.

The genuine gap found in the SPF detector: it recursed `include:` and `redirect=`
references but **silently ignored the `a:<domain>` and `mx:<domain>` mechanisms**
(RFC 7208 §5.3/§5.4). With an explicit domain argument these mechanisms authorise
the named domain's A/AAAA (or MX-host) address records to send mail as the target.
If that domain is NXDOMAIN, an attacker who registers it points its address records
at their own host and **every message they send passes SPF for the target** — the
exact same SubdoMailing takeover the `include:`/`redirect=` sub-case covers, on two
mechanisms the detector previously skipped. This completes SPF dangling-reference
coverage end to end (`include:` + `redirect=` + `a:` + `mx:`).

This was implemented as an **extension of the existing `spf` vector**, not a new
vector: no new vector constant, no new finding field (reuses `SPFInclude` for the
claimable domain), no new CLI flag (covered by the existing `--no-spf` opt-out).
`spfReference` gained a `directive` string (replacing the boolean `redirect` flag)
so the evidence string names which of the four directives pointed at the dangling
host; `spfReferences` now strips a mechanism qualifier prefix and parses `a:`/`mx:`
via a new `spfDualCIDRDomain` helper that strips the RFC 7208 `/cidr`//`/cidr`
dual-CIDR suffix. Bare `a`/`mx` (no `:domain`) reference the target's own records
and are intentionally NOT extracted. `a:`/`mx:` references are terminal (they name
an address host, not a downstream SPF policy), so only `include:`/`redirect=`
recurse — bounded as before by the RFC 7208 ten-lookup cap.

Guarded by 4 new full-detector tests plus an expanded `TestSPFReferences` table
(`pkg/detectors/detectors_test.go`, driven by the existing local-UDP `spfDNSServer`
harness — integration-first, real DNS round-trips): `a:` dangling (with dual-CIDR
suffix), `mx:` dangling, bare-`a`/`mx`-no-finding (proves the target's own records
are never probed as external), and live-`a:`-no-finding. Full suite green, `go vet`
clean. README SPF section, vector table, `--no-spf` flag doc, the SARIF rule
description, and the `VectorSPF`/`SPFInclude` doc comments updated to the four
directives.

**Why this over re-implementing a directed candidate:** both directed candidates
were already shipped (verified in-code), and the directive instructs picking the
next logical roadmap improvement in that case. The `a:`/`mx:` mechanisms are a
genuinely new, exploitable-by-omission, DNS-only signal on a record the detector
already parses but previously ignored — closing SPF reference coverage with zero
new API surface, mirroring the Rank 20 `iodef` disposition exactly.

**Complexity:** Low — one parser branch + one helper, a struct-field swap, no new
vector/field/flag, 4 new tests + 1 expanded table, README + doc-comment + SARIF
updates. No new dependency.

---

## Rank 22 — TLSRPT dangling-report-destination detection (thirteenth vector) — ✅ IMPLEMENTED (Phase 2, Rotation 28)

**Status:** Shipped. Rotation 28's directive named two candidates — **DKIM selector
enumeration** or **MTA-STS dangling policy** — as the next DNS/email-security
vector, with instructions to verify which (if either) was already shipped and, if
both were, to pick the next best unshipped gap. Assessment found **both directed
candidates already shipped**:

- **DKIM selector enumeration is already shipped.** `detectors.DKIM` (Ranks 6 +
  14) probes the `DefaultDKIMSelectors` list (overridable via `--selectors`),
  emits a `CONFIRMED dkim` finding for a selector whose `_domainkey` CNAME target
  is NXDOMAIN, and a `LIKELY dkim` finding for a weak inline RSA key below the
  RFC 8301 1024-bit floor. Re-implementing it would duplicate existing coverage.
- **MTA-STS dangling policy is already shipped.** `detectors.MTASTS` (the 10th
  vector) detects an advertised `_mta-sts` TXT signal whose `mta-sts.<domain>`
  policy host is NXDOMAIN. Re-implementing it would duplicate existing coverage.

Per the directive, the next best unshipped gap was implemented: **SMTP TLS
Reporting (TLSRPT, RFC 8460) dangling-report-destination detection** as
`VectorTLSRPT` ("tlsrpt"), the 13th vector. A domain advertises TLSRPT with a
`v=TLSRPTv1` TXT record at `_smtp._tls.<domain>` carrying a `rua=` tag — a
comma-separated list of report destinations, each a `mailto:` address (the domain
after `@` receives the daily SMTP-TLS failure reports) or an `https:` collector
host. When a report destination is decommissioned but the record is left behind,
an attacker who reclaims the gone mailto domain or collector host **receives every
TLSRPT report sent for the target**: delivery-counterparty and infrastructure
reconnaissance, and — critically — a real-time view of which senders are failing
TLS to the domain, the exact failures an active TLS-downgrade/MITM against the
target's inbound mail produces. The owner is blinded to the very alerts that would
expose the attack. This is the SMTP-TLS analogue of the DMARC `rua`/`ruf`
report-domain takeover (Rank 8), applied to the TLS-reporting plane, and it closes
graverobber's coverage of the MTA-STS/DANE control surface (MTA-STS policy host +
TLSA pin + TLSRPT report destination).

Implemented as a new detector `pkg/detectors/tlsrpt.go` (`TLSRPT`), wired into the
scanner fan-out behind `Options.NoTLSRPT` / `--no-tlsrpt` (opt-out, on by default),
mirroring the BIMI/MTA-STS detectors exactly: parse the TXT record, extract each
report host, probe with `CNAMEChain` (the authoritative NXDOMAIN probe every
DNS-only vector uses), emit a `POTENTIAL tlsrpt` finding per dangling host (keyed
on the target, owner name in `Service`, dangling host in the new `TLSRPTURIHost`
field; destinations naming the same host are deduplicated). `mailto:` domains and
`https:` URL hosts are both parsed; any other scheme (and a malformed `mailto:`
with no domain) names no remote host and is skipped, so the detector never probes
a host it cannot positively identify.

Guarded by 12 new tests in `pkg/detectors/tlsrpt_test.go` (driven by a local-UDP
DNS harness, integration-first, real DNS round-trips): dangling `mailto:` domain,
dangling `https:` host, mixed destinations with only the NXDOMAIN one flagged,
shared-host single-finding dedup, all-live no-finding, no-record no-finding,
non-TLSRPT TXT ignored, case-insensitive version token, evidence wording, and a
`tlsRptReportHosts` parser table (mailto/https/malformed-mailto/non-http-scheme/
no-rua). Plus a scanner opt-out test (`TestRun_NoTLSRPTDisablesTLSRPTVector`), the
`allEmittableVectors`/`summaryVectorOrder` reconciliation (the Rank 17 lesson), and
new output cases in the terminal/CSV/SARIF "every vector" regression tables. Full
suite green, `go vet` clean. README (headline, vector table + prose, `--no-tlsrpt`
flag, a dedicated TLSRPT section, JSONL example, terminal-detail list), the SARIF
rule descriptor + result detail, and the CLI `Short`/`Long` help updated.

**Why this over re-implementing a directed candidate:** both directed candidates
were already shipped (verified in-code), and the directive instructs picking the
next best unshipped gap in that case. TLSRPT is a genuinely new, exploitable,
DNS-only signal on the SMTP-TLS reporting plane — the only email-security report
channel graverobber did not yet cover — completing the MTA-STS/DANE control surface
and mirroring the DMARC report-domain disposition.

**Complexity:** Low-Med — one new detector, one new vector + field + flag, one
scanner seam, 12 new tests + reconciliation, README + SARIF + help updates. No new
dependency.

---

## Rank 23 — DMARC `https:` report-URI dangling-host detection — ✅ IMPLEMENTED (Phase 2, Rotation 29)

**Status:** Shipped. Rotation 29's directive named two candidates — a **BIMI
dangling authority-domain** check or a **DMARC report-uri dangling** check — as the
next DNS-security vector, with instructions to verify which (if either) was already
shipped and, if both were, to pick the next best unshipped gap. Assessment found
**both directed candidates already shipped** in their named form:

- **BIMI dangling authority-domain is already shipped.** `detectors.BIMI` (Rank 18,
  the 11th vector) already parses the `a=` tag — the VMC (Verified Mark
  Certificate) **authority** URL — alongside the `l=` logo URL, extracts its host
  via `bimiURLHost`, and emits a `POTENTIAL bimi` finding when that host is
  NXDOMAIN. The `a=` (authority) asset host is the BIMI authority-domain; it is
  already covered end to end. Re-implementing it would duplicate existing coverage.
- **DMARC report-URI dangling is already shipped — for the `mailto:` transport.**
  `detectors.DMARC` (Rank 8) already parses every `rua=`/`ruf=` `mailto:` URI,
  extracts the domain after the `@`, and emits a `POTENTIAL dmarc` finding when it
  is NXDOMAIN.

Per the directive, the next best unshipped gap **inside the named DMARC report-URI
candidate** was implemented: the DMARC report-URI parser handled only the
`mailto:` transport and **silently dropped every `https:` report URI**. RFC 7489
§6.2 defines each `rua=`/`ruf=` value as a comma-separated list of DMARC URIs, and
§A.5 registers **two** transports — `mailto:` and `https:` (an HTTPS POST endpoint,
the deployment model the large DMARC-as-a-service vendors offer). If an `https:`
collector host is decommissioned but the record is left behind, an attacker who
reclaims it **receives every DMARC aggregate/forensic report sent for the target** —
the identical report-interception takeover the `mailto:` sub-case covers, on a
transport the detector previously ignored. This closes DMARC report-URI coverage
end to end (`mailto:` + `https:`).

Implemented as an **extension of the existing `dmarc` vector**, not a new vector:
no new vector constant, no new finding field (reuses `DMARCURI` for the claimable
host), no new CLI flag (covered by the existing `--no-dmarc` opt-out). The
`mailto:`-only `dmarcReportDomains` parser was generalised to `dmarcReportHosts`,
which delegates each URI to a new `dmarcURIHost` helper — a `mailto:`
host-after-`@` parser (with the RFC 7489 §6.2 `!<size>` limit stripped) plus a
`net/url` `http(s)://` authority parser, reusing the package-local `cutPrefixFold`
for the case-insensitive scheme match. This mirrors the CAA `iodef=` (`caaIodefHost`,
Rank 20) and BIMI (`bimiURLHost`, Rank 18) parsers exactly. Any other scheme, or a
URI with no host, is skipped — the detector never probes a host it cannot positively
identify. The evidence string and SARIF/CLI/README wording moved from "report
domain" to "report host" to reflect both transports.

Guarded by new/updated tests in `pkg/detectors/detectors_test.go` (driven by the
existing local-UDP `dmarcDNSServer` harness — integration-first, real DNS
round-trips): a `dmarcURIHost` unit table (mailto/https/http, size-limit, case-fold,
port-strip, no-@, empty-domain, unsupported-scheme, no-authority, bare-host),
an expanded `dmarcReportHosts` table (https host, mixed-transport, upper-case-host,
ftp-skipped), a full-detector dangling-`https:`-host case, a live-`https:`-host
no-finding case, and a mixed-transport-only-dangling-flagged case. Full suite green
(`-race`), `go vet` clean. README DMARC section (heading, sub-case prose, vector
table, flag doc, JSONL + CSV examples, terminal-detail list), the SARIF rule
descriptor, the CLI `Long`/flag help, and the `VectorDMARC`/`DMARCURI` doc comments
updated to the two transports.

**Why this over re-implementing a directed candidate:** both directed candidates
were already shipped (verified in-code), and the directive instructs picking the
next best unshipped gap in that case. The `https:` report transport is a genuinely
new, exploitable-by-omission, DNS-only signal on a record the detector already
parses but previously ignored — closing DMARC report-URI coverage with zero new API
surface, mirroring the Rank 20 (`iodef` http(s)) and Rank 22 (TLSRPT https) report-
host dispositions exactly.

**Complexity:** Low — one parser generalisation + one helper, no new vector/field/
flag, new tests + expanded tables, README + SARIF + help + doc-comment updates. No
new dependency (`net/url` is stdlib; the resolver already returns the TXT record).

---

## Rank 24 — SPF DNS-lookup-limit (`permerror`) detection — ✅ IMPLEMENTED (Phase 2, Rotation 30)

**Status:** Shipped. Rotation 30's directive named two candidates — **SPF
include-depth** or **DKIM key-rotation** — as the next vector to assess.
Assessment of the codebase confirmed **neither was shipped**; both names point at
the same real gap on the SPF surface (the RFC 7208 §4.6.4 ten-DNS-lookup cap), so
the directive's first-named candidate was implemented in its full RFC form.

RFC 7208 §4.6.4 caps an SPF evaluation at **ten DNS-querying mechanisms and
modifiers** — `include`, `a`, `mx`, `ptr`, `exists`, and `redirect=` each count
as one lookup; `ip4`, `ip6`, `exp=`, `all`, and the version tag do not. A record
whose total (across the apex and every recursed `include:`/`redirect=` target)
exceeds ten MUST yield a `permerror` at every conforming SPF receiver — the SPF
check hard-fails, and under DMARC alignment the domain becomes **spoofable by
omission**: every receiver treats spoofed mail the same as legitimate mail
because SPF cannot return Pass for either. This is the SPF analog of the DMARC
`p=none` weak-policy sub-case (Rank 15): a present-but-broken email-auth record
that confers no protection. It is a common production failure mode — the
"include explosion" antipattern, where a domain accrues ESPs over time and quietly
slips past the ten-lookup threshold without anyone noticing until the receivers
start `permerror`ing weeks of legitimate mail.

Implemented as an **extension of the existing `spf` vector**, not a new vector:
one new finding field (`SPFLookups int`, mirroring the `DKIMKeyBits` integer
sub-case-discriminator shape from Rank 14), no new CLI flag (covered by the
existing `--no-spf` opt-out). The detector adds two helpers: `spfQueryingMechanisms`
tallies the §4.6.4-counted mechanisms in a single record (with the qualifier-prefix
strip and the bare-`a`/`mx`/`ptr` plus `/cidr` form handling RFC 7208 §5.3-5.5
requires; `all`/`exp=` are deliberately excluded), and `spfDNSLookups` walks the
recursed include/redirect graph and sums the per-record counts. The graph walk
reuses the existing `spfReferences` parser, a per-call `visited` map for
cycle-safety (include loops are independently a `permerror` and would otherwise
stack-overflow), and the same `maxSPFDepth` hard recursion guard as the dangling
traversal. The lookup-limit and dangling traversals share no state — each
sub-case fires independently of the others, mirroring the Rank 18 (`p=none` +
dangling) two-sub-case shape.

Guarded by five new tests in `pkg/detectors/detectors_test.go`: a
`spfQueryingMechanisms` unit table covering every counted/uncounted mechanism
and modifier, every form-suffix (`:`, `/`, `//`), qualifier-prefix strip,
`exp=` exclusion, false-match guards (`all` vs `a`), and exactly-at-cap; a new
`spfMultiTXTDNSServer` integration harness driving the full detector against a
multi-domain TXT zone; an over-cap (12-lookup) finding case asserting field
shape, evidence string, and target-keyed subdomain; an at-cap (10-lookup)
no-finding case; a below-cap (3-lookup) no-finding case (the common-path
regression guard); and a cyclic include-graph (A → B → A) case verifying the
visited-map short-circuits the cycle and yields a deterministic count.
Output-rendering tests in `pkg/output/{output,csv,sarif}_test.go` were extended
with a lookup-limit case for the terminal, CSV, and SARIF writers, and the
JSONL omit-empty-fields regression guard was extended with the new
`spf_lookups` field name. Full suite green under `-race`; `go vet` clean. README
"Why these vectors" table, the SPF section (now three sub-cases, with the
"DNS-lookup-limit breach" prose, the §4.6.4 wording, and a new JSONL example
line), the `--no-spf` flag-table description, the cobra `--no-spf` flag short
help, the SARIF rule descriptor (`name`/`short`/`full` all updated), the
`VectorSPF` doc-comment in `finding.go`, and the `SPF` detector doc-comment
were all updated to cover the new sub-case. No new dependency.

**Why this over a DKIM key-rotation check:** DKIM key rotation cannot be detected
from a single DNS scan — it requires per-selector history (when did this key
first appear?). graverobber is a stateless single-shot scanner; history belongs
to the orchestration layer (cron + diff). The SPF §4.6.4 cap is the **DNS-only
single-scan signal** the directive's two candidates collapse to in this codebase.

**Complexity:** Low — one new helper pair (`spfQueryingMechanisms` +
`spfDNSLookups`), one new finding field, no new vector/flag, five new detector
tests + four extended output tests, README + SARIF + CLI help + doc-comment
updates. No new dependency.

---

## Rank 25 — DNSSEC weak-algorithm detection — ✅ IMPLEMENTED (Phase 2, Rotation 31)

**Status:** Shipped. Rotation 31's directive named two candidates — **DNSKEY
algorithm weakness** or **NS lame-delegation** — as the next DNS audit vector
to assess. Assessment found:

- **NS lame-delegation is partially covered today.** The existing NS detector
  (`detectors.NS`) classifies a deleted hosted zone (every delegated
  nameserver returns SERVFAIL/REFUSED) — which is the strict-lame case.
  Per-NS partial lameness (some delegated nameservers answer authoritatively,
  some don't) is a different signal that overlaps with general DNS-health
  monitors; it was deprioritised in favour of the cleaner crypto-weakness gap.
- **DNSKEY algorithm weakness was not present** anywhere in the codebase. The
  existing DNSSEC detector handled only the orphaned-DS sub-case (chain
  missing a link) and `continue`d past every signed delegation regardless of
  the algorithm it used. The IANA DNS Security Algorithm Numbers registry
  contains six algorithms RFC 8624 §3.1 forbids (`MUST NOT`) or deprecates
  (`NOT RECOMMENDED`), plus a DS digest type (SHA-1, RFC 8624 §3.3 `NOT
  RECOMMENDED`) — a domain signing with any of them has a present-but-broken
  chain that a well-resourced attacker can forge, defeating the protection
  DNSSEC exists to provide. This is the second-sub-case completion the prior
  rotations applied to SPF (`redirect=`/`a:`/`mx:`), DKIM (weak inline key),
  DMARC (`p=none` + `https:` report URI), and CAA (`iodef`), applied now to
  the DNSSEC plane.

Implemented as a second sub-case of the existing `dnssec` vector — no new
vector constant, no new CLI flag (covered by the existing `--no-dnssec`
opt-out). Two new resolver primitives back it: `DNSKEYAlgorithms` (the
algorithm field of every child DNSKEY, mirroring `HasDNSKEY` but returning
each key so the detector can flag every weakness) and `DSAlgorithms` (the
key-algorithm and digest-type fields of every parent DS, mirroring
`DSKeyTags`). The detector now branches when the chain is healthy:
`weakAlgorithmFinding` inspects both surfaces (every DNSKEY's `Algorithm`,
every DS's `Algorithm` and `DigestType`) against the RFC 8624 mapping in
`weakDNSKEYAlgorithm` / `weakDSDigest`, and emits a `POTENTIAL` `dnssec`
finding listing every distinct weakness in a deduped, sorted
`DNSSECWeakAlgs` slice. The DS key tags ride along in `DSKeyTags` so an
operator can map the weakness back to specific registrar records. The two
sub-cases are distinguished by whether `DNSSECWeakAlgs` is populated.

**Schema:** new `DNSSECWeakAlgs []string` (`json:"dnssec_weak_algs,omitempty"`)
on `Finding`. No new flag, no new vector constant.

Wired end to end. All four output paths render the new sub-case — terminal
(`dnssec weak algorithm(s) RSASHA1 (RFC 8624 deprecated — forgeable chain)`),
JSONL (`dnssec_weak_algs`), SARIF (`graverobber/dnssec` rule descriptor
extended to cover both sub-cases, distinct result detail per sub-case), and
CSV (the weakness names in the `target` column). The SARIF
`partialFingerprint` remains `(subdomain, vector)` since both sub-cases trace
to the same delegation. The orphan sub-case is unchanged and keeps priority
when no DNSKEY is present (verified by
`TestDNSSEC_OrphanFindingHasNoWeakAlgs`).

Guarded by 5 new detector tests in `pkg/detectors/dnssec_test.go` plus an
algorithm-aware `dnssecDNSServerEx` harness extension:
`TestWeakDNSKEYAlgorithm` (the RFC 8624 mapping table, every forbidden /
deprecated value + every modern safe value), `TestWeakDSDigest` (the digest
mapping), `TestDNSSEC_WeakChildKeyAlgorithmPotential` (the full detector with
a RSASHA1 child key), `TestDNSSEC_WeakDSDigestPotential` (SHA-1 DS digest
with an ECDSA key — weakness in the DS even when the key is modern),
`TestDNSSEC_MultipleWeaknessesDedupSorted` (consolidation across multiple
DNSKEYs and DS records into one finding with deduplicated, sorted weakness
names), `TestDNSSEC_ModernAlgorithmsNoFinding` (the regression guard — a
healthy ECDSA + SHA-256 delegation produces no finding), and
`TestDNSSEC_OrphanFindingHasNoWeakAlgs` (sub-case priority: orphan still
fires when no DNSKEY is present, never the weak-algorithm branch). Plus 4
new resolver tests in `pkg/resolver/resolver_test.go`:
`TestDSAlgorithms_ReturnsAlgoAndDigest`, `TestDSAlgorithms_EmptyWhenNoDS`,
`TestDNSKEYAlgorithms_ReturnsEveryKey`,
`TestDNSKEYAlgorithms_ServfailIsZoneDeleted`. The terminal, CSV, and SARIF
per-vector output tests gained a `dnssec-weak-algorithm` case each, and the
JSONL omit-empty-fields regression guard was extended with `dnssec_weak_algs`
and `ds_key_tags`. Full suite green under `-race`, `go vet` clean. README
DNSSEC section restructured into two sub-cases with the RFC 8624 algorithm
table and a new JSONL example line; `--no-dnssec` flag-table description and
the headline vector table row updated.

**Why this over NS lame-delegation:** the NS detector's existing
all-nameservers-SERVFAIL signal already covers the takeover-relevant
lame-delegation case; per-NS lameness without takeover is a DNS-health
signal that overlaps with dedicated monitoring tools. DNSKEY algorithm
weakness, by contrast, is a genuinely new, exploitable-by-omission,
DNS-only signal on a record the detector already parses but previously
inspected only for presence — closing DNSSEC coverage with the same
"complete an existing vector" disposition that worked for the SPF / DKIM /
DMARC / CAA second sub-cases.

**Complexity:** Low-Med — two new resolver methods, one new helper trio in
the detector (`weakAlgorithmFinding` + `weakDNSKEYAlgorithm` +
`weakDSDigest`), one schema field, no new vector/flag, three output-detail
arms (terminal/CSV/SARIF), 9 new tests + 3 extended output tables + 1
extended JSONL guard, README + POST_V01 updates. No new dependency
(`miekg/dns` already exposes the `Algorithm` and `DigestType` fields on
`*dns.DNSKEY` and `*dns.DS`).

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
| 2 | Active verifier: S3, GitHub Pages, Azure ✅ | Medium | High (accuracy) | No (SetVerifier seam) |
| 3 | MX record fourth vector ✅ | Medium | High (new coverage) | Yes (new vector + flag) |
| 4 | NS provider list sync from indianajson ✅ | Low-Med | Medium (accuracy) | No |
| 5 | CT log monitoring subcommand ✅ | Medium | High (unique feature) | No (new subcommand) |
| 6 | DKIM selector dangling CNAME ✅ | Medium | Medium (new coverage) | Yes (new vector + flag) |
| 7 | Second-order JS reference scanning ✅ | High | Medium (niche) | Yes (new mode) |
| 8 | DMARC report-domain dangling vector ✅ | Low-Med | High (completes email-auth) | Yes (new vector + flag) |
| 9 | Terminal output detail for MX/DKIM/DMARC ✅ | Low | High (default-mode correctness) | No |
| 10 | SARIF 2.1.0 output for CI / Code Scanning ✅ | Low-Med | High (CI integration) | No (new flag only) |
| 11 | CSV output for spreadsheet / ticket triage ✅ | Low | Med-High (analyst triage) | No (new flag only) |
| 12 | AXFR zone-transfer misconfiguration (7th vector) ✅ | Medium | High (new DNS surface, force-multiplier) | Yes (new vector + flag) |
| 13 | SPF `redirect=` modifier dangling detection ✅ | Low | High (completes SPF coverage, same takeover) | No |
| 14 | DKIM weak inline-key detection ✅ | Low | High (completes DKIM coverage, forgeable signatures) | Yes (new field, no flag) |
| 15 | DMARC monitor-only (`p=none`) policy detection ✅ | Low | High (completes DMARC coverage, spoofable domain) | Yes (new field, no flag) |
| 16 | CAA misconfiguration (8th vector) ✅ | Low-Med | High (new DNS-security surface, MITM TLS) | Yes (new vector + flag) |
| 17 | Triage summary by-vector completeness (AXFR/CAA) ✅ | Trivial | High (default-mode correctness) | No |
| 18 | BIMI dangling-asset-host detection (11th vector) ✅ | Low-Med | High (new email-auth-trust surface, brand-impersonation) | Yes (new vector + field + flag) |
| 19 | DNSSEC orphaned-DS detection (12th vector) ✅ | Low-Med | High (new availability surface, self-inflicted SERVFAIL outage) | Yes (new vector + field + flag) |
| 20 | CAA `iodef` dangling-report-host detection ✅ | Low | High (completes CAA coverage, report interception) | No (3rd sub-case of `caa`, reuses field + flag) |
| 21 | SPF `a:`/`mx:` mechanism dangling detection ✅ | Low | High (completes SPF reference coverage, same SubdoMailing takeover) | No (extends `spf`, reuses field + flag) |
| 22 | TLSRPT dangling-report-destination detection (13th vector) ✅ | Low-Med | High (new SMTP-TLS reporting surface, report interception + downgrade-masking) | Yes (new vector + field + flag) |
| 23 | DMARC `https:` report-URI dangling-host detection ✅ | Low | High (completes DMARC report-URI coverage, same report interception) | No (extends `dmarc`, reuses field + flag) |
| 24 | SPF DNS-lookup-limit (§4.6.4 `permerror`) detection ✅ | Low | High (completes SPF coverage, spoofable-by-omission via DMARC alignment collapse) | Yes (new field, no flag) |
| 25 | DNSSEC weak/deprecated algorithm detection (RFC 8624) ✅ | Low-Med | High (completes DNSSEC coverage, forgeable chain of trust) | Yes (new field, no flag) |
