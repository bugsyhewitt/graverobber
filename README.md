# graverobber

**Subdomain takeover scanner for CNAME, NS, SPF, MX, DKIM, and DMARC dangling records, plus AXFR zone-transfer and CAA misconfiguration.**

> Digs up the subdomains your target left for dead — CNAME, NS, SPF, MX, DKIM,
> and DMARC takeover detection plus unauthenticated AXFR zone-transfer discovery
> and CAA misconfiguration in one pipeline-friendly Go binary.

`graverobber` is the only maintained Go binary that covers **CNAME**, **NS**,
**SPF**, **MX**, **DKIM**, and **DMARC** takeover vectors plus **AXFR**
zone-transfer and **CAA** misconfiguration in a single tool. It is a static binary with no
runtime, reads targets from stdin/file/flag, streams JSONL, and uses the
exit-code conventions of the `httpx`/`subfinder` family so it drops straight into
a recon pipeline.

---

## Why these vectors

| Vector | Signal | Real-world campaign |
|---|---|---|
| CNAME | Dangling CNAME → fingerprint match against a known-vulnerable service | The classic takeover; ~60+ services covered |
| NS    | Delegated DNS hosted zone deleted at the provider, re-claimable | Hazy Hawk (.edu campaign, 2025–2026) |
| SPF   | An SPF `include:` mechanism or `redirect=` modifier points at an unregistered, claimable domain | SubdoMailing (Guardio Labs, 2024) — 5M phishing emails/day |
| MX    | A mail-exchanger host is NXDOMAIN or a deleted cloud-mail zone, re-claimable | SubdoMailing / Hazy Hawk inbound-mail hijack |
| DKIM  | A `<selector>._domainkey` CNAME delegates to an NXDOMAIN ESP resource, **or** publishes an inline RSA key below the RFC 8301 1024-bit floor | SubdoMailing DKIM-signing abuse (Guardio Labs, 2024); 512-bit DKIM key factoring (Harris, 2012) |
| DMARC | A `_dmarc` policy is monitor-only (`p=none`, spoofable) **or** its `rua=`/`ruf=` report domain is NXDOMAIN and re-claimable | Hazy Hawk / SubdoMailing report-interception recon; `p=none` spoofing (BEC/phishing precondition) |
| AXFR  | A delegated nameserver allows an unauthenticated zone transfer, leaking every record | Classic DNS misconfiguration; force-multiplier for every other vector |
| CAA   | A `CAA` record names a CA domain that is NXDOMAIN and re-claimable, **or** uses the `*` wildcard authorising any CA to issue | Missing/weak certificate-issuance control → man-in-the-middle TLS |

Most scanners cover CNAME only. NS, SPF, MX, DKIM, and DMARC takeover are live,
actively-exploited vectors that almost no Go tool handles. Together SPF, DKIM,
MX, and DMARC cover the complete email-authentication takeover surface. AXFR adds
the classic zone-transfer leak: a single misconfigured nameserver hands an
attacker the full subdomain list to feed back through every other vector. CAA
adds the certificate-issuance control: a domain that names a claimable CA — or
explicitly authorises any CA — re-opens the door to fraudulent TLS certificates.

---

## Install

```sh
go install github.com/bugsy/graverobber/cmd/graverobber@latest
```

Or grab a pre-built binary from the [releases page](../../releases).

Requires Go 1.22+ to build from source.

---

## Usage

```sh
# Stdin pipe — the primary workflow
subfinder -d target.com -silent | graverobber

# File of targets
graverobber -l subdomains.txt

# Single target
graverobber -t dev.example.com

# JSONL output to a file
graverobber -l subs.txt -c 50 --timeout 10 -o results.jsonl --json

# SARIF output for GitHub Code Scanning / CI upload
graverobber -l subs.txt --sarif -o graverobber.sarif

# CSV output for spreadsheet / ticket triage
graverobber -l subs.txt --csv -o takeovers.csv

# Merge a private fingerprint list (local entries win)
graverobber -l subs.txt --fingerprints ~/private.json

# Offline — cached/embedded fingerprints only, no network
graverobber -l subs.txt --offline

# Skip vectors
graverobber -l subs.txt --no-ns --no-spf --no-mx --no-dkim --no-dmarc --no-axfr --no-caa

# Probe a custom set of DKIM selectors instead of the built-in ESP defaults
graverobber -l subs.txt --selectors default,google,s1,s2,k1
```

### Refreshing the databases

```sh
# Refresh the CNAME fingerprint database
graverobber update

# Refresh the NS takeover provider list
graverobber update --ns-providers
```

`update` fetches the CI-verified `fingerprints.json` from
[EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz),
validates it, atomically writes the cache at
`~/.config/graverobber/fingerprints.json`, and prints an added/removed/changed
diff. The cache is canonical; a compiled-in snapshot is the offline fallback.

`update --ns-providers` does the same for the **NS takeover provider list**: it
fetches the README of
[indianajson/can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns)
— the only community-vetted source for which DNS providers allow a deleted
hosted zone to be re-created — parses its provider table, and writes the cache
at `~/.config/graverobber/ns_providers.json`. The NS detector uses this list to
decide between a `CONFIRMED` finding (deleted zone at a re-claimable provider)
and a `POTENTIAL` one. Only providers the upstream marks **Vulnerable** are
treated as confirmable; **Edge Case**, **Not Vulnerable**, and **Registration
Closed** providers are not. A compiled-in snapshot is the offline fallback when
no cache is present, so a stale list never silently disables NS scoring — but
refreshing periodically keeps confidence accurate as providers change status.

---

## Certificate Transparency monitoring (`ct`)

The scanner finds dangling-record *candidates*. The `ct` subcommand closes the
loop: it checks Certificate Transparency logs to see whether a certificate has
**already been issued** for those subdomains. An unexpected certificate on a
dangling subdomain is near-proof that a takeover already occurred — an attacker
who claimed the resource provisioned TLS for it.

```sh
# Query crt.sh for all certs under target apexes (deduped to apex domains)
subfinder -d target.com -silent | graverobber ct --json

# Cross-reference a prior scan: certs whose name matches a flagged subdomain
# get "takeover_candidate": true
graverobber -l subs.txt --json -o findings.jsonl
graverobber ct -l subs.txt --findings findings.jsonl

# Only emit certificates flagged as takeover candidates
graverobber ct -l subs.txt --findings findings.jsonl --candidates-only
```

`ct` reads targets from `-t`, `-l`, or stdin (same precedence as scan),
deduplicates them to apex domains, and queries
[`crt.sh`](https://crt.sh)'s public JSON endpoint (no auth). Output is JSONL,
one certificate per line:

```json
{"name":"dev.example.com","apex":"example.com","not_before":"2026-05-01T08:00:00Z","issuer":"C=US, O=Let's Encrypt, CN=R3","takeover_candidate":true}
```

crt.sh is a shared community service backed by a single database; `ct`
rate-limits to one query per second by default (`--rate-limit`). The exit code
mirrors the scan command: `1` when any takeover-candidate certificate was found,
`0` otherwise, `2` on error.

| `ct` flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Single target host |
| `-l, --list` | — | File of targets, one host per line |
| `--findings` | — | Prior graverobber JSONL findings to cross-reference (subdomains become candidates) |
| `--candidates-only` | false | Emit only certificates flagged as takeover candidates |
| `--rate-limit` | 1.0 | Max crt.sh queries/sec |
| `--timeout` | 30 | Per-query HTTP timeout (seconds) |

---

## Second-order discovery (`links`)

A *second-order* subdomain takeover hides one hop deeper than the scanner's
direct targets. A live web app resolves and serves fine, but its HTML, JavaScript,
or JSON references some other host — a forgotten analytics endpoint, a legacy CDN
URL, an abandoned OAuth redirect host — that is itself dangling. The page is
healthy; the vulnerable host is the one it points at.

The `links` subcommand does the *discovery* half of that loop, and nothing more.
For each live target it fetches the page, pulls every cross-origin host reference
out of the body (excluding hosts on the same registrable apex, which the main
scanner already covers), and emits them. Keeping extraction separate from scanning
preserves graverobber's stdin→stdout pipeline ethos: the referenced hosts pipe
straight back into `scan`.

```sh
# Discover the cross-origin hosts a set of live pages reference, then scan them
graverobber links -l live-hosts.txt | graverobber scan --json

# Single target, with source attribution
graverobber links -t app.example.com --json
```

Default output is one host per line (pipe-friendly into `scan`). With `--json`,
each line is a `{"host","source"}` record so you can see which page referenced
each host:

```json
{"host":"cdn.thirdparty.net","source":"app.example.com"}
```

Referenced hosts are deduplicated across all targets, so a single dangling CDN
referenced by ten pages emits once. The exit code mirrors `scan`/`ct`: `1` when
any cross-origin reference was found, `0` otherwise, `2` on error. `links` reads
targets from `-t`, `-l`, or stdin (same precedence as `scan`).

| `links` flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Single target host |
| `-l, --list` | — | File of targets, one host per line |
| `-c, --concurrency` | 20 | Concurrent page fetches |
| `--timeout` | 15 | Per-page HTTP timeout (seconds) |
| `--json` | false | Emit `{"host","source"}` JSONL (default: bare host per line) |
| `--http-only` | false | Fetch pages over HTTP only |
| `--https-only` | false | Fetch pages over HTTPS only |

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Single target host |
| `-l, --list` | — | File of targets, one host per line |
| `-c, --concurrency` | 50 | Worker goroutine count |
| `--timeout` | 10 | Per-target HTTP timeout (seconds) |
| `-o, --output` | stdout | Write findings to a file |
| `--json` | false | JSONL output (default: coloured terminal) |
| `--sarif` | false | SARIF 2.1.0 output for GitHub Code Scanning / CI upload (mutually exclusive with `--json`/`--csv`) |
| `--csv` | false | CSV output (header + one row per finding) for spreadsheet/ticket triage (mutually exclusive with `--json`/`--sarif`) |
| `--silent` | false | Results only, suppress progress/banner |
| `--verbose` | false | Verbose debug logging to stderr |
| `--no-ns` | false | Skip NS takeover checks |
| `--no-spf` | false | Skip SPF `include:`/`redirect=` checks |
| `--no-mx` | false | Skip MX dangling-record checks |
| `--no-dkim` | false | Skip DKIM selector checks (dangling CNAME + weak inline RSA key) |
| `--no-dmarc` | false | Skip DMARC report-domain dangling checks |
| `--no-axfr` | false | Skip AXFR zone-transfer misconfiguration checks |
| `--no-caa` | false | Skip CAA (Certification Authority Authorization) misconfiguration checks |
| `--selectors` | — | Comma-separated DKIM selectors to probe (default: common ESP selectors) |
| `--fingerprints` | — | Additional fingerprint JSON to merge (repeatable) |
| `--offline` | false | Cached/embedded fingerprints only, no network |
| `--resolvers` | — | File of custom DNS resolvers |
| `--rate-limit` | 0 | Global max requests/sec (0 = unlimited) |
| `--http-only` | false | Probe services over HTTP only |
| `--https-only` | false | Probe services over HTTPS only |
| `--verify` | false | Actively verify S3 / GitHub Pages / Azure findings (upgrades `LIKELY` → `CONFIRMED`) |
| `--github-token` | — | GitHub token for the `--verify` Pages probe (raises the API rate limit) |
| `--min-confidence` | — | Suppress findings below a tier: `confirmed` \| `likely` \| `potential` (default: emit all) |

When neither `--http-only` nor `--https-only` is set, `graverobber` probes
HTTPS first and falls back to HTTP.

### Active verification (`--verify`)

By default `graverobber` assigns confidence from the fingerprint stage alone. With
`--verify`, the three highest-signal services get an extra unauthenticated probe that
can upgrade a `LIKELY` finding to `CONFIRMED`:

- **AWS/S3** — GET `https://<bucket>.s3.amazonaws.com/`; a `404` carrying `NoSuchBucket`
  confirms the bucket is unclaimed.
- **GitHub Pages** — GET `https://api.github.com/repos/<user>/<user>.github.io`; a `404`
  confirms the backing repo is gone. Pass `--github-token` to lift the 60 req/h
  unauthenticated limit to 5000 req/h.
- **Microsoft Azure** — confirms an `azurewebsites.net` / `cloudapp.net` /
  `trafficmanager.net` (etc.) target via DNS `NXDOMAIN`.

All probes are read-only — `graverobber` confirms claimability, it never claims the
resource. Verification only ever upgrades confidence; it never downgrades, and it never
touches a finding the fingerprint stage already marked `CONFIRMED`.

### Filtering by confidence (`--min-confidence`)

Mass scans surface a long tail of `POTENTIAL` findings — dangling records pointing at
unknown services that may or may not be claimable. `--min-confidence` suppresses
everything below a tier so triage starts with the high-signal hits:

```sh
# Only act-now findings:
cat hosts.txt | graverobber --min-confidence confirmed --json

# Skip the DNS-only noise, keep fingerprint matches and better:
cat hosts.txt | graverobber --min-confidence likely
```

The tiers are ordered `CONFIRMED` ≥ `LIKELY` ≥ `POTENTIAL`. The filter is applied
*after* `--verify`, so a probe that upgrades a `LIKELY` finding to `CONFIRMED` keeps it
above a `confirmed` threshold. The default (flag omitted) emits every finding.

### SPF policy takeover (`--no-spf`)

An SPF record can hand control of a target's mail-authentication policy to
another domain two ways, and both are exploitable when that domain is
unregistered:

- **`include:<domain>`** — a mechanism (RFC 7208 §5.2) that folds another
  domain's SPF record into the evaluation. This is the original SubdoMailing
  vector (Guardio Labs, 2024).
- **`redirect=<domain>`** — a modifier (RFC 7208 §6.1) that designates another
  domain's SPF record as **the** policy for the target when no mechanism matches.
  A dangling `redirect=` is arguably higher-impact than a dangling `include:`
  because the redirect target's policy replaces the local one wholesale.

graverobber parses both directives, recurses into the policies of domains that
still exist (bounded by the RFC 7208 ten-lookup cap), and emits a `POTENTIAL`
`spf` finding for any referenced domain that resolves `NXDOMAIN` — an attacker
who registers it controls the SPF evaluation and can authorise spoofed mail. The
claimable domain is reported in the `spf_include` field for both directive kinds;
the `evidence` string names which directive (`include:` or `redirect=`) pointed
at it. DNS-only signal, no fingerprint — classified `POTENTIAL` like the rest of
the email-auth surface.

### DKIM selector takeover (`--no-dkim`, `--selectors`)

DKIM public keys live at `<selector>._domainkey.<domain>`. Organizations
frequently publish them as **CNAMEs** that delegate the key to an email service
provider (e.g. `s1._domainkey.example.com → s1.domainkey.u123.wl.sendgrid.net`).
When the ESP account is closed or the selector rotated, the CNAME is abandoned —
an attacker who reclaims the ESP resource can serve a DKIM key and sign email
that passes DKIM verification. This is the DKIM half of the SubdoMailing vector
(Guardio Labs, 2024).

The selector name is not discoverable from DNS alone, so graverobber probes a
list of common ESP selectors by default (`default`, `google`, `k1`, `k2`, `s1`,
`s2`, `selector1`, `selector2`, `dkim`, `mail`, `smtp`). Override the list with
`--selectors` (comma-separated) when you know the selector in use.

The DKIM vector checks two distinct weaknesses per selector:

- **Dangling delegation (`CONFIRMED`).** If the selector is published as a CNAME
  whose target is `NXDOMAIN`, the ESP resource is gone and reclaimable — an
  attacker who reclaims it can serve a DKIM key and sign email that passes DKIM
  verification.
- **Weak inline key (`LIKELY`).** If the selector instead publishes the key
  inline as a TXT record, graverobber parses the RSA public key (`p=` tag) and
  flags any modulus below **1024 bits** — the floor mandated by
  [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301). A 512-bit DKIM key has been
  factored in hours on commodity hardware, letting an attacker recover the
  private key and forge DKIM-passing signatures without touching DNS at all. The
  finding carries `dkim_key_bits` with the offending size. Keys that meet the
  floor, non-RSA keys, and explicitly-revoked keys (empty `p=`) are never
  flagged.

### DMARC policy weakness & report-domain takeover (`--no-dmarc`)

graverobber checks the `_dmarc.<domain>` TXT record for **two** distinct
weaknesses.

**1 — Monitor-only policy (`p=none`).** The DMARC `p=` tag tells receivers what
to do with mail that fails DMARC alignment:

```
p=reject        bounce it          (enforcing)
p=quarantine    spam-folder it      (enforcing)
p=none          do nothing         (monitor-only — spoofed mail is delivered)
```

`p=none` is the deployment-bootstrap state (RFC 7489 §6.3), not a destination.
A domain that publishes it indefinitely is **spoofable by anyone**: mail that
fails SPF and DKIM still lands in the inbox, which is the precondition every
business-email-compromise and phishing campaign relies on. graverobber emits a
`POTENTIAL` `dmarc` finding carrying the policy in the new `dmarc_policy` field.
The case is flagged as materially worse when **no `rua=` aggregate-reporting
address is configured** — the owner then has neither enforcement nor visibility,
so an ongoing spoofing campaign is invisible (the `evidence` string calls this
out). Enforcing policies (`p=reject`, `p=quarantine`) are never flagged.

**2 — Dangling report domain.** A DMARC policy can publish two reporting
addresses:

```
rua=mailto:aggregate@reports.example.net   (aggregate reports)
ruf=mailto:forensic@reports.example.net    (failure/forensic reports)
```

Each `mailto:` URI names a domain that receives mail on the policy owner's
behalf. If that domain is `NXDOMAIN` — the reporting vendor was decommissioned,
or the address points at a forgotten internal subdomain whose zone was deleted —
an attacker who registers or reclaims it **intercepts every DMARC report sent
for the target**. The reports expose the target's full sending infrastructure,
which spoofing attempts pass or fail alignment, and source IP reputation: a
quiet reconnaissance goldmine. graverobber parses the `rua=`/`ruf=` tags
(handling comma-separated lists, mixed case, and `!size` limits), probes each
report domain, and emits a `POTENTIAL` `dmarc` finding carrying the claimable
domain in the `dmarc_uri` field. Both sub-cases are DNS-only signals with no
fingerprint, classified like the SPF `include:` vector; they are distinguished
by which of `dmarc_policy` / `dmarc_uri` is set.

Together with SPF, DKIM, and MX, this completes the email-authentication
takeover surface.

### AXFR zone-transfer misconfiguration (`--no-axfr`)

A DNS zone transfer (AXFR) is the mechanism a secondary nameserver uses to pull a
full copy of a zone from the primary. It is meant to be restricted to authorised
secondaries by IP allow-list or TSIG. A nameserver that answers an AXFR from
**any** client is misconfigured: it streams the entire zone — every subdomain,
internal hostname, mail and infrastructure record — to whoever asks.

This is a direct information disclosure and a force-multiplier for every other
graverobber vector: one permissive nameserver hands an attacker the complete
subdomain list, which can then be fed straight back through the CNAME, NS, SPF,
MX, DKIM, and DMARC checks to find the dangling records inside it.

graverobber resolves the target's delegated `NS` records, then attempts an
unauthenticated AXFR (TCP) against each. A nameserver that **refuses** (the
correct, secure response) is skipped silently; the first nameserver that returns
zone data yields a `CONFIRMED` `axfr` finding naming that nameserver, the number
of records leaked, and a capped sample of the exposed hostnames (`leaked_hosts`).
graverobber only reads the zone to confirm and sample the leak — it never writes,
modifies, or persists the transferred records.

### CAA misconfiguration (`--no-caa`)

A `CAA` (Certification Authority Authorization, RFC 8659) record set restricts
which Certificate Authorities may issue certificates for a domain. Without it,
**any** of the ~150 publicly-trusted CAs will issue a certificate to anyone who
passes that CA's domain-control validation — the precondition for a
man-in-the-middle TLS certificate. CAA closes that hole by naming the only CAs
allowed to issue:

```
example.com.  CAA  0 issue "letsencrypt.org"      ; only Let's Encrypt for end-entity certs
example.com.  CAA  0 issuewild ";"                ; no CA may issue wildcard certs
```

graverobber resolves the target's `CAA` records and flags two misconfigurations,
both `POTENTIAL` (DNS-only signals, no fingerprint match):

- **Dangling issuer** — an `issue`/`issuewild` tag names a CA domain that is
  **NXDOMAIN**. This is the SubdoMailing-class takeover applied to CAA: an
  attacker who registers the unregistered CA domain can stand up an ACME/CA
  endpoint that the target's own policy explicitly authorises to issue
  certificates. The claimable domain is reported in `caa_issuer`.
- **Permissive any-CA** — a CAA record set is present but an `issue`/`issuewild`
  tag uses the wildcard value `*`, authorising **any** CA to issue. Publishing
  CAA and then naming `*` re-opens the very hole CAA exists to close while
  falsely signalling that issuance is controlled.

A domain with **no** CAA record at all is the permissive internet-wide default
and is intentionally **not** flagged, to keep the vector low-noise and
pipeline-friendly — only a present-but-broken policy is reported. The secure
deny-all `;` value is likewise never flagged.

---

## Confidence model

Every finding carries one of three tiers:

| Tier | Meaning |
|---|---|
| `CONFIRMED` | Fingerprint match on a definitive signal (e.g. S3's "bucket does not exist") |
| `LIKELY` | Fingerprint match only — the signal is not by itself conclusive |
| `POTENTIAL` | DNS-only signal (NXDOMAIN / SERVFAIL / REFUSED) with no fingerprint match |

---

## Output

JSONL — one finding per line:

```json
{"subdomain":"dev.example.com","vector":"cname","service":"AWS/S3","confidence":"CONFIRMED","cname":"example.s3.amazonaws.com","fingerprint":"The specified bucket does not exist","scheme":"https","timestamp":"2026-05-16T12:34:56Z"}
{"subdomain":"s1._domainkey.example.com","vector":"dkim","confidence":"LIKELY","dkim_selector":"s1","dkim_key_bits":512,"evidence":"DKIM selector publishes a 512-bit RSA key (below the RFC 8301 1024-bit floor) — factorable, forgeable signatures","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"reports.deleted-vendor.net","vector":"dmarc","confidence":"POTENTIAL","dmarc_uri":"reports.deleted-vendor.net","evidence":"DMARC rua/ruf report domain is NXDOMAIN (claimable — report interception)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"dmarc","confidence":"POTENTIAL","dmarc_policy":"none","evidence":"DMARC policy is p=none with no rua= aggregate reporting (no enforcement and no visibility)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"axfr","service":"ns1.example.com","confidence":"CONFIRMED","nameservers":["ns1.example.com"],"leaked_hosts":["admin.example.com","vpn.example.com"],"evidence":"nameserver ns1.example.com allowed unauthenticated AXFR (412 records leaked; sample: admin.example.com, vpn.example.com)","timestamp":"2026-05-28T12:00:00Z"}
```

Without `--json`, findings render as one coloured human-readable line per
finding. Each line carries the confidence tier, the vector tag, the subdomain,
and a vector-specific detail: the dangling CNAME target (`cname`), the claimable
`include:`/`redirect=` domain (`spf`), the failed nameservers (`ns`), the dangling
mail-exchanger hosts (`mx`), the dangling `<selector>._domainkey` delegation or
weak inline RSA key size (`dkim`), the claimable `rua`/`ruf` report domain
(`dmarc`), or the leaking
nameserver and leaked-host count (`axfr`). ANSI colour is emitted only to a TTY;
piped or file output is plain text.

When the scan finishes, the human-readable mode closes with a triage summary on
stderr: the total count, then a breakdown by confidence tier (strongest first)
and by vector (pipeline order). The by-vector breakdown covers every vector the
scanner can emit (`cname`, `ns`, `spf`, `mx`, `dkim`, `dmarc`, `axfr`, `caa`), so
the per-vector counts always reconcile with the total. Only the tiers and vectors
that actually occurred are listed, so a single-vector scan stays uncluttered:

```
graverobber: 17 finding(s)
  by tier:   CONFIRMED=4  LIKELY=5  POTENTIAL=8
  by vector: cname=6  ns=2  spf=4  dmarc=3  axfr=1  caa=1
```

The summary is stderr-only — it never mixes into the findings on stdout — and is
suppressed by `--silent` and by every machine format (`--json`/`--sarif`/`--csv`),
which emit their own self-describing documents.

### SARIF for GitHub Code Scanning (`--sarif`)

`--sarif` renders the whole scan as a single
[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log — the OASIS-standard
format GitHub Code Scanning, Azure DevOps, and most security platforms ingest
natively. Uploading the log turns each takeover candidate into a tracked,
deduplicated alert in the repository's **Security → Code scanning** tab instead
of a line of console output that scrolls away.

```sh
# Scan in CI and upload to the GitHub Security tab
subfinder -d "$GITHUB_REPOSITORY_OWNER.com" -silent \
  | graverobber --sarif -o graverobber.sarif
```

```yaml
# .github/workflows/takeover-scan.yml (excerpt)
- run: subfinder -d example.com -silent | graverobber --sarif -o graverobber.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: graverobber.sarif
```

Each finding becomes a SARIF `result`: `CONFIRMED` maps to `error`, `LIKELY` and
`POTENTIAL` to `warning`; the subdomain is the result location; rule IDs are
namespaced under `graverobber/<vector>`; and a stable `partialFingerprint` keyed
on `(subdomain, vector)` lets Code Scanning dedupe the same candidate across
re-scans rather than re-opening an alert each run. `--sarif` is mutually
exclusive with `--json` and `--csv`. A scan with zero findings still emits a
valid (empty) log so the upload step never fails.

### CSV for spreadsheet / ticket triage (`--csv`)

`--csv` renders the scan as RFC 4180 CSV — a header row followed by one row per
finding — for the spreadsheet-and-ticketing triage workflow that most teams
actually run. The flat sheet drops straight into Excel/Google Sheets, a Jira CSV
import, or a `csvkit`/`pandas` pipeline without a `jq` step.

```sh
subfinder -d example.com -silent | graverobber --csv -o takeovers.csv
```

```
timestamp,subdomain,vector,confidence,service,target,scheme,fingerprint,evidence
2026-05-28T12:00:00Z,dev.example.com,cname,CONFIRMED,AWS/S3,example.s3.amazonaws.com,https,The specified bucket does not exist,
2026-05-28T12:00:00Z,reports.deleted-vendor.net,dmarc,POTENTIAL,,reports.deleted-vendor.net,,,DMARC rua/ruf report domain is NXDOMAIN
2026-05-28T12:00:00Z,example.com,axfr,CONFIRMED,ns1.example.com,ns1.example.com,,,nameserver ns1.example.com allowed unauthenticated AXFR
```

Every vector maps onto the same columns; the vector-specific dangling target
(CNAME, SPF `include:`, NS/MX hosts, DKIM selector delegation, DMARC report
domain, or the leaking AXFR nameserver) is normalised into the single `target`
column so the whole sheet sorts and filters uniformly. `--csv` is mutually
exclusive with `--json` and `--sarif`. A scan with zero findings still emits a
valid header-only file.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan complete, no findings |
| `1` | Scan complete, findings present |
| `2` | Error (bad input, network failure, etc.) |

---

## Library use

`graverobber` is library-first. Embedders import `pkg/scanner` directly and
consume `finding.Finding` values rather than parsing CLI output:

```go
db, _ := fingerprints.Embedded()
sc := scanner.New(db, scanner.DefaultOptions())
for f := range sc.Run(ctx, targets) {
    // f is a finding.Finding
}
```

The CLI in `cmd/graverobber` is itself just a thin wrapper over `Scanner.Run`.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Fingerprint data is sourced from
[EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
(CC-BY-4.0).
