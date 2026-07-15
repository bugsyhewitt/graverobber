# graverobber

<p align="center">
  <img src="https://raw.githubusercontent.com/bugsyhewitt/bugsyhewitt.github.io/main/public/cards/graverobber.jpg" alt="graverobber" width="680">
</p>

**Subdomain takeover scanner for CNAME, NS, SPF, MX, DKIM, and DMARC dangling records, plus AXFR zone-transfer, CAA misconfiguration, dangling DANE TLSA pins, dangling MTA-STS policy hosts, dangling BIMI asset hosts, orphaned DNSSEC DS records, and dangling TLSRPT report destinations.**

> Digs up the subdomains your target left for dead — CNAME, NS, SPF, MX, DKIM,
> and DMARC takeover detection plus unauthenticated AXFR zone-transfer discovery,
> CAA misconfiguration, dangling DANE TLSA pins, dangling MTA-STS policy hosts, dangling BIMI asset hosts, orphaned DNSSEC DS records, and dangling TLSRPT report destinations in one pipeline-friendly Go binary.

`graverobber` is the only maintained Go binary that covers **CNAME**, **NS**,
**SPF**, **MX**, **DKIM**, and **DMARC** takeover vectors plus **AXFR**
zone-transfer, **CAA** misconfiguration, dangling **DANE TLSA** pins, dangling **MTA-STS** policy hosts, dangling **BIMI** asset hosts, orphaned **DNSSEC DS** records, and dangling **TLSRPT** report destinations in a single tool. It is a static binary with no
runtime, reads targets from stdin/file/flag, streams JSONL, and uses the
exit-code conventions of the `httpx`/`subfinder` family so it drops straight into
a recon pipeline.

---

## Why these vectors

| Vector | Signal | Real-world campaign |
|---|---|---|
| CNAME | Dangling CNAME → fingerprint match against a known-vulnerable service | The classic takeover; ~60+ services covered |
| NS    | Delegated DNS hosted zone deleted at the provider (every NS `SERVFAIL`s) and re-claimable, **or** the delegation is partially lame — some NS answer authoritatively, some `SERVFAIL`/`REFUSE` (RFC 1912 §2.8) — and any lame NS hostname belongs to a takeoverable provider, a partial-hijack precondition | Hazy Hawk (.edu campaign, 2025–2026); lame delegations cause intermittent outages and, when the lame NS sits at a re-creatable provider, let an attacker control answers for the fraction of resolver queries that hit it |
| SPF   | An SPF `include:`/`redirect=`/`a:`/`mx:` directive points at an unregistered, claimable domain, the policy ends in `+all` (Pass — any host may send mail as the domain), the recursed evaluation exceeds the RFC 7208 §4.6.4 ten-lookup cap (`permerror` — SPF hard-fails everywhere), **or** the apex record contains a `ptr` mechanism (RFC 7208 §5.5 deprecated — SHOULD NOT be published; ignored or `permerror` on many receivers) | SubdoMailing (Guardio Labs, 2024) — 5M phishing emails/day; `+all` = fully spoofable domain; lookup-explosion `permerror` = the same spoofable-by-omission outcome under DMARC alignment; deprecated `ptr` = SPF result effectively undefined on conforming receivers |
| MX    | A mail-exchanger host is NXDOMAIN or a deleted cloud-mail zone, re-claimable | SubdoMailing / Hazy Hawk inbound-mail hijack |
| DKIM  | A `<selector>._domainkey` CNAME delegates to an NXDOMAIN ESP resource, publishes an inline RSA key below the RFC 8301 1024-bit floor, **or** is named with an embedded 4-digit year ≥ 2 calendar years old (rotation-hint — the published key has not been rotated against the M3AAWG / NIST SP 800-177 annual-rotation guidance, so any past compromise stays exploitable) | SubdoMailing DKIM-signing abuse (Guardio Labs, 2024); 512-bit DKIM key factoring (Harris, 2012); selectors like `dkim2019`, `mar2018`, `key2017` still serving live keys (operator surveys, ongoing) |
| DMARC | A `_dmarc` policy is monitor-only (`p=none`, spoofable) **or** its `rua=`/`ruf=` report host — a `mailto:` domain or `https:` collector host — is NXDOMAIN and re-claimable | Hazy Hawk / SubdoMailing report-interception recon; `p=none` spoofing (BEC/phishing precondition) |
| AXFR  | A delegated nameserver allows an unauthenticated zone transfer, leaking every record | Classic DNS misconfiguration; force-multiplier for every other vector |
| CAA   | A `CAA` record names a CA domain that is NXDOMAIN and re-claimable, an `iodef` report host that is NXDOMAIN, **or** uses the `*` wildcard authorising any CA to issue | Missing/weak certificate-issuance control → man-in-the-middle TLS; or CAA report interception |
| TLSA  | A DANE `TLSA` pin at `_25._tcp.<mxhost>` covers an MX host that is NXDOMAIN — a dangling, DNSSEC-authenticated pin | Hard-fails inbound mail from DANE senders; reclaimable mail host → DANE-trusted interception (RFC 7672) |
| MTA-STS | An MTA-STS policy is advertised (`v=STSv1` TXT at `_mta-sts.<domain>`) but **(a)** the policy host `mta-sts.<domain>` is NXDOMAIN and re-claimable, **or (b)** the policy host resolves but its `mode:` field is `none` or `testing` (not `enforce`) | (a) Reclaimed policy host serves a forged policy → TLS downgrade / mail interception. (b) TLS enforcement inactive — SMTP senders not required to enforce TLS; vulnerable to active-downgrade and MX-redirection attacks (RFC 8461 §3.2) |
| BIMI | A BIMI record (`v=BIMI1` TXT at `default._bimi.<domain>`) names a logo (`l=`) or VMC (`a=`) URL whose host is NXDOMAIN and re-claimable | Reclaimed asset host serves a forged brand logo/VMC, displayed beside DMARC-passing mail → brand-impersonation phishing (BIMI spec) |
| DNSSEC | The parent zone publishes a `DS` (Delegation Signer) record but the domain has **no `DNSKEY`** — an orphaned DS that breaks the chain of trust; **or** the chain is intact but uses a DNSSEC algorithm RFC 8624 forbids/deprecates (RSAMD5, DSA/SHA-1, RSASHA1, DSA-NSEC3-SHA1, RSASHA1-NSEC3-SHA1, ECC-GOST, or a SHA-1 DS digest) — a forgeable chain | Orphan: every validating resolver (Google, Cloudflare, Quad9, most ISPs) `SERVFAIL`s the whole zone → self-inflicted outage. Weak algorithm: a well-resourced attacker can forge a valid-looking DNSSEC chain, defeating DNSSEC entirely (RFC 4034, RFC 8624) |
| TLSRPT | A TLSRPT record (`v=TLSRPTv1` TXT at `_smtp._tls.<domain>`) names a `rua=` report destination — a `mailto:` domain or `https:` collector host — that is NXDOMAIN and re-claimable | Reclaimed destination intercepts every SMTP-TLS failure report → delivery reconnaissance and a live view of the downgrade failures that would otherwise alert the owner (RFC 8460) |
| Autodiscover | `autodiscover.<domain>` (MS Exchange/Outlook) or `autoconfig.<domain>` (Thunderbird and general convention) is published as a CNAME that resolves to NXDOMAIN, and the apex domain is live | Mail clients auto-probe these hosts during account setup; an attacker who reclaims the gone CNAME target serves a forged autoconfiguration payload that silently hands every auto-probing client an attacker-controlled IMAP/SMTP server and harvests mailbox credentials |

Most scanners cover CNAME only. NS, SPF, MX, DKIM, and DMARC takeover are live,
actively-exploited vectors that almost no Go tool handles. Together SPF, DKIM,
MX, and DMARC cover the complete email-authentication takeover surface. AXFR adds
the classic zone-transfer leak: a single misconfigured nameserver hands an
attacker the full subdomain list to feed back through every other vector. CAA
adds the certificate-issuance control: a domain that names a claimable CA — or
explicitly authorises any CA — re-opens the door to fraudulent TLS certificates.
TLSA closes the loop on the mail surface: a DANE pin left behind for a deleted
mail host silently black-holes inbound mail and — because DANE for SMTP mandates
DNSSEC — hands an attacker who reclaims that host a DANE-trusted mail-interception
path. MTA-STS guards the same surface from the policy side: a domain that
advertises MTA-STS but leaves its `mta-sts.<domain>` policy host dangling lets an
attacker who reclaims that host serve a forged policy — `mode: none` to disable
TLS enforcement outright, or an attacker-controlled `mx:` list to steer inbound
mail — defeating the active-downgrade protection MTA-STS is meant to provide.
DNSSEC widens the scope from takeover to availability: a domain whose parent
still publishes a `DS` record after the child has dropped its `DNSKEY` (a DNSSEC
disable, or a provider migration that left the registrar's DS behind) presents an
orphaned DS — the chain of trust breaks at the last link and every
DNSSEC-validating resolver returns `SERVFAIL` for the entire zone, taking the
domain dark for the large and growing share of the internet that validates while
it resolves normally on non-validating resolvers, which makes the outage
maddening to diagnose. It is not attacker-claimable, but it is a high-severity,
purely-DNS-detectable misconfiguration an operator urgently needs surfaced.
TLSRPT completes the SMTP-TLS reporting plane: a domain that advertises TLS
Reporting but leaves its `rua=` report destination dangling lets an attacker who
reclaims that mailto domain or HTTPS collector receive every TLS-failure report
sent for the target — counterparty and infrastructure reconnaissance, and a
real-time view of the very downgrade failures an active TLS MITM produces, which
would otherwise be the owner's earliest warning. It is the SMTP-TLS analogue of
the DMARC report-domain takeover, and together with MTA-STS (policy host) and
TLSA (DANE pin) it closes graverobber's coverage of the MTA-STS/DANE control
surface.

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
graverobber -l subs.txt --no-ns --no-spf --no-mx --no-dkim --no-dmarc --no-axfr --no-caa --no-tlsa --no-mtasts --no-bimi --no-dnssec --no-tlsrpt --no-autodiscover

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
| `--no-ns` | false | Skip NS delegation checks (zone-deleted strict-unanimity + partial-lame delegation) |
| `--no-spf` | false | Skip SPF `include:`/`redirect=`/`a:`/`mx:` dangling, `+all` permissive-policy, RFC 7208 §4.6.4 DNS-lookup-limit, and RFC 7208 §5.5 deprecated-`ptr`-mechanism checks |
| `--no-mx` | false | Skip MX dangling-record checks |
| `--no-dkim` | false | Skip DKIM selector checks (dangling CNAME, weak inline RSA key, stale-year rotation-hint) |
| `--no-dmarc` | false | Skip DMARC report-host dangling + `p=none` checks |
| `--no-axfr` | false | Skip AXFR zone-transfer misconfiguration checks |
| `--no-caa` | false | Skip CAA (Certification Authority Authorization) misconfiguration checks (dangling issuer, dangling `iodef` report host, permissive any-CA) |
| `--no-tlsa` | false | Skip TLSA dangling-DANE-pin checks |
| `--no-mtasts` | false | Skip MTA-STS checks (dangling policy host + weak policy mode) |
| `--no-bimi` | false | Skip BIMI dangling-asset-host checks |
| `--no-dnssec` | false | Skip DNSSEC checks (orphaned DS, weak/deprecated algorithm per RFC 8624) |
| `--no-tlsrpt` | false | Skip TLSRPT dangling-report-destination checks |
| `--no-autodiscover` | false | Skip Autodiscover/Autoconfig dangling mail-client-autoconfiguration-host checks |
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

graverobber flags four classes of SPF weakness: a **dangling reference**, a
**permissive policy**, an **RFC 7208 §4.6.4 DNS-lookup-limit breach**, and use
of the **RFC 7208 §5.5 deprecated `ptr` mechanism**.

**Dangling reference.** An SPF record can authorise another domain to send mail
as the target four ways, and all four are exploitable when that domain is
unregistered:

- **`include:<domain>`** — a mechanism (RFC 7208 §5.2) that folds another
  domain's SPF record into the evaluation. This is the original SubdoMailing
  vector (Guardio Labs, 2024).
- **`redirect=<domain>`** — a modifier (RFC 7208 §6.1) that designates another
  domain's SPF record as **the** policy for the target when no mechanism matches.
  A dangling `redirect=` is arguably higher-impact than a dangling `include:`
  because the redirect target's policy replaces the local one wholesale.
- **`a:<domain>`** — a mechanism (RFC 7208 §5.3) that passes when the sender's IP
  matches an A/AAAA record of the named domain. An attacker who reclaims a
  dangling `a:` domain points its address records at their own host and every
  message they send passes SPF for the target.
- **`mx:<domain>`** — a mechanism (RFC 7208 §5.4) that passes when the sender's IP
  matches an A/AAAA record of one of the named domain's MX hosts — the same
  takeover as `a:`, via the reclaimed domain's mail hosts.

Only the explicit-domain form of `a:`/`mx:` is a reference; a bare `a` or `mx`
(optionally with a `/cidr` dual-CIDR suffix) points at the **target's own**
records and is not a takeover surface, so it is ignored. graverobber parses all
four directives, recurses into the policies of `include:`/`redirect=` domains
that still exist (bounded by the RFC 7208 ten-lookup cap), and emits a
`POTENTIAL` `spf` finding for any referenced domain that resolves `NXDOMAIN` — an
attacker who registers it can authorise spoofed mail for the target. The claimable
domain is reported in the `spf_include` field for all four directive kinds; the
`evidence` string names which directive (`include:`, `redirect=`, `a:`, or `mx:`)
pointed at it.

**Permissive policy.** The `all` mechanism is the catch-all that ends a
well-formed SPF record (RFC 7208 §5.1); its qualifier decides the result for any
sender not matched earlier — `-all` (Fail, the secure default), `~all`
(SoftFail), `?all` (Neutral), or `+all` (Pass). A `+all` policy — or a bare
`all`, which §4.6.2 treats as `+all` — explicitly authorises **every host on the
internet** to send mail as the domain, which defeats the entire purpose of
publishing SPF: the domain is fully spoofable and any forged mail passes SPF
alignment. This is the SPF analog of a DMARC `p=none` policy — a
present-but-toothless email-auth record. graverobber emits a `POTENTIAL` `spf`
finding keyed on the target itself (not an external domain), with the offending
mechanism token in the `spf_all` field; `-all`, `~all`, and `?all` are never
flagged.

**DNS-lookup-limit breach.** [RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4)
caps an SPF evaluation at **ten** DNS-querying mechanisms and modifiers:
`include`, `a`, `mx`, `ptr`, `exists`, and `redirect=` each count as one lookup;
`ip4`, `ip6`, `exp=`, `all`, and the version tag do not. A record whose total
(across the apex and every recursed `include:`/`redirect=` target) exceeds ten
**MUST** produce a `permerror` — every conforming SPF receiver hard-fails the
check, taking down DMARC alignment and leaving the domain spoofable by omission.
This is the email-auth equivalent of misconfiguring the policy into a no-op: the
record exists, but it is structurally guaranteed to fail at evaluation time. It
is a common production failure mode (the "include explosion" antipattern as
domains accrue ESPs over time). graverobber walks the same `include:`/`redirect=`
graph the dangling traversal uses and tallies every DNS-querying mechanism in
each reachable policy; when the total exceeds ten, it emits a `POTENTIAL` `spf`
finding keyed on the target itself, with the offending count in the
`spf_lookups` field. The cycle-safe `visited`-map traversal prevents infinite
recursion on include loops (which are independently a `permerror`, RFC 7208
§4.6.4) without distorting the count.

**Deprecated `ptr` mechanism.** [RFC 7208 §5.5](https://www.rfc-editor.org/rfc/rfc7208#section-5.5)
explicitly discourages publishing the `ptr` mechanism: "Use of this mechanism is
discouraged because it is slow, it is not as reliable as other mechanisms in
cases of DNS errors, and it places a large burden on the .arpa name servers. …
**SPF publishers SHOULD NOT include this mechanism in their SPF records**, and
SHOULD use the `a` or `mx` mechanisms instead." The mechanism passes when the
connecting IP's reverse-DNS PTR record lands in the SPF domain, but some
receivers already ignore it (treating the term as a no-op) and others return
`permerror` on it — leaving the publisher's SPF result effectively undefined on
those receivers and, under DMARC alignment, spoofable-by-omission on the same
axis as a §4.6.4 lookup-limit breach. graverobber flags any `ptr` token in the
apex SPF record (bare `ptr`, qualifier-prefixed `+ptr`/`-ptr`/`~ptr`/`?ptr`, or
the explicit-domain form `ptr:<domain>`) and emits a `POTENTIAL` `spf` finding
keyed on the target itself, with the offending token preserved verbatim in the
`spf_ptr` field so the operator can locate and remove the exact published
field. Apex-only like the permissive sub-case: the deprecation is the
publisher's misconfiguration of their own record.

All four sub-cases are DNS-only signals with no fingerprint — classified
`POTENTIAL` like the rest of the email-auth surface — and can fire independently
for the same record.

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

The DKIM vector checks three distinct weaknesses per selector:

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
- **Stale rotation-hint (`POTENTIAL`).** When the selector name embeds a 4-digit
  year that is at least **two calendar years** older than the current year —
  e.g. `dkim2019`, `mar2019`, `key2018`, `selector-2017` — and the selector
  still publishes a live key (inline TXT or live CNAME delegation), graverobber
  emits a `POTENTIAL` rotation-hint finding carrying the extracted year in
  `dkim_stale_year`. Operators rotate DKIM by spinning up a new selector named
  for the rotation date and re-pointing the signer; a multi-year-old selector
  still serving a live key is a strong signal the rotation never happened.
  [M3AAWG Sender Best Common Practices §6](https://www.m3aawg.org/sites/default/files/m3aawg-senders-bcp-ver3-2015-02.pdf)
  and [NIST SP 800-177r1 §4.5.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-177r1.pdf)
  both recommend annual DKIM key rotation; a key still live under a stale-named
  selector keeps any past compromise exploitable indefinitely. The check uses a
  boundary regex that skips long numeric runs (vendor account ids like
  `u20191234`), only matches years from `2000` onward (DKIM was published as
  RFC 4871 in 2007), and never fires on a `NXDOMAIN` selector — the dangling
  sub-case takes precedence because a non-existent selector has no key to call
  stale.

### DMARC policy weakness & report-host takeover (`--no-dmarc`)

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

**2 — Dangling report host.** A DMARC policy can publish two reporting
destinations, each as a comma-separated list of DMARC URIs:

```
rua=mailto:aggregate@reports.example.net      (aggregate reports, mailto: transport)
ruf=mailto:forensic@reports.example.net       (failure/forensic reports, mailto: transport)
rua=https://collector.vendor.example/ingest   (aggregate reports, https: transport)
```

RFC 7489 §A.5 registers **two** report transports: `mailto:` (the host is the
domain after the `@`) and `https:` (the host is the URL authority — the
deployment model the large DMARC-as-a-service vendors offer via an HTTPS POST
endpoint). If that report host is `NXDOMAIN` — the reporting vendor was
decommissioned, or the address points at a forgotten internal subdomain whose
zone was deleted — an attacker who registers or reclaims it **intercepts every
DMARC report sent for the target**. The reports expose the target's full sending
infrastructure, which spoofing attempts pass or fail alignment, and source IP
reputation: a quiet reconnaissance goldmine. graverobber parses the `rua=`/`ruf=`
tags (handling comma-separated lists, mixed case, `!size` limits, and **both**
the `mailto:` and `https:` transports), probes each report host, and emits a
`POTENTIAL` `dmarc` finding carrying the claimable host in the `dmarc_uri`
field. Both sub-cases are DNS-only signals with no fingerprint, classified like
the SPF `include:` vector; they are distinguished by which of `dmarc_policy` /
`dmarc_uri` is set. This mirrors the dual-transport handling of the CAA `iodef=`
and TLSRPT `rua=` report-host vectors.

**3 — Weak subdomain policy (`sp=none`).** RFC 7489 §6.3 defines the optional
`sp=` tag as an explicit override of the parent `p=` policy for all subdomains.
When `sp=none` is set and the parent `p=` is `reject` or `quarantine`, the
subdomain namespace is left monitor-only while the apex is enforced — an attacker
spoofing from any subdomain (`anything@sub.example.com`) evades DMARC enforcement
entirely because receivers apply the `sp=none` policy, not the enforcing parent.
This is the "split enforcement" anti-pattern: the domain owner enforced the apex
but inadvertently left every subdomain spoofable. graverobber emits a `POTENTIAL`
`dmarc` finding carrying the subdomain policy token in `dmarc_policy` and calls out
the parent policy in the evidence so the operator sees exactly the mismatch.
`p=reject`/`p=quarantine` with an absent `sp=` (subdomains inherit the parent),
or `sp=reject`/`sp=quarantine`, are never flagged — only the explicit mismatch
where the subdomain policy undermines an otherwise-enforcing apex record.

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

graverobber resolves the target's `CAA` records and flags three
misconfigurations, all `POTENTIAL` (DNS-only signals, no fingerprint match):

- **Dangling issuer** — an `issue`/`issuewild` tag names a CA domain that is
  **NXDOMAIN**. This is the SubdoMailing-class takeover applied to CAA: an
  attacker who registers the unregistered CA domain can stand up an ACME/CA
  endpoint that the target's own policy explicitly authorises to issue
  certificates. The claimable domain is reported in `caa_issuer`.
- **Dangling iodef report host** — an `iodef` tag (RFC 8659 §4.4) names the URL
  where a CA reports a forbidden issuance request — a `mailto:` address or an
  `http(s)://` endpoint (RFC 6546). If that URL's host is **NXDOMAIN**, an
  attacker who registers it intercepts the CAA violation reports, a
  reconnaissance channel revealing exactly which CAs are being probed against the
  target's policy (i.e. mis-issuance/attack attempts) — the CAA analogue of the
  DMARC `rua`/`ruf` report-interception case. The claimable host is reported in
  `caa_issuer` and the evidence names the `iodef` tag.
- **Permissive any-CA** — a CAA record set is present but an `issue`/`issuewild`
  tag uses the wildcard value `*`, authorising **any** CA to issue. Publishing
  CAA and then naming `*` re-opens the very hole CAA exists to close while
  falsely signalling that issuance is controlled.

A domain with **no** CAA record at all is the permissive internet-wide default
and is intentionally **not** flagged, to keep the vector low-noise and
pipeline-friendly — only a present-but-broken policy is reported. The secure
deny-all `;` value is likewise never flagged.

### Dangling DANE TLSA pin (`--no-tlsa`)

DANE for SMTP (RFC 7672) lets a domain pin its mail server's TLS certificate in
DNS — secured by DNSSEC — so a sending MTA can verify the certificate without
relying on the public CA system. The pin lives at `_25._tcp.<mxhost>` as a
`TLSA` record (RFC 6698):

```
_25._tcp.mx.example.com.  TLSA  3 1 1 <sha-256 of the server's public key>
```

The pin is only as healthy as the mail host it covers. When the MX host is
removed — the mail vendor is decommissioned, the hosted zone is deleted, the
subdomain is retired — but the `TLSA` record is left behind, you get a **dangling
DANE pin**, and two things go wrong:

- **Inbound mail black-holes.** RFC 7672 §2.2 makes a published-but-unmatchable
  pin a permanent TLS failure, so every DANE-validating sender silently stops
  delivering mail to the domain.
- **DANE-trusted interception becomes possible.** Because DANE mandates DNSSEC,
  the stale pin is *authenticated*. An attacker who reclaims the gone mail host
  (re-registers the domain, or re-creates the deleted hosted zone) can stand up an
  SMTP server presenting a certificate that matches the still-published `TLSA`
  association — and be trusted by every DANE sender.

graverobber detects two sub-cases under the TLSA vector:

**Sub-case 1 — Dangling SMTP pin.** graverobber resolves the target's `MX`
records, probes `_25._tcp.<mxhost>` for a `TLSA` pin, and — if a pin exists —
checks whether that mail host is NXDOMAIN. A dangling pin is reported as a
`POTENTIAL` `tlsa` finding carrying the DANE owner name in `tlsa_name` and the
dangling mail host in `mx_hosts`. A domain with no `TLSA` records, or whose pinned
hosts all resolve, is the healthy case and is intentionally **not** flagged — only
a present-but-orphaned pin is reported, keeping the vector low-noise. (A dangling
MX host with *no* DANE pin is reported by the MX vector instead, not here.)

**Sub-case 2 — Stale HTTPS pin (cert mismatch).** DANE for HTTPS (RFC 7671) uses
`_443._tcp.<target>` TLSA records to pin a domain's public TLS certificate. When
the certificate is rotated (or the operator switches CAs) but the `TLSA` record is
not updated, the published pin and the live certificate drift out of sync. From the
standpoint of every DANE-validating client this is a hard TLS failure (RFC 7671 §5:
a published-but-unmatchable pin breaks the connection). graverobber queries
`_443._tcp.<target>` for TLSA records; if any are present it performs a TLS
handshake (with `InsecureSkipVerify` — to read the certificate bytes, not to
chain-validate against the public PKI) and runs the RFC 7671 §5.1 matching
algorithm against the served certificate chain. If **no** published record matches
the served certificate, graverobber emits a `POTENTIAL` `tlsa` finding carrying the
DANE owner name in `tlsa_name` and the observed leaf SPKI SHA-256 fingerprint in
the evidence (the value to copy into a corrected TLSA record). A handshake failure
(connection refused, timeout, TLS error) is treated as indeterminate and produces
no finding — the detector is biased toward false negatives over false positives.

### MTA-STS misconfiguration (`--no-mtasts`)

SMTP MTA Strict Transport Security (RFC 8461) lets a domain declare that sending
mail servers **must** use TLS with a valid, matching certificate when delivering
to it — closing the active downgrade and MX-redirection attacks that plain
opportunistic STARTTLS allows. A domain opts in with two coupled pieces:

- a `TXT` record at `_mta-sts.<domain>` carrying `v=STSv1; id=<policy-id>` — the
  signal that a policy exists, and
- a policy file served over HTTPS at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`, listing the authorised MX
  hosts and the enforcement mode. The policy host `mta-sts.<domain>` is, in
  practice, a `CNAME` to a hosting provider (a CDN bucket, a SaaS MTA-STS host).

graverobber detects two sub-cases:

**Sub-case 1 — Dangling policy host.** When the policy host is decommissioned
but the `_mta-sts` `TXT` signal is left behind, the policy host is NXDOMAIN and
re-claimable. An attacker who reclaims `mta-sts.<domain>` can serve an arbitrary
policy file: a forged `mode: none` disables TLS enforcement wholesale, and a
forged `mx:` list authorises the attacker's own mail server, steering inbound mail
through it. Finding carries the dangling policy host in `service` and the
claimable `CNAME` target (or the policy host itself) in `cname`.

**Sub-case 2 — Weak policy mode.** When the policy host resolves and the policy
file is reachable, but its `mode:` field is `none` or `testing`, TLS enforcement
is inactive — the same disposition as DMARC `p=none`. In `mode: none`, senders
must treat the policy as absent (RFC 8461 §3.3); in `mode: testing`, senders may
apply TLS but must not fail delivery on violations. Either mode leaves the domain
vulnerable to active TLS-downgrade and MX-redirection attacks. Finding carries the
policy host in `service` and the mode token in `mtasts_mode`. Upgrade to
`mode: enforce` to activate protection.

Both sub-cases emit a `POTENTIAL` `mtasts` finding. A domain that does not
advertise MTA-STS, or whose policy host resolves and serves `mode: enforce`, is
intentionally **not** flagged.

### Dangling BIMI asset host (`--no-bimi`)

BIMI (Brand Indicators for Message Identification) lets a domain publish a brand
logo — optionally backed by a Verified Mark Certificate (VMC) — that BIMI-aware
mail clients (Gmail, Apple Mail, Yahoo, Fastmail) fetch and render beside
authenticated mail from the domain. It is a pure trust-signalling feature: the
logo displays **only** for mail that already passes DMARC at enforcement, so to
the recipient the logo is a visual mark of authenticity. A domain opts in with a
single `TXT` record at `default._bimi.<domain>`:

```
default._bimi.example.com.  TXT  "v=BIMI1; l=https://images.example.com/logo.svg; a=https://certs.example.com/vmc.pem"
```

- `l=` names the HTTPS URL of the SVG Tiny P/S logo (mandatory for display).
- `a=` names the HTTPS URL of the VMC `.pem` that cryptographically binds the
  logo to the brand (optional, but required by Gmail and the strictest tier).

Both URLs are, in practice, hosted on a brand subdomain or a vendor host (a CDN
bucket, a BIMI-as-a-service host). When that asset host is decommissioned — the
bucket is released, the hosted zone is deleted, the brand-asset subdomain is
retired — but the BIMI `TXT` record is left behind, you get a **dangling BIMI
asset host**. An attacker who reclaims the gone host can serve an arbitrary logo
at the `l=` URL (and, where the VMC host is the reclaimed one, an arbitrary VMC at
the `a=` URL). Because the logo renders only beside DMARC-passing mail, a forged
logo lends a spoofing campaign the exact visual trust mark BIMI exists to confer —
a brand-impersonation surface.

graverobber resolves `default._bimi.<target>`; if a `v=BIMI1` record is present it
parses the `l=` and `a=` URLs and probes each referenced host. A host that is
NXDOMAIN is reported as a `POTENTIAL` `bimi` finding carrying the BIMI owner name
in `service` and the dangling asset host in `bimi_uri_host`; the `evidence` string
names which tag (`l=`/`a=`) pointed at it (a single host backing both URLs yields
one finding attributing both). A domain that does not advertise BIMI, or whose
asset hosts all resolve, is the healthy case and is intentionally **not** flagged.
The `a=self` and empty-value forms name no remote host and are likewise never
flagged — only an advertised-but-orphaned asset host is reported.

### Broken or cryptographically weak DNSSEC delegation (`--no-dnssec`)

The DNSSEC vector reports two distinct delegation failures. The first is an
**orphaned DS** (an availability failure: the chain is missing a link); the
second is a **weak DNSSEC algorithm** (a confidentiality/integrity failure: the
chain is present but its cryptography is broken).

#### Orphaned DS — broken chain of trust

DNSSEC secures a delegation with two halves: the child zone signs its records and
publishes a `DNSKEY`, and the **parent** zone publishes a `DS` (Delegation Signer)
record — a hash of one of the child's keys — that tells every validating resolver
"this delegation is secure, verify it." The `DS` is what *turns on* validation for
the child:

```
example.com.        DS      12345 13 2 AB...        ← published by the parent (.com)
example.com.        DNSKEY  257 3 13 ...            ← published by the child
```

If the operator turns DNSSEC **off** at the child (stops signing, drops the
`DNSKEY`) — or migrates to a new DNS provider that generates fresh keys — but
never removes the `DS` at the registrar, the parent still asserts "this delegation
is secure" while the child can no longer prove it. The chain of trust breaks at
the last link. This is an **orphaned DS**, and the consequence is severe and
internet-wide:

- Every DNSSEC-**validating** resolver returns `SERVFAIL` for the **entire zone**,
  not one record — DNSSEC fails closed.
- Validation is the default at Google Public DNS (`8.8.8.8`), Cloudflare
  (`1.1.1.1`), Quad9 (`9.9.9.9`), and a large, growing share of ISP resolvers, so
  the domain and all its services (web, mail, APIs) go dark for a substantial
  fraction of the internet **while resolving normally** for anyone on a
  non-validating resolver — which makes it maddening to diagnose.

It is one of the most common production DNSSEC outages and has taken government
and enterprise domains offline for hours. Unlike the takeover vectors, an orphaned
DS is not directly attacker-claimable — its harm is availability, not interception
— but it is exactly the dangling-delegation family graverobber specialises in,
applied to the DNSSEC chain-of-trust plane, and it is a finding an operator
urgently needs surfaced.

graverobber queries `DS` for the target (answered by the parent). No `DS` means an
unsigned delegation — the common default, nothing to orphan — and is never
flagged. If a `DS` is present, graverobber queries `DNSKEY` (answered by the
child): a key present is the healthy signed case and is not flagged; **no `DNSKEY`
— or a `SERVFAIL` on the `DNSKEY` query, which a validating resolver returns
precisely because the chain is already broken** — is reported as a `POTENTIAL`
`dnssec` finding keyed on the target, carrying the orphaned `DS` key tags in
`ds_key_tags` so you know exactly which registrar records to remove (or re-sign
the zone to match).

#### Weak / deprecated DNSSEC algorithm — forgeable chain

A DNSSEC delegation can be intact but cryptographically rotten. The IANA DNS
Security Algorithm Numbers registry contains algorithms RFC 8624 §3.1 forbids
(`MUST NOT` use) or deprecates (`NOT RECOMMENDED`) for signing — they are
broken or obsolete enough that a well-resourced attacker can forge a valid-
looking chain of trust:

| Alg # | Name                | RFC 8624 disposition          |
|-------|---------------------|-------------------------------|
| 1     | RSAMD5              | MUST NOT (MD5 collision-broken) |
| 3     | DSA/SHA-1           | MUST NOT                       |
| 5     | RSASHA1             | NOT RECOMMENDED (SHA-1 collision-broken) |
| 6     | DSA-NSEC3-SHA1      | MUST NOT                       |
| 7     | RSASHA1-NSEC3-SHA1  | NOT RECOMMENDED                |
| 12    | ECC-GOST            | MUST NOT (GOST R 34.10-2001 deprecated) |

The same applies to the DS record's **digest type**: digest type 1 (SHA-1, RFC
8624 §3.3 `NOT RECOMMENDED`) cannot rule out a substituted child key whose
SHA-1 digest collides with the published DS — so a SHA-1 DS is flagged even
when the key algorithm it references is modern.

When the chain is healthy (DS present + DNSKEY present) graverobber inspects
both surfaces — every child DNSKEY's algorithm and every parent DS's
(algorithm, digest type) pair — and emits a `POTENTIAL` `dnssec` finding
listing every distinct weakness observed in `dnssec_weak_algs` (deduplicated
and sorted). Modern algorithms (RSASHA256, RSASHA512, ECDSA P-256/P-384,
Ed25519, Ed448) and modern digest types (SHA-256, SHA-384) are the secure
norm and are not flagged. Rotate to one of those and update the DS at the
registrar to repair the finding.

The orphan and weak-algorithm sub-cases are distinguished in the output by
which of `ds_key_tags` / `dnssec_weak_algs` is set — both fields are present
on the weak-algorithm finding (the DS tags ride along so an operator can map
the weakness back to the specific registrar records), but `dnssec_weak_algs`
is empty on the orphan.

### Dangling TLSRPT report destination (`--no-tlsrpt`)

SMTP TLS Reporting (TLSRPT, RFC 8460) is the diagnostic feedback channel for SMTP
TLS security — the MTA-STS policies and DANE/TLSA pins above. A domain opts in by
publishing a `TXT` record at `_smtp._tls.<domain>`:

```
_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@vendor.example,https://collector.vendor.example/v1/tlsrpt"
```

The `rua=` tag is a comma-separated list of report destinations: a `mailto:`
address (whose **domain** receives the daily reports) and/or an `https:` collector
**host**. Whenever a sending MTA fails to negotiate the TLS the recipient's
MTA-STS policy or DANE pin requires, it emits a report to those destinations
describing the failure.

In practice the destination is a third-party reporting vendor's mailbox domain or
HTTPS collector host. When that destination is decommissioned — the vendor domain
is retired, the hosted zone is deleted, the collector subdomain is removed — but
the TLSRPT `TXT` record is left behind, you get a **dangling TLSRPT report
destination**. An attacker who reclaims the gone mailto domain or collector host
receives **every TLSRPT report sent for the target**:

- The reports enumerate the target's sending counterparties and the IPs and MX
  hosts involved in delivery — direct infrastructure reconnaissance.
- More dangerously, they reveal **in real time which senders are failing TLS** to
  the domain. An attacker mounting an active TLS-downgrade or MITM against the
  target's inbound mail can watch the very failure reports that would otherwise
  alert the domain owner — silently confirming and tuning the attack while the
  owner is blinded.

This is the SMTP-TLS analogue of the DMARC `rua`/`ruf` report-domain takeover.

graverobber resolves `_smtp._tls.<target>`; if a `v=TLSRPTv1` record is present it
parses the `rua=` destinations and probes each report host (the `mailto:` domain
or the `https:` URL host). A host that is NXDOMAIN is reported as a `POTENTIAL`
`tlsrpt` finding keyed on the target, carrying the TLSRPT owner name in `service`
and the dangling report host in `tlsrpt_uri_host` (destinations naming the same
host are deduplicated to one finding). A domain that does not advertise TLSRPT, or
whose report destinations all resolve, is the healthy case and is intentionally
**not** flagged, keeping the vector low-noise.

### Dangling mail-client autoconfiguration host (`--no-autodiscover`)

Mail clients configure themselves automatically by fetching server settings from
well-known subdomains of the user's email domain — **without any user action**:

- `autodiscover.<domain>` — the Microsoft Exchange / Outlook Autodiscover
  endpoint (MS-OXDSCLI). Outlook and the ActiveSync clients on every major mobile
  platform probe `https://autodiscover.<domain>/autodiscover/autodiscover.xml`
  during account setup. Microsoft 365 tenants publish it as a CNAME to
  `autodiscover.outlook.com` (or a third-party mail host).
- `autoconfig.<domain>` — the Mozilla Thunderbird autoconfiguration endpoint and
  the de-facto cross-client convention. Clients probe
  `https://autoconfig.<domain>/mail/config-v1.1.xml` during setup. Likewise
  typically a CNAME to a mail-hosting provider.

These hosts cover the **autoconfiguration plane** that the CNAME fingerprint, NS,
SPF, DKIM, DMARC, MX, MTA-STS, TLSRPT, and BIMI vectors do not — none of them
probe the host a mail client auto-resolves to fetch its server settings.

When an organisation migrates off a hosted mail tenant — the Microsoft 365 tenant
is closed, the third-party mail host is decommissioned, the hosted zone is deleted
— but the autodiscover/autoconfig CNAME is left behind, the host becomes a
**dangling mail-client autoconfiguration host**: a takeover vector uniquely
dangerous because exploitation is automatic and user-silent. An attacker who
reclaims the gone CNAME target serves a forged autoconfiguration payload; because
the client fetches it automatically and trusts it to configure the account, the
attacker hands every auto-probing mail client an attacker-controlled IMAP/SMTP
server and prompts the user's mailbox credentials — a silent, high-yield
credential-harvesting and mail-interception path.

graverobber confirms the apex domain is live first (a NXDOMAIN apex is a dead
domain, not an autoconfiguration-host takeover — no live organisation's mail
clients would auto-probe it), then probes `autodiscover.<target>` and
`autoconfig.<target>`. If either is NXDOMAIN, graverobber emits a `POTENTIAL`
`autodiscover` finding keyed on the target, carrying the dangling host in `service`
and the claimable CNAME target (or the host itself) in `cname`. A domain whose
autoconfiguration hosts resolve, or that publishes neither, is the healthy case and
is intentionally **not** flagged, keeping the vector low-noise and
pipeline-friendly.

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
{"subdomain":"dkim2019._domainkey.example.com","vector":"dkim","confidence":"POTENTIAL","dkim_selector":"dkim2019","dkim_stale_year":2019,"evidence":"DKIM selector name embeds the year 2019 (2+ years stale) — published key has not been rotated against the M3AAWG / NIST SP 800-177 annual-rotation guidance; a past key compromise stays exploitable","timestamp":"2026-05-29T12:00:00Z"}
{"subdomain":"reports.deleted-vendor.net","vector":"dmarc","confidence":"POTENTIAL","dmarc_uri":"reports.deleted-vendor.net","evidence":"DMARC rua/ruf report host is NXDOMAIN (claimable — report interception)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"dmarc","confidence":"POTENTIAL","dmarc_policy":"none","evidence":"DMARC policy is p=none with no rua= aggregate reporting (no enforcement and no visibility)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"spoofable.example.com","vector":"spf","confidence":"POTENTIAL","spf_all":"+all","evidence":"SPF policy ends in +all (Pass — authorises any host to send mail as the domain; domain is spoofable)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"permerror.example.com","vector":"spf","confidence":"POTENTIAL","spf_lookups":12,"evidence":"SPF evaluation requires 12 DNS-querying mechanisms (RFC 7208 §4.6.4 caps at 10 — receivers return permerror; SPF check hard-fails)","timestamp":"2026-05-29T12:00:00Z"}
{"subdomain":"example.com","vector":"axfr","service":"ns1.example.com","confidence":"CONFIRMED","nameservers":["ns1.example.com"],"leaked_hosts":["admin.example.com","vpn.example.com"],"evidence":"nameserver ns1.example.com allowed unauthenticated AXFR (412 records leaked; sample: admin.example.com, vpn.example.com)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"tlsa","confidence":"POTENTIAL","mx_hosts":["mx.deleted-vendor.invalid"],"tlsa_name":"_25._tcp.mx.deleted-vendor.invalid","evidence":"DANE TLSA pin published at _25._tcp.mx.deleted-vendor.invalid but MX host mx.deleted-vendor.invalid is NXDOMAIN (dangling DANE pin — hard-fails inbound mail; reclaimable for DANE-trusted interception)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"mtasts","service":"mta-sts.example.com","confidence":"POTENTIAL","cname":"policy.deleted-vendor.invalid","evidence":"MTA-STS policy advertised at _mta-sts.example.com but policy host mta-sts.example.com is NXDOMAIN (dangling MTA-STS host — reclaimable to serve a forged policy that disables TLS enforcement or redirects mail)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"mtasts","service":"mta-sts.example.com","confidence":"POTENTIAL","mtasts_mode":"testing","evidence":"MTA-STS policy at mta-sts.example.com is mode: testing — TLS enforcement is monitor-only (senders MAY apply TLS but MUST NOT fail delivery on violations); SMTP senders are not required to enforce TLS for mail destined to example.com, leaving the domain vulnerable to active-downgrade and MX-redirection attacks (RFC 8461 §3.2 — upgrade to mode: enforce to activate protection)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"bimi","service":"default._bimi.example.com","confidence":"POTENTIAL","bimi_uri_host":"images.deleted-vendor.invalid","evidence":"BIMI record at default._bimi.example.com l= asset host images.deleted-vendor.invalid is NXDOMAIN (dangling BIMI asset host — reclaimable to serve a forged brand logo/VMC beside DMARC-passing mail)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"dnssec","confidence":"POTENTIAL","ds_key_tags":[12345],"evidence":"parent zone publishes DS record(s) (key tag(s) 12345) but example.com has no DNSKEY — orphaned DS: DNSSEC-validating resolvers (Google, Cloudflare, Quad9, most ISPs) return SERVFAIL for the whole zone (self-inflicted outage; remove the DS at the registrar or re-sign the zone)","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"weak-dnssec.example.com","vector":"dnssec","confidence":"POTENTIAL","ds_key_tags":[12345],"dnssec_weak_algs":["RSASHA1"],"evidence":"DNSSEC delegation uses weak/deprecated algorithm(s) RSASHA1 (RFC 8624) — forgeable chain of trust; rotate to RSASHA256/RSASHA512/ECDSAP256SHA256/ECDSAP384SHA384/ED25519 and update the DS at the registrar","timestamp":"2026-05-28T12:00:00Z"}
{"subdomain":"example.com","vector":"tlsrpt","service":"_smtp._tls.example.com","confidence":"POTENTIAL","tlsrpt_uri_host":"reports.deleted-vendor.invalid","evidence":"TLSRPT record at _smtp._tls.example.com rua= report destination host reports.deleted-vendor.invalid is NXDOMAIN (dangling SMTP-TLS report destination — reclaimable to intercept TLS failure reports and mask an active TLS-downgrade attack)","timestamp":"2026-05-28T12:00:00Z"}
```

Without `--json`, findings render as one coloured human-readable line per
finding. Each line carries the confidence tier, the vector tag, the subdomain,
and a vector-specific detail: the dangling CNAME target (`cname`); the claimable
`include:`/`redirect=`/`a:`/`mx:` domain, the permissive `+all` mechanism, the
DNS-lookup count exceeding the RFC 7208 §4.6.4 cap, or the deprecated `ptr` token
(`spf`); the failed nameservers (`ns`); the dangling mail-exchanger hosts (`mx`);
the dangling `<selector>._domainkey` delegation, weak inline RSA key size, or
stale-year rotation-hint (`dkim`); the claimable `rua`/`ruf` report host or the
`p=none`/`sp=none` policy token (`dmarc`); the leaking nameserver and
leaked-host count (`axfr`); the claimable CA issuer, `iodef` report host, or
permissive `*` flag (`caa`); the dangling DANE owner name or stale-pin SPKI
fingerprint (`tlsa`); the dangling policy host or weak mode token (`mtasts`);
the dangling asset host (`bimi`); the orphaned `DS` key tags or weak algorithm
names (`dnssec`); the dangling TLSRPT report host (`tlsrpt`); or the dangling
autoconfiguration host (`autodiscover`). ANSI colour is emitted only to a TTY;
piped or file output is plain text.

When the scan finishes, the human-readable mode closes with a triage summary on
stderr: the total count, then a breakdown by confidence tier (strongest first)
and by vector (pipeline order). The by-vector breakdown covers every vector the
scanner can emit (`cname`, `ns`, `spf`, `mx`, `dkim`, `dmarc`, `axfr`, `caa`, `tlsa`, `mtasts`, `bimi`, `dnssec`, `tlsrpt`, `autodiscover`), so
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
2026-05-28T12:00:00Z,reports.deleted-vendor.net,dmarc,POTENTIAL,,reports.deleted-vendor.net,,,DMARC rua/ruf report host is NXDOMAIN
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
