# graverobber

**Subdomain takeover scanner for CNAME, NS, and SPF dangling records.**

> Digs up the subdomains your target left for dead — CNAME, NS, and SPF
> takeover detection in one pipeline-friendly Go binary.

`graverobber` is the only maintained Go binary that covers **CNAME**, **NS**,
and **SPF** takeover vectors in a single tool. It is a static binary with no
runtime, reads targets from stdin/file/flag, streams JSONL, and uses the
exit-code conventions of the `httpx`/`subfinder` family so it drops straight
into a recon pipeline.

---

## Why these three vectors

| Vector | Signal | Real-world campaign |
|---|---|---|
| CNAME | Dangling CNAME → fingerprint match against a known-vulnerable service | The classic takeover; ~60+ services covered |
| NS    | Delegated DNS hosted zone deleted at the provider, re-claimable | Hazy Hawk (.edu campaign, 2025–2026) |
| SPF   | An SPF `include:` directive points at an unregistered, claimable domain | SubdoMailing (Guardio Labs, 2024) — 5M phishing emails/day |

Most scanners cover CNAME only. NS and SPF takeover are live, actively-exploited
vectors that almost no Go tool handles.

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

# Merge a private fingerprint list (local entries win)
graverobber -l subs.txt --fingerprints ~/private.json

# Offline — cached/embedded fingerprints only, no network
graverobber -l subs.txt --offline

# Skip vectors
graverobber -l subs.txt --no-ns --no-spf
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

## Flags

| Flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Single target host |
| `-l, --list` | — | File of targets, one host per line |
| `-c, --concurrency` | 50 | Worker goroutine count |
| `--timeout` | 10 | Per-target HTTP timeout (seconds) |
| `-o, --output` | stdout | Write findings to a file |
| `--json` | false | JSONL output (default: coloured terminal) |
| `--silent` | false | Results only, suppress progress/banner |
| `--verbose` | false | Verbose debug logging to stderr |
| `--no-ns` | false | Skip NS takeover checks |
| `--no-spf` | false | Skip SPF include checks |
| `--fingerprints` | — | Additional fingerprint JSON to merge (repeatable) |
| `--offline` | false | Cached/embedded fingerprints only, no network |
| `--resolvers` | — | File of custom DNS resolvers |
| `--rate-limit` | 0 | Global max requests/sec (0 = unlimited) |
| `--http-only` | false | Probe services over HTTP only |
| `--https-only` | false | Probe services over HTTPS only |
| `--verify` | false | Actively verify S3 / GitHub Pages / Azure findings (upgrades `LIKELY` → `CONFIRMED`) |
| `--github-token` | — | GitHub token for the `--verify` Pages probe (raises the API rate limit) |

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
```

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
