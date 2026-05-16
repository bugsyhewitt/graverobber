# graverobber v1.0 — Claude Code build prompt

Paste this into a fresh Claude Code session opened at the repo root.

---

You are picking up `graverobber`, a Go subdomain takeover scanner. The module
is **fully scaffolded** — every package compiles, `gofmt` is clean, `go vet`
passes on `./pkg/...`. Your job is to implement the detection logic, not to
restructure anything. Do not change package layouts, exported signatures, or
JSON field names — embedders (the Pho3nix MCP server) and the CLI both depend
on them as they stand.

## First steps (do these before writing code)

1. `go mod tidy` — the scaffold has no `go.sum` and `cmd/` imports `cobra`.
   This pulls cobra, miekg/dns, retryablehttp-go, and ratelimit once you add
   their imports. Run it again after you add each new import.
2. Pick the real module path. The placeholder is `github.com/bugsy/graverobber`.
   Replace the `bugsy` segment with the real GitHub handle/org:
   ```sh
   grep -rl 'github.com/bugsy/graverobber' --include='*.go' . \
     | xargs sed -i 's#github.com/bugsy/graverobber#github.com/YOURHANDLE/graverobber#g'
   sed -i 's#github.com/bugsy/graverobber#github.com/YOURHANDLE/graverobber#' go.mod
   ```
3. `go build ./...` and `go test ./...` — confirm a clean green baseline before
   touching anything.

## What is already done — do NOT rebuild

- `pkg/finding` — domain types (`Finding`, `Vector`, `Confidence`). Final.
- `pkg/fingerprints` — DB load/merge/match, `update` logic, embedded `seed.json`
  snapshot, `SignatureVerifier` seam. Complete and tested-ready.
- `pkg/output` — `JSONLWriter` + `TerminalWriter`, concurrency-safe. Complete.
- `pkg/verifier` — `Verifier` interface + `NoopVerifier` (v1.0 default). Seam
  only, intentionally.
- `pkg/scanner` — worker pool, fan-out, verifier application. Complete and
  wired; it calls the detectors below.
- `cmd/graverobber` — full cobra CLI (root scan + `update` subcommand), all
  flags, exit codes 0/1/2. Complete.
- `pkg/resolver` — method signatures are FINAL; bodies return
  `ErrNotImplemented`. **You implement these.**
- `pkg/detectors` — `cname.go` / `ns.go` / `spf.go` signatures are FINAL;
  bodies return `(nil, nil)`. **You implement these.**

## Design decisions already resolved — build to these, do not relitigate

1. **Library-first.** `pkg/scanner` is the integration point. CLI is a wrapper.
2. **v1.0 is fingerprint-only.** No active S3/GitHub Pages probing. `NoopVerifier`
   stays the default. Do not implement real verifiers — that is v1.1.
3. **No fingerprint signing in v1.0.** `NoopSignatureVerifier` stays. Leave the
   `SignatureVerifier` seam untouched.
4. **HTTPS first, HTTP fallback.** When `Config.HTTPOnly`/`HTTPSOnly` are both
   false, probe HTTPS then fall back to HTTP on connect failure. Record the
   winning scheme in `Finding.Scheme`.
5. **Scope is CNAME + NS + SPF only.** No AXFR, MX, SRV, or A-record/IP-recycling.
6. **Concurrency:** 50 workers, `--rate-limit 0` (unlimited) global default.
   Add an always-on per-destination token bucket (~10 req/s/IP) so 50 workers
   do not hammer a single AWS endpoint — this is a separate internal knob, not
   a user flag.

## Implementation work order

1. **`pkg/resolver`** — wire in `github.com/miekg/dns`. Implement `CNAMEChain`,
   `NS`, `TXT`, `AuthoritativeSOA`, `IsWildcard`. `AuthoritativeSOA` must do a
   direct, non-recursive query to the given nameserver and surface the rcode
   (SERVFAIL/REFUSED → deleted zone). Fall back to `/etc/resolv.conf` or a
   public resolver set when no `--resolvers` are configured.
2. **`pkg/detectors/cname.go`** — resolve the CNAME chain, suppress wildcard
   zones via `resolver.IsWildcard`, match the final target with `db.MatchCNAME`,
   HTTP-probe with `retryablehttp-go` (HTTPS-first per decision 4), match the
   body with `Fingerprint.MatchBody`, handle `nxdomain:true` services. Assign
   confidence per the three-tier model: definitive body string → `CONFIRMED`;
   fingerprint match only → `LIKELY`; dangling CNAME, unknown service →
   `POTENTIAL`.
3. **`pkg/detectors/ns.go`** — resolve NS records, query each nameserver's SOA
   directly; if all SERVFAIL/REFUSED → deleted hosted zone. Match NS hostname
   suffixes against `knownDNSProviders`. `CONFIRMED` when the provider is known
   and the zone is gone; `POTENTIAL` otherwise.
4. **`pkg/detectors/spf.go`** — resolve TXT, parse the SPF policy, recurse
   `include:` directives up to `maxSPFDepth`, flag any included domain that is
   NXDOMAIN/unregistered as a claimable `VectorSPF` finding.
5. **Tests** — table-driven unit tests for fingerprint matching, SPF parsing,
   and the CNAME confidence ladder. Mock DNS/HTTP; do not hit the network in
   tests. Aim for the detection logic, not the scaffold.

## Acceptance criteria

- `go build ./...` passes.
- `go test ./...` passes (with `-race`).
- `gofmt -l .` prints nothing.
- `go vet ./...` is clean.
- `echo dev.example.com | go run ./cmd/graverobber --json` produces valid JSONL
  and exits 0 (no finding) or 1 (finding) — never 2 on well-formed input.
- `go run ./cmd/graverobber update` refreshes the cache and prints a diff.

Keep commits scoped per package. Do not add dependencies beyond the four named
above without a clear reason.
