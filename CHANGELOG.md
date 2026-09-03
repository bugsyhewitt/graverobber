# Changelog

All notable changes to graverobber are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Comic card image in README header.

### Changed
- Code quality sweep: efficiency, simplification, and altitude improvements across the codebase (#44).

### Fixed
- Windows CI: pinned NS provider list in `ns_test.go` for test hermeticity; applied `gofmt`.

---

## [1.1.0] - 2026-07-14

A large expansion of detection coverage: graverobber grew from 3 core vectors
to 16, added three new subcommands, two machine-readable output formats, and a
triage summary — while keeping the single-binary, pipeline-friendly interface.

### Added

**New detectors**

- **VectorMX** — dangling MX record detection: mail-exchanger host is NXDOMAIN or belongs to a deleted cloud-mail zone.
- **VectorDKIM** — dangling DKIM selector CNAME detection: `<selector>._domainkey` CNAME resolves to an NXDOMAIN ESP resource (#4).
- **VectorDMARC** — dangling DMARC report-domain detection: `rua=`/`ruf=` mailto domain or `https:` collector host is NXDOMAIN and re-claimable (#6).
- **AXFR** — zone-transfer misconfiguration detection: delegated nameserver allows unauthenticated zone transfer (7th vector) (#12).
- **CAA** — misconfiguration detection: CA domain is NXDOMAIN/re-claimable, `iodef` report host is NXDOMAIN, or wildcard `*` authorises any CA (8th vector) (#16, #23).
- **DANE TLSA** — dangling TLSA pin detection: `_25._tcp.<mxhost>` TLSA record covers an MX host that is NXDOMAIN (9th vector) (#19).
- **MTA-STS policy host** — dangling policy-host detection: `mta-sts.<domain>` is NXDOMAIN and re-claimable (10th vector) (#20).
- **MTA-STS weak-policy mode** — detects `mode: none` or `mode: testing` in a resolved MTA-STS policy (not `enforce`) (#33).
- **BIMI** — dangling asset-host detection: logo (`l=`) or VMC (`a=`) URL host is NXDOMAIN and re-claimable (11th vector) (#21).
- **DNSSEC orphaned-DS** — parent zone publishes a DS record but child has no DNSKEY (12th vector) (#22).
- **DNSSEC weak algorithm** — chain uses an RFC 8624 forbidden/deprecated algorithm (RSAMD5, DSA/SHA-1, RSASHA1, ECC-GOST, SHA-1 DS digest) (#28).
- **TLSRPT** — dangling report-destination detection: `rua=` mailto domain or HTTPS collector host is NXDOMAIN (13th vector) (#25).
- **SPF redirect= dangling** — `redirect=` modifier points at an unregistered domain (#13).
- **SPF a:/mx: dangling** — `a:` or `mx:` mechanism points at an NXDOMAIN host (#24).
- **SPF +all permissive** — apex SPF ends in `+all`, allowing any host to send as the domain (#18).
- **SPF DNS-lookup-limit** — SPF recursion exceeds the RFC 7208 §4.6.4 ten-lookup cap (`permerror`) (#27).
- **SPF deprecated ptr** — `ptr` mechanism present (RFC 7208 §5.5 SHOULD NOT; undefined result on conforming receivers) (#30).
- **DMARC p=none** — monitor-only DMARC policy, domain spoofable (#15).
- **DMARC ruf= HTTPS dangling** — `https:` report-URI collector host is NXDOMAIN (#26).
- **DMARC sp=none** — subdomain policy is `none` when parent is `reject`/`quarantine`, leaving subdomains spoofable (#34).
- **DKIM weak inline-key** — published RSA key is below the RFC 8301 1024-bit floor (#14).
- **DKIM rotation-hint** — selector name embeds a 4-digit year ≥ 2 calendar years ago, indicating a key not rotated per M3AAWG/NIST SP 800-177 guidance (#31).
- **NS partial-lame delegation** — some NS answer authoritatively, some `SERVFAIL`/`REFUSE`; lame NS belongs to a re-claimable provider (RFC 1912 §2.8) (#29).
- **TLSA/DANE HTTPS** — certificate-association detector for HTTPS DANE records (#32).
- **Autodiscover/Autoconfig** — `autodiscover.<domain>` or `autoconfig.<domain>` CNAME resolves to NXDOMAIN with a live apex (mail-client credential-harvesting vector).

**New subcommands**

- `ct` — Certificate Transparency log monitoring: streams newly-issued certs for target domains from crt.sh (#3).
- `links` — second-order takeover discovery: extracts and resolves all hrefs/src links from target pages to find dangling link targets (#5).

**New output formats and filtering**

- `--sarif` — SARIF output for GitHub Code Scanning / CI upload (#9).
- `--csv` — CSV output for spreadsheet/ticket triage (#10).
- `--min-confidence` — filter flag to suppress findings below a given confidence threshold (#8).

**Scan improvements**

- Concurrent per-target vector scanning: all vectors run in parallel per target, not sequentially.
- Active verification: S3, GitHub Pages, and Azure cloud-storage probing to confirm claimability.
- NS provider list sync from `indianajson/can-i-take-over-dns` (#2).
- End-of-scan triage summary appended to human-readable output, including by-vector breakdown (#11).
- Richer terminal detail for MX, DKIM, and DMARC findings (#7).

### Fixed

- Triage summary by-vector breakdown was silently dropping AXFR and CAA findings (#17).
- Windows CI: pinned provider list in NS detector tests to prevent flaky failures on hermeticity (#37, #38).

### Tests

- All scanner tests made hermetic against the expanded vector set (#42).

---

## [1.0.1] - 2026-05-16

### Changed

- Hardened NS detectors: TCP fallback on UDP truncation, retry logic, deduplication of NXDOMAIN results, and goroutine leak fixes.

---

## [1.0.0] - 2026-05-16

Initial release.

### Added

- **VectorCNAME** — dangling CNAME fingerprint matching against 60+ known-vulnerable services (Heroku, GitHub Pages, Fastly, Netlify, AWS Elastic Beanstalk, S3, Azure, and more).
- **VectorNS** — NS zone-deletion detection: every authoritative nameserver for the delegation returns `SERVFAIL`, zone is re-claimable at the registrar/provider.
- **VectorSPF** — SPF `include:` dangling detection: an `include:` directive points at an unregistered domain (SubdoMailing vector).
- 50-worker concurrent scanner; reads targets from stdin, file (`-l`), or `--target` flag.
- JSONL streaming output and human-readable terminal output.
- `update` subcommand to refresh the CNAME fingerprint database from upstream.
- Multi-OS CI matrix (Linux, macOS, Windows) with `go vet`, `gofmt`, and race-detector checks.
- goreleaser cross-platform binary releases.

[Unreleased]: https://github.com/bugsyhewitt/graverobber/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/bugsyhewitt/graverobber/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/bugsyhewitt/graverobber/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/bugsyhewitt/graverobber/releases/tag/v1.0.0
