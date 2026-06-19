// Command graverobber-mcp is the Model Context Protocol (MCP) front end for
// graverobber, the subdomain-takeover detection and confirmation tool.
//
// It is the Go reference server for the necromancer-mcp contract (packet
// P20-01 §5): a thin, policy-applying adapter that exposes graverobber's
// existing engine to an LLM agent over MCP. The graverobber CLI in
// cmd/graverobber and this server are two front ends over ONE engine — the
// pkg/scanner, pkg/verifier, and pkg/fingerprints packages — so the two can
// never drift (A8). This command reimplements no detection logic (D2/A1): every
// handler validates its input, calls the engine, and marshals the result into
// an nmc.Finding.
//
// Tool surface (the §7 graverobber verb map):
//
//	scan_takeover      SAFE   detect candidate takeovers across targets
//	confirm_takeover   ACTIVE prove a candidate by a read-only service probe (gated, D6)
//	list_fingerprints  SAFE   enumerate the service fingerprints graverobber recognises
//
// Plus a read-only MCP resource (Appendix E) exposing the full fingerprint
// database as JSON for direct agent inspection.
//
// Transport defaults to stdio (D9); NMC_TRANSPORT=http (with NMC_BIND/NMC_TOKEN
// or --transport/--bind/--token) selects Streamable HTTP. Loopback is the
// default bind and a routable bind requires a bearer token (D10) — all enforced
// by the shared nmc library, not here.
//
// Safety: confirm_takeover is the only active verb. It calls
// nmc.MustActive(confirm) first (D6) and only ever runs graverobber's read-only
// ServiceVerifier, which CONFIRMS a takeover (an S3 NoSuchBucket GET, a GitHub
// Pages repo-existence GET, an Azure NXDOMAIN lookup) but never CLAIMS the
// resource. Confirming a takeover is in scope; performing one is not.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bugsyhewitt/graverobber/internal/nmc"
	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/scanner"
	"github.com/bugsyhewitt/graverobber/pkg/verifier"
)

// version tracks graverobber's semver and is advertised by the MCP server and
// stamped into every finding's provenance (D11). It is overridable at build
// time with -ldflags "-X main.version=…".
var version = "1.0.1"

// scanTimeout bounds a single scan_takeover call so an agent that abandons a
// turn cannot leave a runaway scan; confirmTimeout bounds the active probe.
// Both are deliberately generous — recon is I/O-bound — and both are enforced
// via a context derived from the handler's request context so SDK-side
// cancellation still wins (A9).
const (
	scanTimeout    = 5 * time.Minute
	confirmTimeout = 30 * time.Second
)

// engineDB loads the fingerprint database the engine matches against. It
// prefers the on-disk cache written by `graverobber update`, and falls back to
// the compile-time embedded snapshot so the server is always usable offline.
// Diagnostics go through slog (stderr, D7) — never stdout.
func engineDB() (*fingerprints.DB, error) {
	if path, err := fingerprints.CachePath(); err == nil {
		if cached, err := fingerprints.LoadFile(path); err == nil {
			return cached, nil
		}
	}
	return fingerprints.Embedded()
}

// ----------------------------------------------------------------------------
// scan_takeover : SAFE (detect-only)
// ----------------------------------------------------------------------------

// ScanIn is the input schema for scan_takeover.
type ScanIn struct {
	Targets []string `json:"targets" jsonschema:"hostnames/subdomains to test for a dangling takeover"`
	// MinConfidence optionally suppresses findings weaker than this tier
	// (confirmed | likely | potential). Empty emits every finding.
	MinConfidence string `json:"min_confidence,omitempty" jsonschema:"optional floor: confirmed|likely|potential"`
}

// ScanOut is the output schema for scan_takeover: zero or more candidate
// findings, emitted as structuredContent (D8).
type ScanOut struct {
	Findings []nmc.Finding `json:"findings"`
}

// scanTakeover returns the scan_takeover handler. It runs graverobber's real
// scanner over the supplied targets and maps each engine finding to an
// nmc.Finding in the "detected" state (this verb is detect-only; confirmation
// is the separate, gated confirm_takeover verb).
func scanTakeover(s *nmc.Server, db *fingerprints.DB) mcp.ToolHandlerFor[ScanIn, ScanOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ScanIn) (*mcp.CallToolResult, ScanOut, error) {
		if len(in.Targets) == 0 {
			// Bad arguments are a PROTOCOL error (Appendix D): the agent must fix
			// the request, not record a finding.
			return nil, ScanOut{}, fmt.Errorf("scan_takeover: at least one target is required")
		}
		minConf, ok := finding.ParseConfidence(in.MinConfidence)
		if !ok {
			return nil, ScanOut{}, fmt.Errorf("scan_takeover: invalid min_confidence %q (want confirmed|likely|potential)", in.MinConfidence)
		}

		ctx, cancel := context.WithTimeout(ctx, scanTimeout)
		defer cancel()

		opts := scanner.DefaultOptions()
		opts.MinConfidence = minConf
		sc := scanner.New(db, opts)

		// Feed the targets on a buffered channel and close it so the scanner's
		// workers drain and the output channel closes deterministically.
		targets := make(chan string, len(in.Targets))
		for _, t := range in.Targets {
			targets <- t
		}
		close(targets)

		out := ScanOut{}
		for f := range sc.Run(ctx, targets) {
			out.Findings = append(out.Findings, scanFindingToNMC(s, f))
		}
		return nil, out, nil
	}
}

// scanFindingToNMC maps a graverobber engine finding to the interim nmc.Finding
// shape. A scan-stage finding is always reported as "detected"; its engine
// confidence tier is carried in raw for triage. Evidence is bounded by
// construction (the engine emits short human-readable strings).
func scanFindingToNMC(s *nmc.Server, f finding.Finding) nmc.Finding {
	out := s.Finding("scan_takeover", f.Subdomain, nmc.StateDetected, false)
	out.Surface = serviceLabel(f)
	out.Title = fmt.Sprintf("Candidate subdomain takeover (%s)", vectorLabel(f))
	out.Evidence = f.Evidence
	if f.Fingerprint != "" {
		out.Refs = []string{f.Fingerprint}
	}
	out.Raw = map[string]any{
		"vector":     string(f.Vector),
		"service":    f.Service,
		"confidence": string(f.Confidence),
		"cname":      f.CNAME,
		"scheme":     f.Scheme,
	}
	return out
}

// ----------------------------------------------------------------------------
// confirm_takeover : ACTIVE (gated, D6)
// ----------------------------------------------------------------------------

// ConfirmIn is the input schema for confirm_takeover.
type ConfirmIn struct {
	Target string `json:"target" jsonschema:"host previously flagged by scan_takeover"`
	// Service is the fingerprinted service that owns the dangling CNAME. The
	// read-only confirmation probe is service-specific; graverobber confirms
	// "AWS/S3", "GitHub Pages", and "Microsoft Azure".
	Service string `json:"service" jsonschema:"fingerprinted service, e.g. AWS/S3 | GitHub Pages | Microsoft Azure"`
	// CNAME is the dangling canonical target the probe inspects (e.g.
	// my-bucket.s3.amazonaws.com or user.github.io). It is what scan_takeover
	// reported in raw.cname for the candidate.
	CNAME string `json:"cname" jsonschema:"the dangling CNAME target to probe (from scan_takeover raw.cname)"`
	// Confirm MUST be true to run the active confirmation probe (D6). It
	// defaults to false so an agent cannot trigger a target-touching path it
	// half-understands.
	Confirm bool `json:"confirm,omitempty" jsonschema:"MUST be true to run the read-only confirmation probe (D6)"`
	// GitHubToken optionally raises the api.github.com rate limit for the GitHub
	// Pages probe from 60 to 5000 requests/hour. The tool is credential-free
	// unless the operator opts in; the token is never echoed back.
	GitHubToken string `json:"github_token,omitempty" jsonschema:"optional GitHub token to raise the Pages probe rate limit"`
}

// confirmTakeover returns the confirm_takeover handler. It is the suite's
// reference ACTIVE verb: it refuses to act unless Confirm==true (D6), then runs
// graverobber's read-only ServiceVerifier to upgrade a candidate to CONFIRMED.
// The verifier never claims the resource — it only observes a definitive
// unclaimed signal (S3 NoSuchBucket, GitHub repo 404, Azure NXDOMAIN).
func confirmTakeover(s *nmc.Server) mcp.ToolHandlerFor[ConfirmIn, nmc.Finding] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ConfirmIn) (*mcp.CallToolResult, nmc.Finding, error) {
		// D6 chokepoint, first line: refuse the active path without explicit
		// per-call consent. This is a PROTOCOL error, not a finding (Appendix D).
		if err := nmc.MustActive(in.Confirm); err != nil {
			return nil, nmc.Finding{}, err
		}
		if in.Target == "" || in.CNAME == "" {
			return nil, nmc.Finding{}, fmt.Errorf("confirm_takeover: target and cname are required")
		}

		ctx, cancel := context.WithTimeout(ctx, confirmTimeout)
		defer cancel()

		sv := verifier.NewServiceVerifier(verifier.Config{
			GitHubToken: in.GitHubToken,
			Timeout:     confirmTimeout,
		})

		// Reconstruct the minimal finding the verifier dispatches on. The
		// verifier keys off Vector==CNAME, Service, and CNAME, and only ever
		// upgrades LIKELY→CONFIRMED, so we present the candidate as LIKELY.
		cand := finding.Finding{
			Subdomain:  in.Target,
			Vector:     finding.VectorCNAME,
			Service:    in.Service,
			CNAME:      in.CNAME,
			Confidence: finding.Likely,
			Timestamp:  time.Now().UTC(),
		}

		conf, err := sv.Verify(ctx, cand)
		if err != nil {
			// The probe itself failed (network/transient): that is data about the
			// TARGET interaction, so report it as a Finding with state=error
			// (Appendix D), not a protocol error.
			f := s.Finding("confirm_takeover", in.Target, nmc.StateError, true)
			f.Surface = in.Service
			f.Title = "Subdomain takeover confirmation probe error"
			f.Evidence = boundedErr(err)
			return nil, f, nil
		}

		state := nmc.StateNotVulnerable
		title := "Subdomain takeover not confirmed"
		evidence := fmt.Sprintf("read-only %s probe of %s did not return a definitive unclaimed signal", in.Service, in.CNAME)
		if conf == finding.Confirmed {
			state = nmc.StateConfirmed
			title = "Subdomain takeover confirmed"
			evidence = fmt.Sprintf("read-only %s probe of %s returned a definitive unclaimed signal", in.Service, in.CNAME)
		}

		f := s.Finding("confirm_takeover", in.Target, state, true)
		f.Surface = in.Service
		f.Title = title
		f.Evidence = evidence
		f.Raw = map[string]any{
			"service":    in.Service,
			"cname":      in.CNAME,
			"confidence": string(conf),
		}
		return nil, f, nil
	}
}

// ----------------------------------------------------------------------------
// list_fingerprints : SAFE (enumerate)
// ----------------------------------------------------------------------------

// ListOut is the output schema for list_fingerprints.
type ListOut struct {
	Services []string `json:"services"`
	Count    int      `json:"count"`
}

// listFingerprints returns the list_fingerprints handler. It enumerates the
// distinct service names in the loaded fingerprint database — a cheap,
// high-value verb that lets an agent plan (which services graverobber can match)
// before scanning (§7 cross-cutting rule).
func listFingerprints(db *fingerprints.DB) mcp.ToolHandlerFor[struct{}, ListOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListOut, error) {
		names := distinctServices(db)
		return nil, ListOut{Services: names, Count: len(names)}, nil
	}
}

// ----------------------------------------------------------------------------
// helpers (pure, dependency-free, unit-tested)
// ----------------------------------------------------------------------------

// distinctServices returns the sorted, de-duplicated set of service names in
// db. Blank service names are skipped.
func distinctServices(db *fingerprints.DB) []string {
	seen := map[string]struct{}{}
	for _, e := range db.Entries() {
		if e.Service == "" {
			continue
		}
		seen[e.Service] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// serviceLabel returns the best human-readable sub-locus for a finding: the
// fingerprinted service when present, else the detection vector.
func serviceLabel(f finding.Finding) string {
	if f.Service != "" {
		return f.Service
	}
	return string(f.Vector)
}

// vectorLabel returns a label describing what produced the candidate: the
// service for a CNAME match, otherwise the vector name.
func vectorLabel(f finding.Finding) string {
	if f.Vector == finding.VectorCNAME && f.Service != "" {
		return f.Service
	}
	return string(f.Vector)
}

// maxEvidence bounds any evidence/error string written into the JSON-RPC
// channel (§9/A5: the channel is control-plane, not data transfer).
const maxEvidence = 2 << 10 // 2 KiB

// boundedErr renders an error to a length-bounded string for a Finding's
// Evidence field.
func boundedErr(err error) string {
	s := err.Error()
	if len(s) > maxEvidence {
		return s[:maxEvidence] + "…[truncated]"
	}
	return s
}

// fingerprintsJSON returns the full fingerprint database as indented JSON for
// the read-only resource (Appendix E). It is bounded by the database size,
// which is small (the can-i-take-over-xyz set).
func fingerprintsJSON(db *fingerprints.DB) (string, error) {
	b, err := json.MarshalIndent(db.Entries(), "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ----------------------------------------------------------------------------
// wiring
// ----------------------------------------------------------------------------

// build constructs the fully-wired MCP server: it loads the engine's
// fingerprint DB, registers the three tools and the read-only resource, and
// returns the server ready to Run. Splitting this out of main keeps it testable
// — the in-process smoke test builds the same server and drives it over an
// in-memory transport.
func build() (*nmc.Server, error) {
	db, err := engineDB()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint database: %w", err)
	}

	s := nmc.New("graverobber", version) // logger → stderr (D7); naming policy applied

	nmc.AddTool(s, "scan_takeover",
		"Detect candidate subdomain takeovers across the given targets (safe, read-only). "+
			"Returns one finding per candidate in the 'detected' state; confirmation is the separate, gated confirm_takeover verb.",
		scanTakeover(s, db))

	nmc.AddTool(s, "confirm_takeover",
		"Confirm a flagged takeover with a READ-ONLY service probe (S3 NoSuchBucket, GitHub Pages repo 404, Azure NXDOMAIN). "+
			"ACTIVE: requires confirm=true (D6). Confirms a takeover but never claims the resource.",
		confirmTakeover(s))

	nmc.AddTool(s, "list_fingerprints",
		"Enumerate the distinct service fingerprints graverobber recognises for CNAME takeover detection (safe).",
		listFingerprints(db))

	// Read-only resource: the full fingerprint database (Appendix E). Resources
	// are for data, never for actions or anything that touches a target.
	s.AddResource(
		"fingerprints://can-i-take-over-xyz",
		"takeover-fingerprints",
		"The full subdomain-takeover service fingerprint database as JSON.",
		"application/json",
		func() (string, error) { return fingerprintsJSON(db) },
	)

	return s, nil
}

func main() {
	s, err := build()
	if err != nil {
		// build() failures are infrastructure errors (DB load): report on stderr
		// (D7) and exit non-zero. Nothing has touched stdout.
		fmt.Fprintln(os.Stderr, "graverobber-mcp:", err)
		os.Exit(1)
	}
	if err := s.Run(context.Background()); err != nil { // stdio default (D9)
		fmt.Fprintln(os.Stderr, "graverobber-mcp:", err)
		os.Exit(1)
	}
}
