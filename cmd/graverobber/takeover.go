package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/graverobber/pkg/confirm"
	"github.com/bugsyhewitt/graverobber/pkg/confirm/adapters"
	"github.com/bugsyhewitt/graverobber/pkg/engine"
	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// This file wires Packet 07's takeover-confirmation feature into the CLI:
//
//	scan-takeover     multi-signal detection (SAFE; no claiming) — the precision
//	                  play that suppresses fingerprint-only false positives.
//	confirm-takeover  the gated safe-claim confirmer. Defaults to a DRY-RUN demo
//	                  (claim/serve/prove/release simulated in-memory) so the
//	                  see-it-work loop runs without touching a provider. A real
//	                  claim requires explicit authorization AND a wired live
//	                  adapter — graverobber never performs a real provider
//	                  registration autonomously (see pkg/confirm/adapters).
//	list-fingerprints the fingerprint DB and which services have a claim adapter.
//
// (Packet 01's MCP verbs map to these subcommands; this repository ships no MCP
// server, so the verbs are realized as CLI subcommands — see TAKEOVER.md.)

// newScanTakeoverCmd builds `graverobber scan-takeover`: multi-signal detection.
func newScanTakeoverCmd() *cobra.Command {
	var (
		target    string
		list      string
		offline   bool
		resolvers string
		jsonOut   bool
	)
	cmd := &cobra.Command{
		Use:   "scan-takeover",
		Short: "Multi-signal subdomain-takeover detection (fingerprint + NXDOMAIN + TLS + DNS chain). Safe — no claiming.",
		Long: "scan-takeover runs graverobber's multi-signal detector: a candidate is\n" +
			"reported only when a provider fingerprint match is corroborated by at\n" +
			"least one independent unclaimed-backend signal (the CNAME target is\n" +
			"NXDOMAIN, or the TLS certificate is absent/default/mismatched). A bare\n" +
			"fingerprint match with a live, owned backend is suppressed — the\n" +
			"precision that separates graverobber from fingerprint-only scanners.\n\n" +
			"It is SAFE: it only resolves DNS and issues read-only HTTP/TLS probes. It\n" +
			"emits nmc.finding-style JSONL with the takeover.<service> rule and the\n" +
			"multi-signal evidence. Confirm true positives with `confirm-takeover`.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScanTakeover(cmd.Context(), scanTakeoverArgs{
				target: target, list: list, offline: offline, resolvers: resolvers, json: jsonOut,
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&target, "target", "t", "", "single subdomain/host to test")
	fl.StringVarP(&list, "list", "l", "", "file of hosts, one per line (CNAME list from recon)")
	fl.BoolVar(&offline, "offline", false, "use cached/embedded fingerprints only, no network for the DB")
	fl.StringVar(&resolvers, "resolvers", "", "file of custom DNS resolvers")
	fl.BoolVar(&jsonOut, "json", true, "emit JSONL findings (default true)")
	return cmd
}

type scanTakeoverArgs struct {
	target, list, resolvers string
	offline, json           bool
}

func runScanTakeover(ctx context.Context, a scanTakeoverArgs) error {
	db, err := loadTakeoverDB(a.offline)
	if err != nil {
		return err
	}
	res, err := loadResolvers(a.resolvers)
	if err != nil {
		return err
	}
	r := resolver.New(res, 10*time.Second)
	det := engine.NewDetector(db, engine.WithResolver(r, resolver.ErrNXDomain))

	hosts, err := collectTakeoverTargets(a.target, a.list)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("scan-takeover: no targets (use -t, -l, or pipe hosts on stdin)")
	}

	enc := json.NewEncoder(os.Stdout)
	var found int
	for _, host := range hosts {
		sig, detected := det.Detect(ctx, host)
		if !detected {
			continue
		}
		f := det.Finding(host, sig)
		found++
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
	}
	if found > 0 {
		return errFindings
	}
	return nil
}

// newConfirmTakeoverCmd builds `graverobber confirm-takeover`: the gated
// safe-claim confirmer, dry-run by default.
func newConfirmTakeoverCmd() *cobra.Command {
	var (
		target     string
		service    string
		authorized bool
		allowApex  []string
		githubUser string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "confirm-takeover",
		Short: "Safely confirm a takeover: claim a dangling resource, serve a canary, prove control, release. Gated; dry-run by default.",
		Long: "confirm-takeover realizes the safe-claim confirmation EdOverflow\n" +
			"documents — claim the dangling resource into YOUR own provider account,\n" +
			"serve a unique canary on a hidden /.well-known path, prove control by\n" +
			"fetching the FQDN, characterize the blast radius, and RELEASE the\n" +
			"resource. Only a served-and-reflected canary yields `confirmed`; every\n" +
			"other branch is a real negative (`not_vulnerable`) or an error.\n\n" +
			"SAFETY: confirmation is the most sensitive action in the suite. It is\n" +
			"gated (--authorized) and scoped (--allow-apex). By DEFAULT it runs in\n" +
			"DRY-RUN mode: the claim/serve/prove/release lifecycle is simulated\n" +
			"in-memory so you can see it work without registering anything. A REAL\n" +
			"claim additionally requires a wired live adapter; graverobber does not\n" +
			"perform real provider registration autonomously. Only ever run against a\n" +
			"target you own or are explicitly authorized to test.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfirmTakeover(cmd.Context(), confirmTakeoverArgs{
				target: target, service: service, authorized: authorized,
				allowApex: allowApex, githubUser: githubUser, json: jsonOut,
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&target, "target", "t", "", "the FQDN to confirm (required)")
	fl.StringVar(&service, "service", "github-pages", "provider / claim adapter (e.g. github-pages)")
	fl.BoolVar(&authorized, "authorized", false, "REQUIRED to attempt a claim: assert you are authorized to test the target")
	fl.StringArrayVar(&allowApex, "allow-apex", nil, "authorized apex domain(s) (repeatable); the target's apex must be listed")
	fl.StringVar(&githubUser, "github-user", "graverobber-operator", "operator account name used for the (dry-run) claim")
	fl.BoolVar(&jsonOut, "json", true, "emit the resulting JSONL finding (default true)")
	return cmd
}

type confirmTakeoverArgs struct {
	target, service, githubUser string
	authorized, json            bool
	allowApex                   []string
}

func runConfirmTakeover(ctx context.Context, a confirmTakeoverArgs) error {
	if strings.TrimSpace(a.target) == "" {
		return errors.New("confirm-takeover: --target is required")
	}
	if !a.authorized {
		return errors.New("confirm-takeover: refusing — confirmation is gated; pass --authorized to assert you are authorized to test the target")
	}
	apexes := a.allowApex
	if len(apexes) == 0 {
		// Default the allow-list to the target's own apex so the gate is scoped
		// but the operator is not forced to repeat it; --allow-apex narrows it.
		apexes = []string{apexOfHost(a.target)}
	}

	// Build the confirmer with the dry-run GitHub Pages reference adapter. The
	// adapter is dry-run because no live credentials/ops are wired — graverobber
	// does not perform a real provider registration autonomously.
	gh := adapters.NewGitHubPagesAdapter(adapters.GitHubPagesConfig{User: a.githubUser})
	canaries := confirm.NewCanaries(confirm.WithReflector(func(_ context.Context, url string, c *confirm.Canary) bool {
		// Dry-run reflection: the adapter "serves" the canary at its path, so a
		// dry-run confirmation reflects iff the proof URL is the expected canary
		// URL. (A live run uses the real HTTP reflector instead.)
		return strings.HasSuffix(url, c.Path())
	}))
	c := confirm.NewTakeoverConfirmer(
		confirm.WithAdapter(a.service, gh),
		confirm.WithCanaries(canaries),
		confirm.WithGate(confirm.NewGate(true, apexes)),
	)

	f := &finding.Finding{
		Subdomain: strings.ToLower(strings.TrimSpace(a.target)),
		Vector:    finding.VectorCNAME,
		Service:   a.service,
		Rule:      "takeover." + a.service,
		State:     finding.StateDetected,
		Severity:  finding.SeverityHigh,
		Timestamp: time.Now().UTC(),
	}

	if gh.DryRun() {
		fmt.Fprintln(os.Stderr, "graverobber: confirm-takeover running in DRY-RUN mode (no provider registration performed)")
	}

	r, err := c.Confirm(ctx, f)
	if err != nil {
		return fmt.Errorf("confirm-takeover: %w", err)
	}
	c.Apply(f, r)

	if a.json {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
	}
	// Surface outstanding artifacts loudly (should be none).
	if out := c.Tracker().Outstanding(); len(out) > 0 {
		fmt.Fprintf(os.Stderr, "graverobber: WARNING %d claimed resource(s) NOT released — manual cleanup required:\n", len(out))
		for _, art := range out {
			fmt.Fprintf(os.Stderr, "  %s resource %q (canary %s)\n", art.Adapter, art.Handle, art.CanaryID)
		}
		return errors.New("confirm-takeover: claimed resource(s) left registered")
	}
	if f.State == finding.StateConfirmed {
		return errFindings
	}
	return nil
}

// newListFingerprintsCmd builds `graverobber list-fingerprints`: the DB + which
// services have a safe claim adapter (§10/§15).
func newListFingerprintsCmd() *cobra.Command {
	var (
		offline     bool
		jsonOut     bool
		claimedOnly bool
	)
	cmd := &cobra.Command{
		Use:   "list-fingerprints",
		Short: "List the takeover fingerprint database and which services have a safe claim adapter",
		Long: "list-fingerprints prints graverobber's fingerprint database (synced from\n" +
			"can-i-take-over-xyz, augmented with claim-adapter assignments). Use\n" +
			"--claimable to list only the services graverobber can safely CONFIRM\n" +
			"(those with a claim adapter), and --json for machine output.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := loadTakeoverDB(offline)
			if err != nil {
				return err
			}
			if claimedOnly {
				claimable := db.Claimable()
				if jsonOut {
					return json.NewEncoder(os.Stdout).Encode(claimable)
				}
				for _, sa := range claimable {
					fmt.Printf("%-24s  %s\n", sa.Service, sa.Adapter)
				}
				return nil
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(db.Entries())
			}
			for _, e := range db.Entries() {
				adapter := e.ClaimAdapter
				if adapter == "" {
					adapter = "-"
				}
				fmt.Printf("%-24s  status=%-14s  claim_adapter=%s\n", e.Service, e.Status, adapter)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&offline, "offline", false, "use cached/embedded fingerprints only")
	fl.BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	fl.BoolVar(&claimedOnly, "claimable", false, "list only services with a safe claim adapter")
	return cmd
}

// loadTakeoverDB loads the fingerprint DB (cache → embedded) and applies the
// graverobber claim-adapter augmentations (D1) so every entry carries its adapter.
func loadTakeoverDB(offline bool) (*fingerprints.DB, error) {
	var db *fingerprints.DB
	if path, err := fingerprints.CachePath(); err == nil {
		if cached, err := fingerprints.LoadFile(path); err == nil {
			db = cached
		}
	}
	if db == nil {
		emb, err := fingerprints.Embedded()
		if err != nil {
			return nil, fmt.Errorf("load fingerprints: %w", err)
		}
		db = emb
		if !offline {
			fmt.Fprintln(os.Stderr, "graverobber: no fingerprint cache; using embedded snapshot — run `graverobber update`")
		}
	}
	if err := fingerprints.ApplyAugment(db); err != nil {
		return nil, fmt.Errorf("apply claim-adapter augmentations: %w", err)
	}
	return db, nil
}

// collectTakeoverTargets reads targets in precedence order -t, -l, then stdin.
func collectTakeoverTargets(target, list string) ([]string, error) {
	switch {
	case target != "":
		if h := normalizeLine(target); h != "" {
			return []string{h}, nil
		}
		return nil, nil
	case list != "":
		file, err := os.Open(list)
		if err != nil {
			return nil, fmt.Errorf("open list %s: %w", list, err)
		}
		defer file.Close()
		return readTakeoverLines(file)
	default:
		return readTakeoverLines(os.Stdin)
	}
}

func readTakeoverLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if h := normalizeLine(sc.Text()); h != "" {
			out = append(out, h)
		}
	}
	return out, sc.Err()
}

// apexOfHost returns the registrable apex (last two labels) of host.
func apexOfHost(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
