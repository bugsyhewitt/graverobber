package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/graverobber/pkg/ct"
)

// ctFlags holds parsed flags for the `ct` subcommand.
type ctFlags struct {
	target     string
	list       string
	findings   string
	candidates bool
	rateLimit  float64
	timeout    int
}

// newCTCmd builds the `graverobber ct` subcommand: query Certificate
// Transparency logs (crt.sh) for certificates issued on target domains and flag
// any cert issued for a subdomain a prior scan classified as a takeover
// candidate. It reads targets from -t, -l, or stdin (same precedence as the
// scan command), dedupes them to apex domains, and streams certificates as
// JSONL.
func newCTCmd() *cobra.Command {
	f := &ctFlags{}

	cmd := &cobra.Command{
		Use:   "ct",
		Short: "Query Certificate Transparency logs (crt.sh) for takeover-candidate certs",
		Long: "ct closes the takeover detection loop: the scanner finds dangling-record\n" +
			"candidates; ct checks whether a certificate has already been issued for them.\n" +
			"An unexpected certificate on a dangling subdomain is near-proof a takeover\n" +
			"already occurred.\n\n" +
			"Targets come from -t, -l, or stdin (same precedence as scan); they are\n" +
			"deduplicated to apex domains before querying crt.sh. Pipe a prior scan's\n" +
			"JSONL output via --findings to cross-reference: certs whose name matches a\n" +
			"flagged subdomain get \"takeover_candidate\": true. Output is JSONL.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCT(cmd.Context(), f)
		},
	}

	fl := cmd.Flags()
	fl.StringVarP(&f.target, "target", "t", "", "single target host")
	fl.StringVarP(&f.list, "list", "l", "", "file of targets, one host per line")
	fl.StringVar(&f.findings, "findings", "", "prior graverobber JSONL findings file to cross-reference (subdomains become takeover candidates)")
	fl.BoolVar(&f.candidates, "candidates-only", false, "emit only certificates flagged as takeover candidates")
	fl.Float64Var(&f.rateLimit, "rate-limit", 1.0, "max crt.sh queries/sec (be polite; crt.sh is a shared service)")
	fl.IntVar(&f.timeout, "timeout", 30, "per-query HTTP timeout in seconds")

	return cmd
}

// runCT executes the ct subcommand body.
func runCT(ctx context.Context, f *ctFlags) error {
	hosts, err := collectCTTargets(f)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("ct: no targets (use -t, -l, or pipe hosts on stdin)")
	}
	apexes := ct.DedupeApexes(hosts)

	var candidates map[string]bool
	if f.findings != "" {
		fc, err := os.Open(f.findings)
		if err != nil {
			return fmt.Errorf("open findings %s: %w", f.findings, err)
		}
		defer fc.Close()
		candidates, err = ct.CandidatesFromFindings(fc)
		if err != nil {
			return err
		}
	}

	rl := time.Duration(0)
	if f.rateLimit > 0 {
		rl = time.Duration(float64(time.Second) / f.rateLimit)
	} else {
		rl = -1 // disable
	}

	client := ct.NewClient(ct.Config{
		RateLimit: rl,
		Timeout:   time.Duration(f.timeout) * time.Second,
	})

	enc := json.NewEncoder(os.Stdout)
	var flagged int
	for _, apex := range apexes {
		certs, err := client.Query(ctx, apex, candidates)
		if err != nil {
			// A single apex failing (crt.sh hiccup, throttle) should not abort
			// the whole run; report to stderr and continue.
			fmt.Fprintf(os.Stderr, "graverobber: ct %s: %v\n", apex, err)
			continue
		}
		for _, cert := range certs {
			if f.candidates && !cert.TakeoverCandidate {
				continue
			}
			if cert.TakeoverCandidate {
				flagged++
			}
			if err := enc.Encode(cert); err != nil {
				return fmt.Errorf("write certificate: %w", err)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	// Exit code mirrors the scan command: 1 when takeover-candidate certs were
	// found (actionable signal), 0 otherwise.
	if flagged > 0 {
		return errFindings
	}
	return nil
}

// collectCTTargets reads all targets for the ct command into a slice, in
// precedence order -t, -l, then stdin. Unlike the streaming scan path, ct
// materializes targets so it can dedupe to apexes before querying.
func collectCTTargets(f *ctFlags) ([]string, error) {
	switch {
	case f.target != "":
		if h := normalizeLine(f.target); h != "" {
			return []string{h}, nil
		}
		return nil, nil
	case f.list != "":
		file, err := os.Open(f.list)
		if err != nil {
			return nil, fmt.Errorf("open list %s: %w", f.list, err)
		}
		defer file.Close()
		return readCTLines(file)
	default:
		return readCTLines(os.Stdin)
	}
}

// readCTLines reads normalized, non-empty hosts from r.
func readCTLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if h := normalizeLine(sc.Text()); h != "" {
			out = append(out, h)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
