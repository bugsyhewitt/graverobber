package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/graverobber/pkg/links"
)

// linksFlags holds parsed flags for the `links` subcommand.
type linksFlags struct {
	target      string
	list        string
	concurrency int
	timeout     int
	json        bool
	httpOnly    bool
	httpsOnly   bool
}

// newLinksCmd builds the `graverobber links` subcommand: the second-order
// takeover discovery step. For each live target it fetches the page and emits
// the cross-origin host references found in the body — hosts the page points at
// that live on a different registrable apex. Those hosts are exactly the
// second-order takeover candidates: feed them back into `scan`.
//
//	graverobber links -l live-hosts.txt | graverobber scan --json
//
// Default output is one host per line (pipe-friendly into scan). --json emits
// {"host","source"} JSONL so you can see which page referenced each host.
func newLinksCmd() *cobra.Command {
	f := &linksFlags{}

	cmd := &cobra.Command{
		Use:   "links",
		Short: "Extract cross-origin host references from live pages (second-order takeover discovery)",
		Long: "links is graverobber's second-order takeover discovery step.\n\n" +
			"A live web app often references hosts in its HTML/JS/JSON that are\n" +
			"themselves dangling — a forgotten analytics endpoint, a legacy CDN, an\n" +
			"abandoned OAuth redirect host. The page resolves fine; the vulnerable\n" +
			"host is one hop deeper. links fetches each target, pulls every\n" +
			"cross-origin host reference out of the body (excluding same-apex hosts,\n" +
			"which the main scanner already covers), and emits them.\n\n" +
			"Targets come from -t, -l, or stdin (same precedence as scan). Default\n" +
			"output is one host per line, ready to pipe straight back into scan:\n\n" +
			"  graverobber links -l live-hosts.txt | graverobber scan --json\n\n" +
			"Use --json for {\"host\",\"source\"} JSONL with source attribution.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLinks(cmd.Context(), f)
		},
	}

	fl := cmd.Flags()
	fl.StringVarP(&f.target, "target", "t", "", "single target host")
	fl.StringVarP(&f.list, "list", "l", "", "file of targets, one host per line")
	fl.IntVarP(&f.concurrency, "concurrency", "c", 20, "concurrent page fetches")
	fl.IntVar(&f.timeout, "timeout", 15, "per-page HTTP timeout in seconds")
	fl.BoolVar(&f.json, "json", false, "emit {\"host\",\"source\"} JSONL (default: bare host per line)")
	fl.BoolVar(&f.httpOnly, "http-only", false, "fetch pages over HTTP only")
	fl.BoolVar(&f.httpsOnly, "https-only", false, "fetch pages over HTTPS only")

	return cmd
}

// runLinks executes the links subcommand body. It fans target fetches out
// across a bounded worker pool, deduplicates the union of referenced hosts
// across all targets, and streams the result. Exit code mirrors scan/ct: 1 when
// any cross-origin references were found (actionable), 0 otherwise.
func runLinks(ctx context.Context, f *linksFlags) error {
	if f.httpOnly && f.httpsOnly {
		return errors.New("--http-only and --https-only are mutually exclusive")
	}

	hosts, err := collectLinksTargets(f)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("links: no targets (use -t, -l, or pipe hosts on stdin)")
	}

	client := links.NewClient(links.Config{
		Timeout:   time.Duration(f.timeout) * time.Second,
		HTTPOnly:  f.httpOnly,
		HTTPSOnly: f.httpsOnly,
	})

	conc := f.concurrency
	if conc < 1 {
		conc = 1
	}

	in := make(chan string)
	results := make(chan links.Reference)

	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range in {
				refs, err := client.Extract(ctx, host)
				if err != nil {
					// One unreachable target should not abort the run; report to
					// stderr and continue (mirrors the ct subcommand's behaviour).
					fmt.Fprintf(os.Stderr, "graverobber: links %s: %v\n", host, err)
					continue
				}
				for _, r := range refs {
					select {
					case <-ctx.Done():
						return
					case results <- r:
					}
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case in <- h:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	// Deduplicate referenced hosts across every source page so the same dangling
	// CDN referenced by ten pages emits once. First-seen source is retained for
	// JSON attribution.
	enc := json.NewEncoder(os.Stdout)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	seen := make(map[string]bool)
	var emitted int
	for r := range results {
		if seen[r.Host] {
			continue
		}
		seen[r.Host] = true
		emitted++
		if f.json {
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("write reference: %w", err)
			}
		} else {
			fmt.Fprintln(out, r.Host)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}

	if emitted > 0 {
		return errFindings
	}
	return nil
}

// collectLinksTargets reads all targets into a slice, in precedence order -t,
// -l, then stdin. It mirrors collectCTTargets so the two discovery subcommands
// behave identically at the input boundary.
func collectLinksTargets(f *linksFlags) ([]string, error) {
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
		return readLinksLines(file)
	default:
		return readLinksLines(os.Stdin)
	}
}

// readLinksLines reads normalized, non-empty hosts from r.
func readLinksLines(r io.Reader) ([]string, error) {
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
