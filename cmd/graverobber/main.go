// Command graverobber is the CLI entrypoint for the subdomain takeover
// scanner. It is a thin wrapper: all detection logic lives in pkg/, and the
// command merely wires flags into a scanner.Scanner and streams the resulting
// findings to an output.Writer.
//
// Exit codes (handoff spec):
//
//	0  scan completed, no findings
//	1  scan completed, findings present
//	2  error (bad input, network failure, etc.)
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
	"github.com/bugsyhewitt/graverobber/pkg/nsproviders"
	"github.com/bugsyhewitt/graverobber/pkg/output"
	"github.com/bugsyhewitt/graverobber/pkg/scanner"
	"github.com/bugsyhewitt/graverobber/pkg/verifier"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// goreleaser sets this from the git tag; see .goreleaser.yaml. It is a var,
// not a const, precisely so the linker can rewrite it.
var version = "dev"

// errFindings is a sentinel: it is returned up through cobra when the scan
// produced at least one finding, so main can translate it to exit code 1
// without it being printed as an error.
var errFindings = errors.New("findings present")

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errFindings) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "graverobber: "+err.Error())
		os.Exit(2)
	}
	os.Exit(0)
}

func run() error {
	// Context cancelled on first SIGINT/SIGTERM so an interrupted mass scan
	// drains its worker pool cleanly instead of leaving goroutines dangling.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return newRootCmd().ExecuteContext(ctx)
}

// cliFlags holds the parsed flag values for the root scan command.
type cliFlags struct {
	target        string
	list          string
	concurrency   int
	timeout       int
	output        string
	json          bool
	sarif         bool
	csv           bool
	silent        bool
	verbose       bool
	noNS          bool
	noSPF         bool
	noMX          bool
	noDKIM        bool
	noDMARC       bool
	noAXFR        bool
	noCAA         bool
	noTLSA        bool
	noMTASTS      bool
	noBIMI        bool
	noDNSSEC      bool
	noTLSRPT      bool
	selectors     string
	fingerprints  []string
	offline       bool
	resolvers     string
	rateLimit     int
	httpOnly      bool
	httpsOnly     bool
	verify        bool
	githubToken   string
	minConfidence string
}

func newRootCmd() *cobra.Command {
	f := &cliFlags{}

	root := &cobra.Command{
		Use:   "graverobber",
		Short: "Subdomain takeover scanner for CNAME, NS, SPF, MX, DKIM, DMARC, AXFR, CAA, TLSA, MTA-STS, BIMI, DNSSEC, and TLSRPT dangling/misconfigured records",
		Long: "graverobber digs up the subdomains your target left for dead.\n" +
			"It detects CNAME fingerprint, NS zone-deletion, SPF include, MX\n" +
			"dangling-record, DKIM selector, DMARC report-host takeover, AXFR\n" +
			"zone-transfer misconfiguration, CAA misconfiguration, TLSA dangling\n" +
			"DANE pin, MTA-STS dangling-policy-host takeover, BIMI dangling-asset\n" +
			"host, DNSSEC orphaned-DS (broken chain-of-trust) outages, and TLSRPT\n" +
			"dangling-report-destination interception across a stream of hosts read\n" +
			"from stdin, a file, or -t.",
		Version: version,
		Args:    cobra.NoArgs,
		// The command reports findings via the errFindings sentinel and its
		// own messages; cobra should neither reprint errors nor dump usage on
		// what are not usage errors.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), f)
		},
	}

	fl := root.Flags()
	fl.StringVarP(&f.target, "target", "t", "", "single target host")
	fl.StringVarP(&f.list, "list", "l", "", "file of targets, one host per line")
	fl.IntVarP(&f.concurrency, "concurrency", "c", 50, "worker count")
	fl.IntVar(&f.timeout, "timeout", 10, "per-target HTTP timeout in seconds")
	fl.StringVarP(&f.output, "output", "o", "", "write findings to file (default stdout)")
	fl.BoolVar(&f.json, "json", false, "JSONL output (default: coloured terminal)")
	fl.BoolVar(&f.sarif, "sarif", false, "SARIF 2.1.0 output for GitHub Code Scanning / CI upload")
	fl.BoolVar(&f.csv, "csv", false, "CSV output (header + one row per finding) for spreadsheet/ticket triage")
	fl.BoolVar(&f.silent, "silent", false, "results only, suppress progress/banner")
	fl.BoolVar(&f.verbose, "verbose", false, "verbose debug logging to stderr")
	fl.BoolVar(&f.noNS, "no-ns", false, "skip NS takeover checks")
	fl.BoolVar(&f.noSPF, "no-spf", false, "skip SPF include checks")
	fl.BoolVar(&f.noMX, "no-mx", false, "skip MX dangling-record checks")
	fl.BoolVar(&f.noDKIM, "no-dkim", false, "skip DKIM selector dangling-CNAME checks")
	fl.BoolVar(&f.noDMARC, "no-dmarc", false, "skip DMARC report-host dangling + p=none checks")
	fl.BoolVar(&f.noAXFR, "no-axfr", false, "skip AXFR zone-transfer misconfiguration checks")
	fl.BoolVar(&f.noCAA, "no-caa", false, "skip CAA (Certification Authority Authorization) misconfiguration checks")
	fl.BoolVar(&f.noTLSA, "no-tlsa", false, "skip TLSA dangling-DANE-pin checks")
	fl.BoolVar(&f.noMTASTS, "no-mtasts", false, "skip MTA-STS dangling-policy-host checks")
	fl.BoolVar(&f.noBIMI, "no-bimi", false, "skip BIMI dangling-asset-host checks")
	fl.BoolVar(&f.noDNSSEC, "no-dnssec", false, "skip DNSSEC orphaned-DS (broken chain-of-trust) checks")
	fl.BoolVar(&f.noTLSRPT, "no-tlsrpt", false, "skip TLSRPT dangling-report-destination checks")
	fl.StringVar(&f.selectors, "selectors", "", "comma-separated DKIM selectors to probe (default: common ESP selectors)")
	fl.StringArrayVar(&f.fingerprints, "fingerprints", nil, "additional fingerprint JSON to merge (repeatable)")
	fl.BoolVar(&f.offline, "offline", false, "use cached/embedded fingerprints only, no network")
	fl.StringVar(&f.resolvers, "resolvers", "", "file of custom DNS resolvers")
	fl.IntVar(&f.rateLimit, "rate-limit", 0, "global max requests/sec (0 = unlimited)")
	fl.BoolVar(&f.httpOnly, "http-only", false, "probe services over HTTP only")
	fl.BoolVar(&f.httpsOnly, "https-only", false, "probe services over HTTPS only")
	fl.BoolVar(&f.verify, "verify", false, "actively verify S3/GitHub Pages/Azure findings (upgrades LIKELY→CONFIRMED)")
	fl.StringVar(&f.githubToken, "github-token", "", "GitHub token for the --verify Pages probe (raises API rate limit)")
	fl.StringVar(&f.minConfidence, "min-confidence", "", "suppress findings below this tier: confirmed|likely|potential (default: emit all)")

	root.AddCommand(newUpdateCmd())
	root.AddCommand(newCTCmd())
	root.AddCommand(newLinksCmd())
	return root
}

// newUpdateCmd builds the `graverobber update` subcommand: an explicit,
// nuclei-style refresh of the local databases from upstream. By default it
// refreshes the CNAME fingerprint database; --ns-providers refreshes the NS
// takeover provider list from indianajson/can-i-take-over-dns instead.
func newUpdateCmd() *cobra.Command {
	var nsProviders bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Refresh the local fingerprint and NS-provider databases from upstream",
		Long: "update refreshes graverobber's local data caches from their canonical\n" +
			"upstream sources.\n\n" +
			"  graverobber update                 refresh the CNAME fingerprint database\n" +
			"  graverobber update --ns-providers  refresh the NS takeover provider list",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if nsProviders {
				return runNSProvidersUpdate(cmd.Context())
			}
			// v1.0 passes NoopSignatureVerifier: the upstream source is
			// unsigned and HTTPS provides transport integrity (handoff Q3).
			res, err := fingerprints.Update(cmd.Context(), fingerprints.NoopSignatureVerifier{})
			if err != nil {
				return fmt.Errorf("update: %w", err)
			}
			fmt.Printf("fingerprints updated: %s\n", res.Path)
			fmt.Printf("  total %d  (+%d added, -%d removed, ~%d changed)\n",
				res.Total, res.Added, res.Removed, res.Changed)
			return nil
		},
	}
	cmd.Flags().BoolVar(&nsProviders, "ns-providers", false,
		"refresh the NS takeover provider list from indianajson/can-i-take-over-dns instead of fingerprints")
	return cmd
}

// runNSProvidersUpdate refreshes the cached NS-provider list and prints a diff
// of the vulnerable-suffix set.
func runNSProvidersUpdate(ctx context.Context) error {
	res, err := nsproviders.Update(ctx)
	if err != nil {
		return fmt.Errorf("update --ns-providers: %w", err)
	}
	fmt.Printf("ns providers updated: %s\n", res.Path)
	fmt.Printf("  total %d  (%d vulnerable; +%d added, -%d removed)\n",
		res.Total, res.Vulnerable, res.Added, res.Removed)
	return nil
}

// runScan executes a scan according to f. It is the body of the root command.
func runScan(ctx context.Context, f *cliFlags) error {
	if f.httpOnly && f.httpsOnly {
		return errors.New("--http-only and --https-only are mutually exclusive")
	}
	if n := boolCount(f.json, f.sarif, f.csv); n > 1 {
		return errors.New("--json, --sarif, and --csv are mutually exclusive output formats")
	}

	minConf, ok := finding.ParseConfidence(strings.ToLower(strings.TrimSpace(f.minConfidence)))
	if !ok {
		return fmt.Errorf("invalid --min-confidence %q: want confirmed, likely, or potential", f.minConfidence)
	}

	db, err := loadDB(ctx, f)
	if err != nil {
		return err
	}

	resolvers, err := loadResolvers(f.resolvers)
	if err != nil {
		return err
	}

	opts := scanner.Options{
		Concurrency:   f.concurrency,
		Timeout:       time.Duration(f.timeout) * time.Second,
		RateLimit:     f.rateLimit,
		NoNS:          f.noNS,
		NoSPF:         f.noSPF,
		NoMX:          f.noMX,
		NoDKIM:        f.noDKIM,
		NoDMARC:       f.noDMARC,
		NoAXFR:        f.noAXFR,
		NoCAA:         f.noCAA,
		NoTLSA:        f.noTLSA,
		NoMTASTS:      f.noMTASTS,
		NoBIMI:        f.noBIMI,
		NoDNSSEC:      f.noDNSSEC,
		NoTLSRPT:      f.noTLSRPT,
		HTTPOnly:      f.httpOnly,
		HTTPSOnly:     f.httpsOnly,
		Resolvers:     resolvers,
		DKIMSelectors: parseSelectors(f.selectors),
		MinConfidence: minConf,
	}

	w, closeOut, err := openWriter(f)
	if err != nil {
		return err
	}
	defer closeOut()

	targets, scanErr := targetChan(ctx, f)

	sc := scanner.New(db, opts)
	if f.verify {
		sc.SetVerifier(verifier.NewServiceVerifier(verifier.Config{
			GitHubToken: f.githubToken,
			Timeout:     opts.Timeout,
			Resolvers:   resolvers,
		}))
	}
	findings := sc.Run(ctx, targets)

	var summary scanSummary
	for fnd := range findings {
		if err := w.Write(fnd); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
		summary.tally(fnd)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}

	// A target-stream error (e.g. unreadable list file) surfaces only after
	// the channel is drained; report it rather than masking it with exit 0/1.
	if err := <-scanErr; err != nil {
		return err
	}
	if !f.silent && !f.json && !f.sarif && !f.csv {
		summary.write(os.Stderr)
	}
	if summary.total > 0 {
		return errFindings
	}
	return nil
}

// scanSummary accumulates a per-tier and per-vector tally of emitted findings so
// the human-readable (non-machine) run can close with a triage breakdown rather
// than a bare count. It is written to stderr only — the JSONL/SARIF/CSV wire
// contracts on stdout are untouched, and --silent suppresses it entirely.
type scanSummary struct {
	total    int
	byTier   map[finding.Confidence]int
	byVector map[finding.Vector]int
}

// tally records one finding. It lazily initialises the maps so a zero
// scanSummary is usable.
func (s *scanSummary) tally(f finding.Finding) {
	s.total++
	if s.byTier == nil {
		s.byTier = make(map[finding.Confidence]int)
		s.byVector = make(map[finding.Vector]int)
	}
	s.byTier[f.Confidence]++
	s.byVector[f.Vector]++
}

// summaryTierOrder fixes the tier columns from strongest to weakest so the
// breakdown reads the way an operator triages: confirmed first.
var summaryTierOrder = []finding.Confidence{finding.Confirmed, finding.Likely, finding.Potential}

// summaryVectorOrder fixes the vector columns to the detector pipeline order so
// the breakdown is stable across runs regardless of which vector emitted first.
// It MUST list every vector the scanner can emit: summaryParts iterates only
// over these keys, so a vector missing here is silently dropped from the
// "by vector:" line even though its findings still count toward the total and
// the tier breakdown — making the breakdown fail to reconcile. AXFR and CAA
// were added as vectors (POST_V01 Ranks 12 and 16) without being added here.
var summaryVectorOrder = []finding.Vector{
	finding.VectorCNAME, finding.VectorNS, finding.VectorSPF,
	finding.VectorMX, finding.VectorDKIM, finding.VectorDMARC,
	finding.VectorAXFR, finding.VectorCAA, finding.VectorTLSA,
	finding.VectorMTASTS, finding.VectorBIMI, finding.VectorDNSSEC,
	finding.VectorTLSRPT,
}

// write renders the summary to w. With no findings it prints the bare count line
// (preserving the prior behaviour). With findings it adds a tier breakdown and a
// vector breakdown, each listing only the categories that actually occurred so a
// scan that exercised a subset of vectors stays uncluttered.
func (s *scanSummary) write(w io.Writer) {
	fmt.Fprintf(w, "graverobber: %d finding(s)\n", s.total)
	if s.total == 0 {
		return
	}
	if tiers := summaryParts(summaryTierOrder, func(c finding.Confidence) (string, int) {
		return string(c), s.byTier[c]
	}); tiers != "" {
		fmt.Fprintf(w, "  by tier:   %s\n", tiers)
	}
	if vectors := summaryParts(summaryVectorOrder, func(v finding.Vector) (string, int) {
		return string(v), s.byVector[v]
	}); vectors != "" {
		fmt.Fprintf(w, "  by vector: %s\n", vectors)
	}
}

// summaryParts joins the non-zero "label=count" pairs for keys, in the given
// order, into a "  " separated string. It is generic over the key type so tier
// and vector breakdowns share one renderer.
func summaryParts[K comparable](keys []K, get func(K) (string, int)) string {
	var parts []string
	for _, k := range keys {
		if label, n := get(k); n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", label, n))
		}
	}
	return strings.Join(parts, "  ")
}

// loadDB assembles the fingerprint database: the on-disk cache when available
// (or the embedded snapshot as a fallback), with any --fingerprints files
// merged on top (local entries win).
func loadDB(_ context.Context, f *cliFlags) (*fingerprints.DB, error) {
	var db *fingerprints.DB

	if path, err := fingerprints.CachePath(); err == nil {
		if cached, err := fingerprints.LoadFile(path); err == nil {
			db = cached
		}
	}
	if db == nil {
		// No cache. Fall back to the compiled-in snapshot. In online mode the
		// user is nudged to run `graverobber update` for full coverage.
		emb, err := fingerprints.Embedded()
		if err != nil {
			return nil, fmt.Errorf("load fingerprints: %w", err)
		}
		db = emb
		if !f.offline && !f.silent {
			fmt.Fprintln(os.Stderr,
				"graverobber: no fingerprint cache; using embedded snapshot — run `graverobber update`")
		}
	}

	for _, path := range f.fingerprints {
		extra, err := fingerprints.LoadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load --fingerprints %s: %w", path, err)
		}
		db.Merge(extra)
	}
	return db, nil
}

// loadResolvers reads a newline-delimited resolver file. An empty path yields a
// nil slice, meaning "use defaults".
func loadResolvers(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open resolvers %s: %w", path, err)
	}
	defer file.Close()

	var resolvers []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		if line := normalizeLine(sc.Text()); line != "" {
			resolvers = append(resolvers, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read resolvers %s: %w", path, err)
	}
	return resolvers, nil
}

// openWriter selects the output sink and format, returning the Writer and a
// cleanup func that closes the underlying file (a no-op for stdout).
func openWriter(f *cliFlags) (output.Writer, func(), error) {
	sink := os.Stdout
	cleanup := func() {}
	if f.output != "" {
		file, err := os.Create(f.output)
		if err != nil {
			return nil, nil, fmt.Errorf("create output %s: %w", f.output, err)
		}
		sink = file
		cleanup = func() { _ = file.Close() }
	}

	if f.sarif {
		return output.NewSARIF(sink, version), cleanup, nil
	}
	if f.csv {
		return output.NewCSV(sink), cleanup, nil
	}
	if f.json {
		return output.NewJSONL(sink), cleanup, nil
	}
	// Colour only when writing to a terminal; a redirected file or pipe gets
	// plain text. os.Stdout to a non-file output keeps colour.
	colour := f.output == ""
	return output.NewTerminal(sink, colour), cleanup, nil
}

// targetChan produces the stream of targets feeding the scanner. Exactly one
// source is used, in precedence order: -t, then -l, then stdin. The returned
// error channel carries at most one value once the source is fully consumed.
func targetChan(ctx context.Context, f *cliFlags) (<-chan string, <-chan error) {
	out := make(chan string)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		emit := func(line string) bool {
			line = normalizeLine(line)
			if line == "" {
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case out <- line:
				return true
			}
		}

		switch {
		case f.target != "":
			emit(f.target)
		case f.list != "":
			file, err := os.Open(f.list)
			if err != nil {
				errc <- fmt.Errorf("open list %s: %w", f.list, err)
				return
			}
			defer file.Close()
			if err := scanLines(file, emit); err != nil {
				errc <- fmt.Errorf("read list %s: %w", f.list, err)
			}
		default:
			if err := scanLines(os.Stdin, emit); err != nil {
				errc <- fmt.Errorf("read stdin: %w", err)
			}
		}
	}()

	return out, errc
}

// scanLines feeds each line of r to emit until emit returns false (context
// cancelled) or the reader is exhausted.
func scanLines(r io.Reader, emit func(string) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !emit(sc.Text()) {
			return nil
		}
	}
	return sc.Err()
}

// parseSelectors splits a comma-separated DKIM selector list into a normalized
// slice. An empty input yields nil, which the detector reads as "use the
// built-in DefaultDKIMSelectors". Blank entries are dropped and each selector is
// lower-cased so case-variant duplicates collapse downstream.
func parseSelectors(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if sel := strings.ToLower(strings.TrimSpace(part)); sel != "" {
			out = append(out, sel)
		}
	}
	return out
}

// boolCount returns how many of the given flags are true. It backs the mutual-
// exclusion guard for the machine output formats (--json/--sarif/--csv).
func boolCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// normalizeLine trims whitespace and drops blank lines and # comments. It
// lower-cases hosts so duplicate-cased entries collapse downstream.
func normalizeLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	return strings.ToLower(s)
}
