package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// CSV is the spreadsheet-native output format. Security teams triage takeover
// candidates in spreadsheets, ticketing imports, and BI dashboards far more
// often than they parse JSONL by hand; a flat CSV with one row per finding
// drops straight into Excel/Sheets, Jira CSV import, and `csvkit` pipelines
// without a jq step. Unlike SARIF (a single nested document for Code Scanning)
// and JSONL (a stream for programmatic consumers), CSV targets the human-
// spreadsheet triage workflow.
//
// The schema is intentionally flat and stable: every vector maps onto the same
// columns, and the vector-specific datum (the dangling target) is normalised
// into a single `target` column so a reviewer can sort/filter the whole sheet
// uniformly regardless of which vector produced each row.

// csvHeader is the fixed column order. It is written exactly once, on the first
// Write (or on Close if no findings were produced), so an empty scan still
// yields a valid header-only CSV that downstream importers accept.
var csvHeader = []string{
	"timestamp",
	"subdomain",
	"vector",
	"confidence",
	"service",
	"target",
	"scheme",
	"fingerprint",
	"evidence",
}

// CSVWriter emits RFC 4180 CSV: a header row followed by one row per finding.
// It is safe for the scanner's concurrent Write calls.
type CSVWriter struct {
	mu          sync.Mutex
	w           *csv.Writer
	wroteHeader bool
}

// NewCSV returns a CSVWriter writing to w.
func NewCSV(w io.Writer) *CSVWriter {
	return &CSVWriter{w: csv.NewWriter(w)}
}

// writeHeaderLocked emits the header row once. The caller must hold s.mu.
func (c *CSVWriter) writeHeaderLocked() error {
	if c.wroteHeader {
		return nil
	}
	c.wroteHeader = true
	return c.w.Write(csvHeader)
}

// Write renders f as a single CSV row, emitting the header first if needed.
func (c *CSVWriter) Write(f finding.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.writeHeaderLocked(); err != nil {
		return err
	}
	return c.w.Write([]string{
		f.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		f.Subdomain,
		string(f.Vector),
		string(f.Confidence),
		f.Service,
		csvTarget(f),
		f.Scheme,
		f.Fingerprint,
		f.Evidence,
	})
}

// Close emits a header-only file when no findings were written, then flushes the
// buffered csv.Writer and surfaces any deferred write error.
func (c *CSVWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.writeHeaderLocked(); err != nil {
		return err
	}
	c.w.Flush()
	return c.w.Error()
}

// csvTarget collapses each vector's identifying datum (the dangling target an
// attacker would claim) into the single `target` column, so the flat sheet
// reads uniformly across vectors. Multi-valued vectors (NS, MX) join their
// hosts with a space; the encoding/csv quoting keeps the cell intact.
func csvTarget(f finding.Finding) string {
	switch f.Vector {
	case finding.VectorCNAME:
		return f.CNAME
	case finding.VectorSPF:
		if f.SPFInclude != "" {
			return f.SPFInclude
		}
		// Permissive sub-case has no remote target; the offending mechanism token
		// is the actionable datum (the subdomain column names the spoofable domain).
		if f.SPFAll != "" {
			return f.SPFAll + " (permissive)"
		}
		// Lookup-limit sub-case has no remote target either; the offending count
		// is the actionable datum.
		if f.SPFLookups > 0 {
			return fmt.Sprintf("%d DNS lookups (permerror)", f.SPFLookups)
		}
		// Deprecated-ptr sub-case has no remote target; the offending mechanism
		// token (e.g. "+ptr" or "ptr:example.com") is the actionable datum.
		if f.SPFPtr != "" {
			return f.SPFPtr + " (deprecated)"
		}
		return ""
	case finding.VectorNS:
		return strings.Join(f.Nameservers, " ")
	case finding.VectorMX:
		return strings.Join(f.MXHosts, " ")
	case finding.VectorDKIM:
		if f.DKIMKeyBits > 0 {
			return fmt.Sprintf("%s._domainkey (%d-bit RSA key)", f.DKIMSelector, f.DKIMKeyBits)
		}
		if f.DKIMStaleYear > 0 {
			return fmt.Sprintf("%s._domainkey (stale year %d)", f.DKIMSelector, f.DKIMStaleYear)
		}
		if f.DKIMSelector != "" {
			return fmt.Sprintf("%s._domainkey -> %s", f.DKIMSelector, f.CNAME)
		}
		return f.CNAME
	case finding.VectorDMARC:
		if f.DMARCPolicy != "" {
			return fmt.Sprintf("policy p=%s (monitor-only)", f.DMARCPolicy)
		}
		if f.DMARCSubdomainPolicy != "" {
			return fmt.Sprintf("sp=%s (subdomains spoofable)", f.DMARCSubdomainPolicy)
		}
		return f.DMARCURI
	case finding.VectorAXFR:
		// The leaking nameserver is the actionable target; Service holds it.
		return f.Service
	case finding.VectorCAA:
		if f.CAAIssuer != "" {
			return f.CAAIssuer
		}
		// The permissive sub-case has no remote target; the misconfigured
		// domain itself (the subdomain column) is the actionable item.
		return "* (any CA)"
	case finding.VectorTLSA:
		// The dangling DANE pin's owner name plus the gone mail host it covers
		// are the actionable target. The HTTPS validation sub-case has no MX
		// host; its Scheme field is "https".
		switch {
		case len(f.MXHosts) > 0:
			return fmt.Sprintf("%s -> %s (NXDOMAIN)", f.TLSAName, f.MXHosts[0])
		case f.Scheme == "https":
			return fmt.Sprintf("%s (cert mismatch)", f.TLSAName)
		default:
			return f.TLSAName
		}
	case finding.VectorMTASTS:
		// Sub-case 2 (weak mode): the policy host is up but the mode is not enforce.
		if f.MTASTSMode != "" {
			return fmt.Sprintf("%s (mode: %s)", f.Service, f.MTASTSMode)
		}
		// Sub-case 1 (dangling host): the policy host is NXDOMAIN.
		if f.CNAME != "" && f.CNAME != f.Service {
			return fmt.Sprintf("%s -> %s (NXDOMAIN)", f.Service, f.CNAME)
		}
		return fmt.Sprintf("%s (NXDOMAIN)", f.Service)
	case finding.VectorBIMI:
		// The dangling BIMI asset host (logo/VMC URL host) is the actionable
		// target the attacker would reclaim.
		return fmt.Sprintf("%s (NXDOMAIN)", f.BIMIURIHost)
	case finding.VectorDNSSEC:
		if len(f.DNSSECWeakAlgs) > 0 {
			// The weak-algorithm sub-case names the deprecated DNSSEC algorithm(s)
			// (RFC 8624) so an operator can plan the key rollover.
			return fmt.Sprintf("weak DNSSEC algorithm(s) %s (RFC 8624 deprecated)", strings.Join(f.DNSSECWeakAlgs, ", "))
		}
		// The orphaned DS key tags name exactly which registrar records must be
		// removed (or matched by re-signing) to repair the broken chain.
		return fmt.Sprintf("orphaned DS %s (no child DNSKEY)", formatKeyTags(f.DSKeyTags))
	case finding.VectorTLSRPT:
		// The dangling TLSRPT report host (mailto domain or https collector) is the
		// actionable target the attacker would reclaim to intercept TLS reports.
		return fmt.Sprintf("%s (NXDOMAIN)", f.TLSRPTURIHost)
	case finding.VectorAutodiscover:
		// The dangling autoconfiguration host and the claimable target it points at
		// are the actionable datum the attacker would reclaim.
		if f.CNAME != "" && f.CNAME != f.Service {
			return fmt.Sprintf("%s -> %s (NXDOMAIN)", f.Service, f.CNAME)
		}
		return fmt.Sprintf("%s (NXDOMAIN)", f.Service)
	default:
		return ""
	}
}

// compile-time interface check.
var _ Writer = (*CSVWriter)(nil)
