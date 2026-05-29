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
		return f.SPFInclude
	case finding.VectorNS:
		return strings.Join(f.Nameservers, " ")
	case finding.VectorMX:
		return strings.Join(f.MXHosts, " ")
	case finding.VectorDKIM:
		if f.DKIMSelector != "" {
			return fmt.Sprintf("%s._domainkey -> %s", f.DKIMSelector, f.CNAME)
		}
		return f.CNAME
	case finding.VectorDMARC:
		return f.DMARCURI
	case finding.VectorAXFR:
		// The leaking nameserver is the actionable target; Service holds it.
		return f.Service
	default:
		return ""
	}
}

// compile-time interface check.
var _ Writer = (*CSVWriter)(nil)
