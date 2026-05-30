// Package output renders findings as either newline-delimited JSON (for
// pipelines) or coloured human-readable text (for interactive terminals).
//
// All Writer implementations are safe for concurrent use: the scanner emits
// findings from a pool of worker goroutines.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// Writer consumes findings produced by the scanner.
type Writer interface {
	Write(finding.Finding) error
	Close() error
}

// JSONLWriter emits one compact JSON object per finding, one per line.
type JSONLWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONL returns a JSONLWriter writing to w.
func NewJSONL(w io.Writer) *JSONLWriter {
	return &JSONLWriter{enc: json.NewEncoder(w)}
}

// Write serializes f as a single JSON line.
func (j *JSONLWriter) Write(f finding.Finding) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(f)
}

// Close is a no-op; the underlying io.Writer is owned by the caller.
func (j *JSONLWriter) Close() error { return nil }

// ANSI colour codes used by TerminalWriter.
const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGray   = "\033[90m"
)

// TerminalWriter emits coloured, human-readable lines.
type TerminalWriter struct {
	mu     sync.Mutex
	w      io.Writer
	colour bool
}

// NewTerminal returns a TerminalWriter. When colour is false, ANSI escapes are
// omitted — pass false for non-tty output (files, pipes).
func NewTerminal(w io.Writer, colour bool) *TerminalWriter {
	return &TerminalWriter{w: w, colour: colour}
}

func (t *TerminalWriter) paint(code, s string) string {
	if !t.colour {
		return s
	}
	return code + s + colReset
}

// confidenceColour maps a confidence tier to an ANSI colour.
func confidenceColour(c finding.Confidence) string {
	switch c {
	case finding.Confirmed:
		return colRed
	case finding.Likely:
		return colYellow
	default:
		return colGray
	}
}

// Write renders f as one coloured line.
func (t *TerminalWriter) Write(f finding.Finding) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	tier := t.paint(colBold+confidenceColour(f.Confidence), string(f.Confidence))
	host := t.paint(colCyan, f.Subdomain)

	detail := f.Service
	switch f.Vector {
	case finding.VectorCNAME:
		if f.CNAME != "" {
			detail = fmt.Sprintf("%s -> %s", f.Service, f.CNAME)
		}
	case finding.VectorSPF:
		switch {
		case f.SPFInclude != "":
			detail = fmt.Sprintf("spf include:%s", f.SPFInclude)
		case f.SPFAll != "":
			detail = fmt.Sprintf("spf %s (permissive — any host)", f.SPFAll)
		case f.SPFLookups > 0:
			detail = fmt.Sprintf("spf %d DNS lookups (>10 — permerror, SPF hard-fails)", f.SPFLookups)
		case f.SPFPtr != "":
			detail = fmt.Sprintf("spf %s (deprecated — RFC 7208 §5.5)", f.SPFPtr)
		}
	case finding.VectorNS:
		if len(f.Nameservers) > 0 {
			// Distinguish the partial-lame sub-case (some NS authoritative,
			// some lame) from the zone-deleted strict-unanimity sub-case so
			// the default terminal output is unambiguous; the Evidence string
			// is the authoritative discriminator.
			if strings.Contains(f.Evidence, "partial lame delegation") {
				detail = fmt.Sprintf("ns partial-lame %v", f.Nameservers)
			} else {
				detail = fmt.Sprintf("ns %v", f.Nameservers)
			}
		}
	case finding.VectorMX:
		if len(f.MXHosts) > 0 {
			detail = fmt.Sprintf("mx %v", f.MXHosts)
		}
	case finding.VectorDKIM:
		switch {
		case f.DKIMKeyBits > 0:
			detail = fmt.Sprintf("dkim %s._domainkey weak %d-bit RSA key", f.DKIMSelector, f.DKIMKeyBits)
		case f.DKIMSelector != "":
			detail = fmt.Sprintf("dkim %s._domainkey -> %s", f.DKIMSelector, f.CNAME)
		}
	case finding.VectorDMARC:
		switch {
		case f.DMARCPolicy != "":
			detail = fmt.Sprintf("dmarc policy p=%s (monitor-only)", f.DMARCPolicy)
		case f.DMARCURI != "":
			detail = fmt.Sprintf("dmarc rua/ruf:%s", f.DMARCURI)
		}
	case finding.VectorAXFR:
		if f.Service != "" {
			detail = fmt.Sprintf("axfr %s leaked %d host(s)", f.Service, len(f.LeakedHosts))
		}
	case finding.VectorCAA:
		if f.CAAIssuer != "" {
			detail = fmt.Sprintf("caa issuer %s NXDOMAIN (claimable)", f.CAAIssuer)
		} else {
			detail = "caa authorises any CA (permissive)"
		}
	case finding.VectorTLSA:
		if len(f.MXHosts) > 0 {
			detail = fmt.Sprintf("tlsa %s pins %s NXDOMAIN (dangling DANE pin)", f.TLSAName, f.MXHosts[0])
		} else {
			detail = fmt.Sprintf("tlsa %s dangling DANE pin", f.TLSAName)
		}
	case finding.VectorMTASTS:
		detail = fmt.Sprintf("mta-sts policy host %s NXDOMAIN (dangling -> %s)", f.Service, f.CNAME)
	case finding.VectorBIMI:
		detail = fmt.Sprintf("bimi asset host %s NXDOMAIN (dangling brand logo/VMC)", f.BIMIURIHost)
	case finding.VectorDNSSEC:
		if len(f.DNSSECWeakAlgs) > 0 {
			detail = fmt.Sprintf("dnssec weak algorithm(s) %s (RFC 8624 deprecated — forgeable chain)", strings.Join(f.DNSSECWeakAlgs, ", "))
		} else {
			detail = fmt.Sprintf("dnssec orphaned DS %s (parent DS, no child DNSKEY — SERVFAIL outage)", formatKeyTags(f.DSKeyTags))
		}
	case finding.VectorTLSRPT:
		detail = fmt.Sprintf("tlsrpt report host %s NXDOMAIN (dangling — TLS-report interception)", f.TLSRPTURIHost)
	}

	_, err := fmt.Fprintf(t.w, "[%s] [%s] %s  %s\n",
		tier, t.paint(colGray, string(f.Vector)), host, detail)
	return err
}

// Close is a no-op; the underlying io.Writer is owned by the caller.
func (t *TerminalWriter) Close() error { return nil }

// formatKeyTags renders DNSSEC DS key tags as a "key tag N" / "key tags A, B"
// phrase shared by the terminal, CSV, and SARIF renderers so the wording cannot
// drift between output formats. An empty slice yields "key tag(s) (none)".
func formatKeyTags(tags []uint16) string {
	if len(tags) == 0 {
		return "key tag(s) (none)"
	}
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = strconv.Itoa(int(t))
	}
	label := "key tag"
	if len(tags) > 1 {
		label = "key tags"
	}
	return label + " " + strings.Join(parts, ", ")
}

// compile-time interface checks.
var (
	_ Writer = (*JSONLWriter)(nil)
	_ Writer = (*TerminalWriter)(nil)
)
