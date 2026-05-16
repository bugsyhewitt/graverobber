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
		if f.SPFInclude != "" {
			detail = fmt.Sprintf("spf include:%s", f.SPFInclude)
		}
	case finding.VectorNS:
		if len(f.Nameservers) > 0 {
			detail = fmt.Sprintf("ns %v", f.Nameservers)
		}
	}

	_, err := fmt.Fprintf(t.w, "[%s] [%s] %s  %s\n",
		tier, t.paint(colGray, string(f.Vector)), host, detail)
	return err
}

// Close is a no-op; the underlying io.Writer is owned by the caller.
func (t *TerminalWriter) Close() error { return nil }

// compile-time interface checks.
var (
	_ Writer = (*JSONLWriter)(nil)
	_ Writer = (*TerminalWriter)(nil)
)
