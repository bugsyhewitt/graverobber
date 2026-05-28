package nsproviders

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// UpstreamURL is the canonical community source for DNS-provider takeover
// status: the README of indianajson/can-i-take-over-dns. The data lives in a
// Markdown table rather than a structured artifact, so Update parses it (see
// ParseREADME). If the maintainer ever publishes a providers.json artifact,
// only this constant and the body parser need to change.
const UpstreamURL = "https://raw.githubusercontent.com/indianajson/can-i-take-over-dns/main/README.md"

// maxREADMEBytes caps the upstream download to a sane size.
const maxREADMEBytes = 4 << 20 // 4 MiB

// UpdateResult summarizes a completed `graverobber update --ns-providers`.
type UpdateResult struct {
	Path       string
	Total      int // total providers parsed
	Vulnerable int // of which marked vulnerable
	Added      int // vulnerable suffixes new vs. previous cache
	Removed    int // vulnerable suffixes dropped vs. previous cache
}

// Update fetches the indianajson README, parses the DNS-provider table,
// atomically writes the cache at CachePath, and returns a diff of the
// vulnerable-suffix set against whatever was previously cached (or, on first
// run, against the compiled-in default).
func Update(ctx context.Context) (*UpdateResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UpstreamURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch upstream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch upstream: unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxREADMEBytes))
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}

	fresh, err := ParseREADME(body)
	if err != nil {
		return nil, err
	}

	path, err := CachePath()
	if err != nil {
		return nil, err
	}

	prev := Default()
	if old, err := LoadFile(path); err == nil {
		prev = old
	}
	added, removed := diffVulnerable(prev, fresh)

	out, err := fresh.Marshal()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("install cache: %w", err)
	}

	return &UpdateResult{
		Path:       path,
		Total:      fresh.Len(),
		Vulnerable: len(fresh.VulnerableSuffixes()),
		Added:      added,
		Removed:    removed,
	}, nil
}

// diffVulnerable reports how the set of vulnerable suffixes changed from prev to
// fresh.
func diffVulnerable(prev, fresh *List) (added, removed int) {
	prevSet := make(map[string]bool)
	for _, s := range prev.VulnerableSuffixes() {
		prevSet[strings.ToLower(s)] = true
	}
	freshSet := make(map[string]bool)
	for _, s := range fresh.VulnerableSuffixes() {
		freshSet[strings.ToLower(s)] = true
	}
	for s := range freshSet {
		if !prevSet[s] {
			added++
		}
	}
	for s := range prevSet {
		if !freshSet[s] {
			removed++
		}
	}
	return added, removed
}

// labelRe extracts the provider label from a leading Markdown link
// `[Label](url)` or a bare cell value.
var labelRe = regexp.MustCompile(`^\[([^\]]+)\]`)

// hostTokenRe matches nameserver-hostname-shaped tokens inside a fingerprint
// cell. Allows the `*` wildcard the upstream uses to abbreviate numeric/region
// segments (e.g. ns-****.awsdns-**.org).
var hostTokenRe = regexp.MustCompile(`[A-Za-z0-9*][A-Za-z0-9.*\-]*\.[A-Za-z]{2,}`)

// ParseREADME parses the indianajson README Markdown and returns the provider
// list derived from the "DNS Providers" table. Providers whose status begins
// with "Vulnerable" are marked Vulnerable; everything else (Not Vulnerable,
// Edge Case, Registration Closed) is recorded but not vulnerable.
//
// Only the public "DNS Providers" section is parsed; the "Private DNS" section
// lists non-public nameservers that are never takeover-able and is skipped.
func ParseREADME(data []byte) (*List, error) {
	text := string(data)
	lines := strings.Split(text, "\n")

	var providers []Provider
	inProviders := false
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		// Section tracking: enter on the DNS Providers heading, leave on the
		// next ## heading (e.g. "## Private DNS").
		if strings.HasPrefix(trimmed, "## ") {
			inProviders = strings.Contains(strings.ToLower(trimmed), "dns providers")
			continue
		}
		if !inProviders {
			continue
		}

		// A data row has at least three pipe-separated cells and is not the
		// header/separator row.
		if !strings.Contains(line, "|") {
			continue
		}
		cells := splitCells(line)
		if len(cells) < 3 {
			continue
		}
		labelCell := strings.TrimSpace(cells[0])
		statusCell := strings.TrimSpace(cells[1])
		fpCell := strings.TrimSpace(cells[2])

		// Skip header ("Provider | Status | ...") and separator ("---|---")
		// rows.
		if strings.EqualFold(labelCell, "Provider") || strings.HasPrefix(labelCell, "---") {
			continue
		}

		label := parseLabel(labelCell)
		if label == "" {
			continue
		}
		vulnerable := isVulnerableStatus(statusCell)

		for _, suffix := range extractSuffixes(fpCell) {
			providers = append(providers, Provider{
				Suffix:     suffix,
				Label:      label,
				Vulnerable: vulnerable,
			})
		}
	}

	l := newList(providers)
	if l.Len() == 0 {
		return nil, fmt.Errorf("parse README: no providers found (upstream format changed?)")
	}
	return l, nil
}

// splitCells splits a Markdown table row on unescaped pipes, trimming a leading
// and trailing pipe if present.
func splitCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	return strings.Split(line, "|")
}

// parseLabel pulls the human label out of a Markdown-link cell, falling back to
// the raw cell text with markup stripped.
func parseLabel(cell string) string {
	if m := labelRe.FindStringSubmatch(cell); m != nil {
		return strings.TrimSpace(m[1])
	}
	cell = strings.ReplaceAll(cell, "*", "")
	return strings.TrimSpace(cell)
}

// isVulnerableStatus reports whether a status cell denotes a takeover-able
// provider. The upstream marks these as "**Vulnerable**" (sometimes with a
// parenthetical like "(w/ purchase)"). "Edge Case", "Not Vulnerable", and
// "Registration Closed" are all treated as not-confirmable.
func isVulnerableStatus(cell string) bool {
	// Strip markdown emphasis and any <sub>/<sup> annotations.
	s := stripMarkup(cell)
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "not vulnerable") {
		return false
	}
	return strings.HasPrefix(s, "vulnerable")
}

// extractSuffixes derives matchable nameserver suffixes from a fingerprint
// cell. The cell holds one or more nameserver patterns separated by <br>; for
// each, the wildcard markers are removed and the result reduced to its
// registrable-domain-style suffix (the last meaningful label group), which is
// what the NS detector matches against a target's actual nameservers.
func extractSuffixes(cell string) []string {
	cell = strings.ReplaceAll(cell, "<br>", " ")
	cell = strings.ReplaceAll(cell, "<BR>", " ")
	// Drop backslash escapes the upstream uses around '*'.
	cell = strings.ReplaceAll(cell, `\`, "")

	seen := make(map[string]bool)
	var out []string
	for _, tok := range hostTokenRe.FindAllString(cell, -1) {
		suffix := suffixFromHost(tok)
		if suffix == "" || seen[suffix] {
			continue
		}
		seen[suffix] = true
		out = append(out, suffix)
	}
	return out
}

// suffixFromHost reduces a (possibly wildcarded) nameserver hostname to the
// distinctive suffix the detector matches. It strips wildcards, then keeps the
// last three labels for known multi-part TLDs (e.g. co.uk) or the last two
// otherwise — enough to be provider-distinctive without over-matching.
func suffixFromHost(host string) string {
	host = strings.ToLower(strings.Trim(host, ".-"))
	// Remove wildcard segments entirely; "ns-****.awsdns-**.org" -> labels
	// ["ns-", "awsdns-", "org"] after stripping '*'.
	host = strings.ReplaceAll(host, "*", "")
	labels := strings.Split(host, ".")
	// Clean empty/garbage labels produced by wildcard removal.
	cleaned := labels[:0]
	for _, l := range labels {
		l = strings.Trim(l, "-")
		if l != "" {
			cleaned = append(cleaned, l)
		}
	}
	if len(cleaned) < 2 {
		return ""
	}

	n := 2
	// Two-letter final label after a short label suggests a ccTLD second level
	// (co.uk, com.au); keep three labels.
	last := cleaned[len(cleaned)-1]
	secondLast := cleaned[len(cleaned)-2]
	if len(last) == 2 && len(secondLast) <= 3 && len(cleaned) >= 3 {
		n = 3
	}
	if n > len(cleaned) {
		n = len(cleaned)
	}
	return strings.Join(cleaned[len(cleaned)-n:], ".")
}

// stripMarkup removes Markdown emphasis markers and inline HTML tags from a
// cell so status comparisons see plain text.
var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripMarkup(s string) string {
	s = tagRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "*", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}
