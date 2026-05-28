// Package nsproviders maintains the list of DNS providers whose hosted zones
// can be re-created by an attacker after deletion — the signal the NS takeover
// detector uses to decide between a CONFIRMED and a POTENTIAL finding.
//
// The canonical community source is
// github.com/indianajson/can-i-take-over-dns, which documents, per provider,
// whether a deleted hosted zone can be re-claimed. That repository publishes
// its data as a Markdown table in its README, so this package fetches the
// README, parses the table, caches the result as JSON at
// ~/.config/graverobber/ns_providers.json, and falls back to a compiled-in
// snapshot when the cache is absent.
//
// The list is intentionally small and changes slowly (a provider is added when
// it is confirmed to allow zone re-creation, e.g. Google Cloud DNS in 2023, or
// removed when a provider patches the behaviour). A stale list produces both
// false negatives (a known-vulnerable provider scored POTENTIAL instead of
// CONFIRMED) and false positives, which is why an explicit refresh path exists.
package nsproviders

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Provider describes a single DNS provider entry: the nameserver-hostname
// suffix used to match a target's NS records, a human label, and whether the
// provider is currently believed to allow hosted-zone re-creation.
type Provider struct {
	// Suffix is the nameserver-hostname fragment matched against a target's NS
	// records (suffix or substring match), e.g. "awsdns" or "azure-dns.com".
	Suffix string `json:"suffix"`
	// Label is the human-readable provider name, e.g. "AWS Route 53".
	Label string `json:"label"`
	// Vulnerable reports whether a deleted hosted zone at this provider can be
	// re-created by an attacker (and is therefore takeover-confirmable).
	Vulnerable bool `json:"vulnerable"`
}

// List is an ordered, deduplicated collection of providers with suffix-match
// helpers. The zero value is not useful; build one with Default or Load.
type List struct {
	providers []Provider
}

// Providers returns a copy of the underlying entries in deterministic order.
func (l *List) Providers() []Provider {
	out := make([]Provider, len(l.providers))
	copy(out, l.providers)
	return out
}

// Len reports the number of providers in the list.
func (l *List) Len() int { return len(l.providers) }

// VulnerableSuffixes returns the suffixes of providers marked vulnerable, in
// the same order they appear in the list. This is the exact slice the NS
// detector matches against.
func (l *List) VulnerableSuffixes() []string {
	out := make([]string, 0, len(l.providers))
	for _, p := range l.providers {
		if p.Vulnerable {
			out = append(out, p.Suffix)
		}
	}
	return out
}

// Match returns the first vulnerable-provider suffix that the nameserver
// hostname matches (suffix or substring), or "" when none match. Matching is
// case-insensitive.
func (l *List) Match(nameserver string) string {
	ns := strings.ToLower(nameserver)
	for _, p := range l.providers {
		if !p.Vulnerable {
			continue
		}
		s := strings.ToLower(p.Suffix)
		if s == "" {
			continue
		}
		if strings.HasSuffix(ns, s) || strings.Contains(ns, s) {
			return p.Suffix
		}
	}
	return ""
}

// newList builds a List from raw providers, deduplicating by lower-cased suffix
// (last write wins) and sorting deterministically by suffix.
func newList(providers []Provider) *List {
	byKey := make(map[string]Provider, len(providers))
	for _, p := range providers {
		p.Suffix = strings.TrimSpace(p.Suffix)
		if p.Suffix == "" {
			continue
		}
		byKey[strings.ToLower(p.Suffix)] = p
	}
	out := make([]Provider, 0, len(byKey))
	for _, p := range byKey {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Suffix) < strings.ToLower(out[j].Suffix)
	})
	return &List{providers: out}
}

// Default returns the compiled-in provider snapshot. It is the offline fallback
// used when no cache is present and the source-of-truth for the NS detector's
// historical hardcoded list.
func Default() *List {
	return newList(defaultProviders)
}

// Load parses a JSON provider list (the on-disk cache format: a JSON array of
// Provider objects) and returns a List. An empty or whitespace-only payload, or
// one that parses to zero usable entries, is treated as an error so a corrupt
// cache never silently disables NS confidence scoring.
func Load(data []byte) (*List, error) {
	var raw []Provider
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ns providers: %w", err)
	}
	l := newList(raw)
	if l.Len() == 0 {
		return nil, fmt.Errorf("parse ns providers: no usable entries")
	}
	return l, nil
}

// LoadFile reads and parses a provider cache file.
func LoadFile(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Marshal serialises the list to the JSON cache format (a pretty-printed array
// of Provider objects).
func (l *List) Marshal() ([]byte, error) {
	return json.MarshalIndent(l.providers, "", "  ")
}

// CachePath returns the on-disk cache location,
// ~/.config/graverobber/ns_providers.json (XDG-aware via os.UserConfigDir),
// mirroring the fingerprint cache convention.
func CachePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "graverobber", "ns_providers.json"), nil
}

// LoadCachedOrDefault returns the cached provider list when a valid cache
// exists, otherwise the compiled-in default. It never returns an error: a
// missing or corrupt cache degrades silently to the default so the NS detector
// always has a usable list.
func LoadCachedOrDefault() *List {
	if path, err := CachePath(); err == nil {
		if cached, err := LoadFile(path); err == nil {
			return cached
		}
	}
	return Default()
}
