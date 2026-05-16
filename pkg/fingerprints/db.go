// Package fingerprints loads, merges, caches, and queries the service
// fingerprint database that drives CNAME takeover detection.
//
// The canonical schema follows EdOverflow/can-i-take-over-xyz's
// fingerprints.json. Upstream entries may carry additional fields beyond those
// modeled here; encoding/json discards unknown fields, which is intentional and
// keeps graverobber forward-compatible with upstream schema additions.
package fingerprints

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// seed is a small bundled snapshot, embedded at compile time. It is the
// last-resort source used only when the on-disk cache is missing AND the scan
// is running with --offline. Real coverage comes from `graverobber update`,
// which writes the cache from the upstream source.
//
// NOTE: Go's //go:embed cannot reference files outside the importing package's
// directory, so the snapshot lives here as seed.json rather than at repo root
// as the handoff layout sketch shows.
//
//go:embed seed.json
var seed []byte

// Fingerprint is a single service signature.
type Fingerprint struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	NXDomain    bool     `json:"nxdomain"`
	Status      string   `json:"status"`
	Discussion  string   `json:"discussion"`
}

// DB is an in-memory fingerprint database.
type DB struct {
	entries []Fingerprint
}

// Load parses a fingerprints.json byte slice into a DB.
func Load(data []byte) (*DB, error) {
	var entries []Fingerprint
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse fingerprints: %w", err)
	}
	return &DB{entries: entries}, nil
}

// LoadFile reads and parses a fingerprints.json file from disk.
func LoadFile(path string) (*DB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Load(data)
}

// Embedded returns the DB built from the compile-time bundled snapshot.
func Embedded() (*DB, error) {
	return Load(seed)
}

// Merge overlays other on top of the receiver. Entries from other replace
// receiver entries that share the same Service name; new services are
// appended. This implements the --fingerprints private-list feature: a
// hunter's local entries win over the upstream database.
func (db *DB) Merge(other *DB) {
	if other == nil {
		return
	}
	byService := make(map[string]int, len(db.entries))
	for i, e := range db.entries {
		byService[e.Service] = i
	}
	for _, e := range other.entries {
		if i, ok := byService[e.Service]; ok {
			db.entries[i] = e
			continue
		}
		byService[e.Service] = len(db.entries)
		db.entries = append(db.entries, e)
	}
}

// Len reports the number of fingerprints in the DB.
func (db *DB) Len() int { return len(db.entries) }

// Entries returns the underlying fingerprint slice. Treat it as read-only.
func (db *DB) Entries() []Fingerprint { return db.entries }

// MatchCNAME returns every fingerprint whose cname suffix list matches the
// supplied CNAME target host. A single target may match more than one service.
func (db *DB) MatchCNAME(cname string) []Fingerprint {
	needle := normalizeHost(cname)
	var hits []Fingerprint
	for _, e := range db.entries {
		for _, suffix := range e.CNAME {
			s := normalizeHost(suffix)
			if s != "" && (needle == s || strings.HasSuffix(needle, "."+s)) {
				hits = append(hits, e)
				break
			}
		}
	}
	return hits
}

// MatchBody reports whether an HTTP response body contains fp's fingerprint
// string. An empty fingerprint string never matches a body — such services are
// detected via the NXDomain flag instead.
func (fp Fingerprint) MatchBody(body []byte) bool {
	if fp.Fingerprint == "" {
		return false
	}
	return bytes.Contains(body, []byte(fp.Fingerprint))
}

func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}
