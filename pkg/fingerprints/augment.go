package fingerprints

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// augmentSeed is graverobber's vendored augmentation side-file, embedded at
// compile time. It carries the graverobber-added fields — claim_adapter and an
// nxdomain override — that DO NOT exist upstream, keyed by service name. Keeping
// them in a side-file (rather than editing the synced fingerprints.json) is the
// whole point of D1: a `graverobber update` re-pulls upstream and would clobber
// any field graverobber wrote into the merged file, so the augmentations live
// here and are re-applied (ApplyAugment) on top of whatever upstream ships.
//
//go:embed augment.json
var augmentSeed []byte

// Augment is one service's graverobber-added augmentation. Service is the join
// key against the upstream fingerprint database.
type Augment struct {
	// Service matches the upstream Fingerprint.Service (case-insensitive).
	Service string `json:"service"`
	// ClaimAdapter is the pkg/confirm adapter key that can safely confirm this
	// service's takeover, e.g. "github-pages". Empty means "no adapter yet".
	ClaimAdapter string `json:"claim_adapter"`
	// NXDomain, when set non-nil, overrides the upstream nxdomain flag — used
	// where graverobber's live-signal experience disagrees with the upstream
	// classification (the DB lags reality, A5). nil means "do not override".
	NXDomain *bool `json:"nxdomain,omitempty"`
}

// AugmentSet is a service-keyed collection of augmentations.
type AugmentSet struct {
	byService map[string]Augment
}

// LoadAugment parses an augment.json byte slice into an AugmentSet. Duplicate
// service keys: last entry wins. Service keys are matched case-insensitively.
func LoadAugment(data []byte) (*AugmentSet, error) {
	var list []Augment
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse augmentations: %w", err)
	}
	set := &AugmentSet{byService: make(map[string]Augment, len(list))}
	for _, a := range list {
		set.byService[augKey(a.Service)] = a
	}
	return set, nil
}

// EmbeddedAugment returns the AugmentSet built from the compile-time side-file.
func EmbeddedAugment() (*AugmentSet, error) {
	return LoadAugment(augmentSeed)
}

// LoadAugmentFile reads and parses an augment.json file from disk.
func LoadAugmentFile(path string) (*AugmentSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return LoadAugment(data)
}

// Len reports the number of augmentation entries.
func (a *AugmentSet) Len() int {
	if a == nil {
		return 0
	}
	return len(a.byService)
}

// For returns the augmentation for a service (case-insensitive) and whether one
// exists.
func (a *AugmentSet) For(service string) (Augment, bool) {
	if a == nil {
		return Augment{}, false
	}
	aug, ok := a.byService[augKey(service)]
	return aug, ok
}

// Apply overlays the augmentation set onto a DB in place: for each DB entry that
// has a matching augmentation (by service), it sets ClaimAdapter and, when the
// augmentation carries an nxdomain override, NXDomain. Entries with no matching
// augmentation are left untouched. This is the D1 step: call it after Load /
// LoadFile / Update so the synced upstream fingerprints carry graverobber's
// claim_adapter/nxdomain additions without those additions ever being written
// into (and clobbered by the next sync of) the upstream file.
func (a *AugmentSet) Apply(db *DB) {
	if a == nil || db == nil {
		return
	}
	for i := range db.entries {
		if aug, ok := a.byService[augKey(db.entries[i].Service)]; ok {
			if aug.ClaimAdapter != "" {
				db.entries[i].ClaimAdapter = aug.ClaimAdapter
			}
			if aug.NXDomain != nil {
				db.entries[i].NXDomain = *aug.NXDomain
			}
		}
	}
}

// ApplyAugment loads the embedded augmentation side-file and applies it to db.
// It is the one-call convenience the loader path uses: db, _ := Load(...);
// ApplyAugment(db). A failure to parse the embedded side-file is returned so a
// malformed augment.json is caught in CI rather than silently dropping adapters.
func ApplyAugment(db *DB) error {
	set, err := EmbeddedAugment()
	if err != nil {
		return err
	}
	set.Apply(db)
	return nil
}

// Claimable returns the services in the DB that have a claim adapter assigned
// (i.e. that graverobber can safely confirm), as a sorted-by-service slice of
// (service, adapter) pairs. Used by `graverobber list-fingerprints` / the
// confirmer registry to report coverage.
func (db *DB) Claimable() []ServiceAdapter {
	var out []ServiceAdapter
	for _, e := range db.entries {
		if e.ClaimAdapter != "" {
			out = append(out, ServiceAdapter{Service: e.Service, Adapter: e.ClaimAdapter})
		}
	}
	return out
}

// ServiceAdapter pairs a fingerprint service with its claim adapter.
type ServiceAdapter struct {
	Service string `json:"service"`
	Adapter string `json:"claim_adapter"`
}

// augKey normalizes a service name for case-insensitive joining.
func augKey(service string) string {
	return strings.ToLower(strings.TrimSpace(service))
}
