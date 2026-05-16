package fingerprints

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// UpstreamURL is the canonical fingerprint source: the CI-verified
// fingerprints.json from EdOverflow/can-i-take-over-xyz.
const UpstreamURL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

// maxFingerprintBytes caps the upstream download to a sane size.
const maxFingerprintBytes = 16 << 20 // 16 MiB

// CachePath returns the on-disk cache location:
// ~/.config/graverobber/fingerprints.json (XDG-aware via os.UserConfigDir).
func CachePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "graverobber", "fingerprints.json"), nil
}

// UpdateResult summarizes a completed `graverobber update`.
type UpdateResult struct {
	Path    string
	Total   int
	Added   int
	Removed int
	Changed int
}

// Update fetches the upstream fingerprint database, runs the payload through
// the supplied SignatureVerifier (see verify.go), validates the schema,
// atomically writes the cache, and returns a diff summary against whatever was
// previously cached.
//
// In v1.0 the SignatureVerifier is NoopSignatureVerifier: transport integrity
// comes from HTTPS, and the upstream source itself is unsigned. The hook exists
// so that v1.1 can introduce signed releases without touching this code path
// (see handoff open question #3). A nil sv is treated as the no-op verifier.
func Update(ctx context.Context, sv SignatureVerifier) (*UpdateResult, error) {
	if sv == nil {
		sv = NoopSignatureVerifier{}
	}

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBytes))
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}
	if err := sv.Verify(body); err != nil {
		return nil, fmt.Errorf("verify fingerprints: %w", err)
	}

	fresh, err := Load(body) // doubles as schema validation
	if err != nil {
		return nil, err
	}

	path, err := CachePath()
	if err != nil {
		return nil, err
	}

	var prev *DB
	if old, err := LoadFile(path); err == nil {
		prev = old
	}
	added, removed, changed := diff(prev, fresh)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("install cache: %w", err)
	}

	return &UpdateResult{
		Path:    path,
		Total:   fresh.Len(),
		Added:   added,
		Removed: removed,
		Changed: changed,
	}, nil
}

// diff compares a previous DB against a fresh one by Service name.
func diff(prev, fresh *DB) (added, removed, changed int) {
	if prev == nil {
		return fresh.Len(), 0, 0
	}
	old := make(map[string]Fingerprint, prev.Len())
	for _, e := range prev.entries {
		old[e.Service] = e
	}
	seen := make(map[string]bool, fresh.Len())
	for _, e := range fresh.entries {
		seen[e.Service] = true
		switch o, ok := old[e.Service]; {
		case !ok:
			added++
		case !sameFingerprint(o, e):
			changed++
		}
	}
	for s := range old {
		if !seen[s] {
			removed++
		}
	}
	return added, removed, changed
}

// sameFingerprint reports field-by-field equality (Fingerprint contains a slice
// and so is not comparable with ==).
func sameFingerprint(a, b Fingerprint) bool {
	if a.Service != b.Service || a.Fingerprint != b.Fingerprint ||
		a.NXDomain != b.NXDomain || a.Status != b.Status || a.Discussion != b.Discussion {
		return false
	}
	if len(a.CNAME) != len(b.CNAME) {
		return false
	}
	for i := range a.CNAME {
		if a.CNAME[i] != b.CNAME[i] {
			return false
		}
	}
	return true
}
