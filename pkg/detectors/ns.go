package detectors

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/nsproviders"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// knownDNSProviders is the compiled-in suffix list used to decide whether a
// deleted hosted zone is re-claimable. It is derived from the nsproviders
// default snapshot (itself sourced from indianajson/can-i-take-over-dns) and is
// the offline fallback. At runtime the NS detector prefers the locally-cached
// list refreshed by `graverobber update --ns-providers`; this slice is the
// last-resort default and the basis for matchNSProvider's pure-logic tests.
var knownDNSProviders = nsproviders.Default().VulnerableSuffixes()

// providerList holds the active provider list. It is loaded lazily from the
// on-disk cache (falling back to the compiled-in default) on first use so that
// a fresh `update --ns-providers` is picked up without restructuring the
// detector's call signature.
var (
	providerMu   sync.Mutex
	providerList *nsproviders.List
)

// activeProviders returns the provider list the detector should match against,
// loading it once from cache-or-default. SetProviders overrides it (used by the
// CLI/embedders and tests).
func activeProviders() *nsproviders.List {
	providerMu.Lock()
	defer providerMu.Unlock()
	if providerList == nil {
		providerList = nsproviders.LoadCachedOrDefault()
	}
	return providerList
}

// SetProviders overrides the active DNS-provider list used by the NS detector.
// Embedders that manage their own provider source call this; passing nil resets
// to the lazily-loaded cache-or-default.
func SetProviders(l *nsproviders.List) {
	providerMu.Lock()
	defer providerMu.Unlock()
	providerList = l
}

// NS detects subdomain takeover via a deleted DNS hosted zone.
//
// Algorithm (handoff "Detection vectors / 2. NS takeover detection"):
//  1. Resolve the target's NS records (resolver.NS).
//  2. Query each nameserver directly for the zone SOA
//     (resolver.AuthoritativeSOA).
//  3. If every nameserver answers SERVFAIL/REFUSED, the hosted zone is gone.
//  4. If the NS hostnames belong to a known cloud DNS provider
//     (knownDNSProviders), the zone is re-claimable — emit Confirmed; if the
//     provider is unknown, emit Potential.
func NS(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	nameservers, err := r.NS(ctx, target)
	if err != nil || len(nameservers) == 0 {
		return nil, nil
	}

	// Query each nameserver directly for the zone SOA.
	allDeleted := true
	for _, ns := range nameservers {
		soaErr := r.AuthoritativeSOA(ctx, target, ns)
		if !errors.Is(soaErr, resolver.ErrZoneDeleted) {
			// At least one NS is authoritative — zone is live.
			allDeleted = false
			break
		}
	}
	if !allDeleted {
		return nil, nil
	}

	// All nameservers indicate the zone is deleted. Determine confidence based
	// on whether the provider is known to allow zone re-creation. The active
	// list is the cached indianajson data when present, else the compiled-in
	// default.
	provider := activeProviders().Match(strings.Join(nameservers, " "))
	if provider == "" {
		// Defensive: match each nameserver individually in case a joined match
		// behaves differently. (Match already scans substrings, so this rarely
		// adds anything, but keeps the per-host semantics explicit.)
		for _, ns := range nameservers {
			if p := activeProviders().Match(ns); p != "" {
				provider = p
				break
			}
		}
	}
	conf := finding.Potential
	if provider != "" {
		conf = finding.Confirmed
	}

	return []finding.Finding{{
		Subdomain:   target,
		Vector:      finding.VectorNS,
		Service:     provider,
		Confidence:  conf,
		Nameservers: nameservers,
		Evidence:    "all nameservers returned SERVFAIL/REFUSED for zone SOA",
	}}, nil
}

// matchNSProvider returns the first knownDNSProvider suffix that any of the
// nameservers matches, or "" if none match.
func matchNSProvider(nameservers []string) string {
	for _, ns := range nameservers {
		ns = strings.ToLower(ns)
		for _, suffix := range knownDNSProviders {
			if strings.HasSuffix(ns, suffix) || strings.Contains(ns, suffix) {
				return suffix
			}
		}
	}
	return ""
}
