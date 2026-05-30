package detectors

import (
	"context"
	"errors"
	"sort"
	"strconv"
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

// NS detects subdomain takeover and partial-hijack vectors caused by broken
// NS delegation. It has two sub-cases, distinguished by the Evidence string and
// by which subset of the delegated nameservers is reported in Nameservers:
//
// Zone-deleted sub-case (the strict-unanimity case). EVERY delegated nameserver
// returns SERVFAIL/REFUSED/NXDOMAIN for the zone's SOA — the hosted zone has
// been deleted at the provider and is re-claimable. If the NS hostnames belong
// to a known cloud DNS provider (knownDNSProviders / the indianajson cache) the
// finding is Confirmed (zone re-creation is documented to work at that
// provider); otherwise Potential. All delegated nameservers are listed in
// Nameservers.
//
// Partial-lame sub-case (the new sub-case shipped in R32). SOME delegated
// nameservers answer authoritatively while OTHERS report SERVFAIL/REFUSED/
// NXDOMAIN: the parent delegation lists nameservers that are not actually
// authoritative for the zone (a "lame delegation", RFC 1912 §2.8). This is a
// real DNS misconfiguration in its own right — every validating resolver that
// happens to query a lame nameserver experiences a timeout-and-retry cascade or
// outright SERVFAIL, while the same lookup from a different resolver succeeds
// (causing intermittent, hard-to-reproduce outages). It is also a partial-
// hijack precondition: if any lame nameserver's hostname belongs to a
// takeoverable cloud DNS provider, an attacker who re-creates the zone at that
// provider controls the answers returned for the fraction of resolver queries
// that hit the lame NS — without ever owning the full delegation. Confidence:
// Confirmed when at least one lame NS matches a known provider (the
// partial-hijack case), Potential otherwise. Only the lame nameservers are
// listed in Nameservers, so an operator sees exactly which delegations to
// repair at the registrar. Subject to the same opt-out (--no-ns) as the
// zone-deleted sub-case, since both share the NS delegation surface.
//
// Algorithm:
//  1. Resolve the target's NS records (resolver.NS). If none, return.
//  2. Query EVERY nameserver directly for the zone SOA
//     (resolver.AuthoritativeSOA). Partition into "live" (success) and "lame"
//     (ErrZoneDeleted). Transport errors (timeout, DNS protocol error) are
//     treated as "unknown" and excluded from BOTH partitions — neither a
//     positive break signal nor a positive liveness signal — so a network
//     hiccup against one nameserver never produces a finding on its own.
//  3. If every nameserver is lame → zone-deleted sub-case.
//  4. If some are lame and at least one is live → partial-lame sub-case.
//  5. Otherwise → no finding.
func NS(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	nameservers, err := r.NS(ctx, target)
	if err != nil || len(nameservers) == 0 {
		return nil, nil
	}

	var lame, live []string
	for _, ns := range nameservers {
		soaErr := r.AuthoritativeSOA(ctx, target, ns)
		switch {
		case errors.Is(soaErr, resolver.ErrZoneDeleted):
			lame = append(lame, ns)
		case soaErr == nil:
			live = append(live, ns)
		default:
			// Transport error (timeout, malformed response, etc.). We cannot
			// classify this nameserver either way — do NOT mark it lame
			// (would be a false positive on a UDP-dropped packet) and do NOT
			// mark it live (would mask a real partial lameness). Excluding it
			// from both partitions degrades the worst case to "no finding"
			// rather than to a wrong finding, consistent with the tool's
			// preference for false negatives over false positives.
		}
	}

	// No lame nameservers — nothing to report (the common, healthy path, and the
	// transport-error-only path).
	if len(lame) == 0 {
		return nil, nil
	}

	// Stable order for tests and reproducible output.
	sort.Strings(lame)

	// Zone-deleted sub-case: every nameserver is lame. This is the existing
	// unanimity case; report all of them.
	if len(live) == 0 {
		all := append([]string(nil), nameservers...)
		sort.Strings(all)
		provider := matchProviderInList(all)
		conf := finding.Potential
		if provider != "" {
			conf = finding.Confirmed
		}
		return []finding.Finding{{
			Subdomain:   target,
			Vector:      finding.VectorNS,
			Service:     provider,
			Confidence:  conf,
			Nameservers: all,
			Evidence:    "all nameservers returned SERVFAIL/REFUSED for zone SOA",
		}}, nil
	}

	// Partial-lame sub-case: some answer authoritatively, some do not. The
	// surfaced nameservers are the LAME ones (the ones to fix). Confidence is
	// elevated to Confirmed when at least one lame NS belongs to a known
	// takeoverable provider — that combination is the partial-hijack
	// precondition.
	provider := matchProviderInList(lame)
	conf := finding.Potential
	evidence := "partial lame delegation: " +
		strconv.Itoa(len(lame)) + " of " + strconv.Itoa(len(nameservers)) +
		" nameservers returned SERVFAIL/REFUSED for zone SOA while others answered authoritatively"
	if provider != "" {
		conf = finding.Confirmed
		evidence += " (lame nameserver matches takeoverable provider " + provider +
			" — re-creating the zone at the provider partially hijacks the delegation)"
	}
	return []finding.Finding{{
		Subdomain:   target,
		Vector:      finding.VectorNS,
		Service:     provider,
		Confidence:  conf,
		Nameservers: lame,
		Evidence:    evidence,
	}}, nil
}

// matchProviderInList returns the first known-takeoverable provider suffix that
// any nameserver in the slice matches, or "" if none match. It uses the live
// (cache-aware) provider list; matchNSProvider remains as a compiled-in-only
// helper for the pure-logic tests.
func matchProviderInList(nameservers []string) string {
	// Try a joined match first (the existing semantics — the provider list's
	// Match scans substrings of its argument).
	if p := activeProviders().Match(strings.Join(nameservers, " ")); p != "" {
		return p
	}
	// Fall back to per-host matching in case a joined-string match behaves
	// differently for a particular suffix.
	for _, ns := range nameservers {
		if p := activeProviders().Match(ns); p != "" {
			return p
		}
	}
	return ""
}

// matchNSProvider returns the first knownDNSProvider suffix that any of the
// nameservers matches, or "" if none match. It uses ONLY the compiled-in
// default list (knownDNSProviders) and is preserved for the existing
// TestNSUnanimity_MatchProvider pure-logic test; production code uses
// matchProviderInList, which is cache-aware.
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

