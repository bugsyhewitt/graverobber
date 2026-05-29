package detectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// DNSSEC detects an orphaned DS (Delegation Signer) record: a domain whose
// PARENT zone publishes a DS record — committing every DNSSEC-validating
// resolver to build an authenticated chain of trust into the domain's zone —
// while the domain's own zone publishes NO DNSKEY, so that chain cannot be
// built.
//
// How DNSSEC delegation works. When a zone is signed, its parent publishes a DS
// record (RFC 4034 §5) that is a hash of one of the child's DNSKEYs. A
// validating resolver, descending from the root, sees the DS at the parent and
// therefore REQUIRES the child to present a matching, validly-signed DNSKEY. The
// DS is what turns on validation for the child: it is the parent's signed
// assertion "this delegation is secure — verify it."
//
// The orphan. If the operator turns DNSSEC OFF at the child (removes the DNSKEY
// / stops signing) — or migrates to a new DNS provider that generates fresh keys
// — but never removes the DS record at the registrar, the parent still asserts
// "this delegation is secure" while the child can no longer prove it. The chain
// of trust is broken at the last link. The consequence is severe and
// internet-wide:
//
//   - Every DNSSEC-validating resolver returns SERVFAIL for the ENTIRE zone, not
//     just one record. Validation is all-or-nothing: a broken chain fails closed.
//   - DNSSEC validation is the default at Google Public DNS (8.8.8.8), Cloudflare
//     (1.1.1.1), Quad9 (9.9.9.9) and a large and growing share of ISP resolvers,
//     so the domain and all of its services — web, mail, APIs — go dark for a
//     substantial fraction of the internet's users while resolving normally for
//     everyone on a non-validating resolver, which makes it maddening to diagnose.
//
// This is a self-inflicted denial of service and one of the most common
// production DNSSEC outages (it has taken down government and enterprise domains
// for hours). It is purely DNS-detectable: a DS at the parent with no DNSKEY at
// the child is unambiguous. Unlike the takeover vectors, the orphaned DS is not
// directly attacker-claimable — its harm is availability, not interception — but
// it is exactly the dangling-delegation family graverobber specialises in,
// applied to the DNSSEC chain-of-trust plane, and it is a finding an operator
// urgently needs to see.
//
// The finding is keyed on the target, classified Potential (a DNS-only signal,
// consistent with the other DNS-only vectors), and carries the orphaned DS key
// tags in DSKeyTags so the operator knows exactly which registrar records to
// remove.
//
// Algorithm:
//  1. Query DS for the target (answered by the parent zone). No DS → the
//     delegation is unsigned (insecure), the common default, nothing to orphan;
//     return no findings.
//  2. Query DNSKEY for the target (answered by the child zone). If the child
//     publishes a DNSKEY the delegation is signed and healthy → no finding.
//     (graverobber does not verify the DS hashes a specific key; the presence of
//     ANY key is the low-noise, low-false-positive signal that the zone is signed
//     — a DS/DNSKEY key-tag mismatch is a far rarer, separately-classifiable
//     case that this vector deliberately does not chase.)
//  3. DS present + no DNSKEY → orphaned DS. Emit a Potential finding carrying the
//     parent's DS key tags. A SERVFAIL on the DNSKEY query (which a validating
//     resolver returns precisely because the chain is already broken) is treated
//     as confirmation of the break, not as an indeterminate error.
func DNSSEC(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	target = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
	if target == "" {
		return nil, nil
	}

	// 1. Is there a DS at the parent? No DS → insecure delegation, nothing to
	//    orphan. A lookup error is indeterminate → emit nothing.
	tags, err := r.DSKeyTags(ctx, target)
	if err != nil || len(tags) == 0 {
		return nil, nil
	}

	// 2/3. Does the child publish a DNSKEY?
	hasKey, keyErr := r.HasDNSKEY(ctx, target)
	switch {
	case keyErr == nil && hasKey:
		// Signed delegation with a key present — healthy, the normal secure case.
		return nil, nil
	case keyErr == nil && !hasKey:
		// DS at the parent, no DNSKEY at the child: the orphan. Fall through.
	case errors.Is(keyErr, resolver.ErrZoneDeleted):
		// A validating resolver returned SERVFAIL for the DNSKEY query because the
		// chain is already broken — this is the orphan presenting itself. Fall
		// through and emit the finding.
	default:
		// Indeterminate (transport failure, unexpected rcode) — emit nothing
		// rather than risk a false positive.
		return nil, nil
	}

	// Stable, deduplicated key-tag evidence so output is deterministic.
	tags = dedupSortedKeyTags(tags)

	return []finding.Finding{{
		Subdomain:  target,
		Vector:     finding.VectorDNSSEC,
		Confidence: finding.Potential,
		DSKeyTags:  tags,
		Evidence: fmt.Sprintf(
			"parent zone publishes DS record(s) (key tag(s) %s) but %s has no DNSKEY — "+
				"orphaned DS: DNSSEC-validating resolvers (Google, Cloudflare, Quad9, most ISPs) "+
				"return SERVFAIL for the whole zone (self-inflicted outage; remove the DS at the "+
				"registrar or re-sign the zone)",
			joinKeyTags(tags), target),
	}}, nil
}

// dedupSortedKeyTags returns the distinct key tags in ascending order so the
// finding is stable across runs regardless of DNS answer ordering.
func dedupSortedKeyTags(tags []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(tags))
	out := make([]uint16, 0, len(tags))
	for _, t := range tags {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// joinKeyTags renders key tags as a comma-separated decimal list for evidence.
func joinKeyTags(tags []uint16) string {
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = fmt.Sprintf("%d", t)
	}
	return strings.Join(parts, ", ")
}
