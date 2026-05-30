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
	//    orphan and no algorithm to weigh. A lookup error is indeterminate → emit
	//    nothing.
	dsRecs, err := r.DSAlgorithms(ctx, target)
	if err != nil || len(dsRecs) == 0 {
		return nil, nil
	}

	// 2. Does the child publish a DNSKEY? The answer routes to one of the two
	//    sub-cases: no key → orphan; key(s) present → check algorithms for weak.
	childAlgs, keyErr := r.DNSKEYAlgorithms(ctx, target)
	switch {
	case keyErr == nil && len(childAlgs) > 0:
		// Signed delegation with at least one key present. Healthy as far as the
		// chain goes; now inspect both the DS records and the child DNSKEYs for
		// algorithms RFC 8624 has retired. Any hit → weak-algorithm finding.
		return weakAlgorithmFinding(target, dsRecs, childAlgs), nil
	case keyErr == nil && len(childAlgs) == 0:
		// DS at the parent, no DNSKEY at the child: the orphan. Fall through.
	case errors.Is(keyErr, resolver.ErrZoneDeleted):
		// A validating resolver returned SERVFAIL for the DNSKEY query because the
		// chain is already broken — this is the orphan presenting itself. Fall
		// through and emit the orphan finding.
	default:
		// Indeterminate (transport failure, unexpected rcode) — emit nothing
		// rather than risk a false positive.
		return nil, nil
	}

	// Orphan sub-case. Stable, deduplicated key-tag evidence so output is
	// deterministic.
	tags := dedupSortedKeyTags(dsKeyTagsOf(dsRecs))

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

// dsKeyTagsOf projects out the key tags from a DS-algorithm slice so the orphan
// sub-case can reuse the existing dedupSortedKeyTags pipeline unchanged.
func dsKeyTagsOf(dsRecs []resolver.DSAlgorithm) []uint16 {
	out := make([]uint16, len(dsRecs))
	for i, d := range dsRecs {
		out[i] = d.KeyTag
	}
	return out
}

// weakAlgorithmFinding inspects a healthy signed delegation for DNSSEC
// algorithms RFC 8624 has retired and returns a single Potential finding when
// any are present. A zone that uses only modern algorithms (RSASHA256/512,
// ECDSA, Ed25519) produces no finding — the secure normal case.
//
// Two surfaces are inspected:
//
//   - Each DNSKEY's Algorithm field, against weakDNSKEYAlgorithms. A weak key
//     means an attacker who breaks the underlying primitive can forge zone
//     signatures.
//   - Each DS record's Algorithm field (the key algorithm the parent commits
//     to) and DigestType (the hash used to fingerprint the key). A weak
//     digest type means an attacker can craft a different key whose digest
//     collides under the broken hash and substitute it into the chain.
//
// Findings list every distinct weakness observed, deduplicated and sorted, so
// the output is stable across runs and across multiple keys sharing the same
// algorithm.
func weakAlgorithmFinding(target string, dsRecs []resolver.DSAlgorithm, childAlgs []resolver.DNSKEYAlgorithm) []finding.Finding {
	weaknesses := make(map[string]struct{})

	for _, a := range childAlgs {
		if name, weak := weakDNSKEYAlgorithm(uint8(a)); weak {
			weaknesses[name] = struct{}{}
		}
	}
	for _, ds := range dsRecs {
		if name, weak := weakDNSKEYAlgorithm(ds.Algorithm); weak {
			weaknesses[name] = struct{}{}
		}
		if name, weak := weakDSDigest(ds.DigestType); weak {
			weaknesses[name] = struct{}{}
		}
	}
	if len(weaknesses) == 0 {
		return nil
	}

	names := make([]string, 0, len(weaknesses))
	for n := range weaknesses {
		names = append(names, n)
	}
	sort.Strings(names)

	// Carry the DS key tags too so an operator triaging the finding can match it
	// against the registrar records. The tag list is stable (deduped, sorted).
	tags := dedupSortedKeyTags(dsKeyTagsOf(dsRecs))

	return []finding.Finding{{
		Subdomain:      target,
		Vector:         finding.VectorDNSSEC,
		Confidence:     finding.Potential,
		DSKeyTags:      tags,
		DNSSECWeakAlgs: names,
		Evidence: fmt.Sprintf(
			"DNSSEC delegation uses weak/deprecated algorithm(s) %s (RFC 8624) — "+
				"forgeable chain of trust; rotate to RSASHA256/RSASHA512/ECDSAP256SHA256/"+
				"ECDSAP384SHA384/ED25519 and update the DS at the registrar",
			strings.Join(names, ", ")),
	}}
}

// weakDNSKEYAlgorithm names the IANA DNS Security Algorithm Numbers that
// RFC 8624 §3.1 forbids ("MUST NOT") or deprecates ("NOT RECOMMENDED") for
// signing. The second return value reports whether the algorithm is weak.
//
// Forbidden / deprecated algorithms:
//
//	1  RSAMD5                — MUST NOT use (MD5 collision-broken)
//	3  DSA/SHA-1             — MUST NOT use (DSA + SHA-1)
//	5  RSASHA1               — NOT RECOMMENDED (SHA-1 collision-broken)
//	6  DSA-NSEC3-SHA1        — MUST NOT use
//	7  RSASHA1-NSEC3-SHA1    — NOT RECOMMENDED
//	12 ECC-GOST              — MUST NOT use (GOST R 34.10-2001 deprecated)
//
// All other registered algorithms (RSASHA256, RSASHA512, ECDSA P-256/P-384,
// Ed25519, Ed448) are considered safe by RFC 8624 and yield ("", false).
func weakDNSKEYAlgorithm(a uint8) (string, bool) {
	switch a {
	case 1:
		return "RSAMD5", true
	case 3:
		return "DSA/SHA-1", true
	case 5:
		return "RSASHA1", true
	case 6:
		return "DSA-NSEC3-SHA1", true
	case 7:
		return "RSASHA1-NSEC3-SHA1", true
	case 12:
		return "ECC-GOST", true
	default:
		return "", false
	}
}

// weakDSDigest names the IANA DS RR Digest Algorithms that RFC 8624 §3.3
// deprecates. Digest type 1 (SHA-1) is NOT RECOMMENDED — SHA-1 is collision-
// broken, so a parent that fingerprints child keys with SHA-1 cannot rule out a
// substituted key whose SHA-1 digest matches. Digest type 0 is reserved and
// also flagged. Digest types 2 (SHA-256, the current mandatory) and 4
// (SHA-384) are safe and yield ("", false).
func weakDSDigest(d uint8) (string, bool) {
	switch d {
	case 0:
		return "DS-RESERVED", true
	case 1:
		return "DS-SHA1", true
	default:
		return "", false
	}
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
