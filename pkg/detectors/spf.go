package detectors

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// maxSPFDepth bounds recursive include: resolution. RFC 7208 caps SPF DNS
// lookups at 10; the build step should enforce that limit here.
const maxSPFDepth = 10

// maxSPFLookups is the RFC 7208 §4.6.4 cap on DNS-querying mechanisms and
// modifiers across an SPF evaluation. include, a, mx, ptr, exists, and
// redirect= each count as one DNS-querying term; ip4, ip6, exp, all, and the
// version tag do not. A record whose total exceeds 10 MUST produce a
// "permerror" — every SPF-checking receiver hard-fails the check, which
// (under DMARC alignment) leaves the domain spoofable by omission.
const maxSPFLookups = 10

// SPF detects four classes of SPF weakness on a domain: a dangling reference
// (the SubdoMailing takeover), a permissive "all" mechanism, a record that
// exceeds the RFC 7208 §4.6.4 DNS-lookup cap (a "permerror"-by-design policy),
// and use of the deprecated "ptr" mechanism (RFC 7208 §5.5 — "SHOULD NOT be
// published").
//
// Dangling-reference sub-case. Four SPF directives reference an external
// domain and are therefore equally exploitable when that domain is unregistered:
//
//   - include:<domain> — a mechanism (RFC 7208 §5.2) that pulls in another
//     domain's SPF record; a passing result there contributes to the policy.
//   - redirect=<domain> — a modifier (RFC 7208 §6.1) that designates another
//     domain's SPF record as THE policy for the current domain when no
//     mechanism matches. A dangling redirect= is arguably higher-impact than a
//     dangling include: because the redirect target's policy replaces the local
//     one wholesale.
//   - a:<domain> — a mechanism (RFC 7208 §5.3) that passes when the sender's IP
//     matches an A/AAAA record of the named domain. With an explicit domain
//     argument it authorises that external domain's address records to send mail
//     as the target.
//   - mx:<domain> — a mechanism (RFC 7208 §5.4) that passes when the sender's IP
//     matches an A/AAAA record of one of the named domain's MX hosts. With an
//     explicit domain argument it authorises that external domain's mail-host
//     addresses to send as the target.
//
// All four yield the SubdoMailing takeover (Guardio Labs, Feb 2024): an attacker
// who registers the claimable target domain controls the SPF evaluation and can
// authorise spoofed mail. For a:/mx: the attacker simply points the reclaimed
// domain's A (or MX) records at their own sending host and every message they
// send passes SPF for the target. The claimable domain is carried in SPFInclude.
//
// Bare a/mx mechanisms with NO ":domain" argument (e.g. "a", "a/24", "mx",
// "mx//64") reference the TARGET's own A/MX records, not an external domain, so
// they are not a takeover surface and are intentionally NOT extracted.
//
// Permissive-policy sub-case. The "all" mechanism is the catch-all that ends a
// well-formed SPF record (RFC 7208 §5.1); its qualifier decides the result for
// any sender not matched by an earlier mechanism: "-all" (Fail, the secure
// default), "~all" (SoftFail), "?all" (Neutral), and "+all" (Pass). A "+all"
// policy — or a bare "all", which §4.6.2 treats as "+all" — explicitly
// authorises EVERY host on the internet to send mail as the domain, which
// defeats the entire purpose of publishing SPF: the domain is fully spoofable
// and any forged mail passes SPF alignment. This mirrors the DMARC p=none
// weak-policy sub-case: a present-but-toothless email-authentication record. The
// offending token is carried in SPFAll and the finding is keyed on the target
// itself (not an external domain), so it is emitted once per record.
//
// Deprecated-ptr sub-case. The "ptr" mechanism (RFC 7208 §5.2.4 / §5.5)
// authorises a sender whose PTR record (reverse-DNS lookup of the connecting
// IP) lands in the SPF domain. §5.5 explicitly discourages it: "Use of this
// mechanism is discouraged because it is slow, it is not as reliable as other
// mechanisms in cases of DNS errors, and it places a large burden on the
// .arpa name servers. If used, proper PTR records have to be in place for the
// domain's hosts and the mechanism SHOULD be one of the last mechanisms
// checked. SPF publishers SHOULD NOT include this mechanism in their SPF
// records, and SHOULD use the "a" or "mx" mechanisms instead." Some receivers
// already ignore ptr or treat it as a permerror, which makes the publisher's
// SPF result effectively undefined and — under DMARC alignment — leaves the
// domain spoofable-by-omission on the same axis as the §4.6.4 lookup-limit
// breach. graverobber emits a Potential sub-case keyed on the apex when the
// apex policy contains any "ptr" mechanism (bare or "ptr:<domain>"). The
// offending token is carried in SPFPtr. Checked only against the apex record
// (not recursed includes): the deprecation is the publisher's misconfigura-
// tion, so it is reported on the record graverobber is auditing. This mirrors
// the apex-only scope of the permissive-"+all" sub-case.
//
// Lookup-limit sub-case. RFC 7208 §4.6.4 caps an SPF evaluation at ten
// DNS-querying mechanisms and modifiers — include, a, mx, ptr, exists, and
// redirect= each count as one; ip4, ip6, exp, all, and the version tag do not.
// A record whose total (across the apex policy and every recursed include/
// redirect target) exceeds ten MUST yield a "permerror" — every conforming
// SPF receiver hard-fails the check, which under DMARC alignment leaves the
// domain spoofable by omission. This is the SPF analog of the DMARC p=none
// weak-policy sub-case: a present-but-broken email-auth record. The offending
// count is carried in SPFLookups and the finding is keyed on the target.
//
// Algorithm:
//  1. Resolve TXT records (resolver.TXT) and extract the SPF policy.
//  2. If the record's all mechanism qualifies as Pass, emit a Potential
//     permissive finding keyed on the target.
//  3. If the apex record contains any "ptr" mechanism, emit a Potential
//     deprecated-ptr finding keyed on the target (RFC 7208 §5.5).
//  4. Parse include: mechanisms and the redirect= modifier, recursing up to
//     maxSPFDepth; for each referenced domain that is NXDOMAIN (claimable), emit
//     a Potential dangling finding.
//  5. Walk the recursed policy graph and tally every DNS-querying mechanism
//     and modifier; if the total exceeds maxSPFLookups, emit a Potential
//     lookup-limit finding keyed on the target.
func SPF(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	txts, err := r.TXT(ctx, target)
	if err != nil || len(txts) == 0 {
		return nil, nil
	}

	spfRecord := extractSPF(txts)
	if spfRecord == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// Permissive-policy sub-case: a Pass-qualified "all" mechanism authorises any
	// sender. Keyed on the target itself, so it is emitted once per record. This
	// is checked only against the apex record (not recursed includes): the all
	// mechanism that governs the scanned name is the one in its own record.
	if token := spfPermissiveAll(spfRecord); token != "" {
		findings = append(findings, finding.Finding{
			Subdomain:  target,
			Vector:     finding.VectorSPF,
			Confidence: finding.Potential,
			SPFAll:     token,
			Evidence:   "SPF policy ends in " + token + " (Pass — authorises any host to send mail as the domain; domain is spoofable)",
		})
	}

	// Deprecated-ptr sub-case: the apex policy contains a "ptr" mechanism.
	// RFC 7208 §5.5 — "SHOULD NOT be published" — and many SPF receivers
	// either ignore the mechanism or treat it as permerror, leaving the
	// publisher's SPF result effectively undefined. Keyed on the target itself
	// (the publisher's misconfiguration), apex-only like the permissive
	// sub-case. The first ptr token observed is reported; multiple ptr
	// mechanisms still collapse to a single finding (one record, one
	// misconfiguration). It is independent of the other sub-cases — a record
	// can contain both "ptr" and "+all", or "ptr" and a dangling include:, and
	// each sub-case emits its own finding.
	if token := spfDeprecatedPtr(spfRecord); token != "" {
		findings = append(findings, finding.Finding{
			Subdomain:  target,
			Vector:     finding.VectorSPF,
			Confidence: finding.Potential,
			SPFPtr:     token,
			Evidence:   "SPF policy contains the " + token + " mechanism (RFC 7208 §5.5 deprecated — slow, unreliable, and ignored or treated as permerror by some receivers; SPF publishers SHOULD NOT include it)",
		})
	}

	visited := map[string]bool{target: true}
	dangling, _ := spfIncludes(ctx, spfRecord, r, visited, 0)
	findings = append(findings, dangling...)

	// Lookup-limit sub-case: tally every DNS-querying mechanism and modifier
	// across the recursed policy graph. Each include/redirect target whose
	// downstream policy is reachable contributes its own mechanism count; an
	// unreachable target (NXDOMAIN, SERVFAIL, missing TXT) still contributes the
	// single lookup the apex spent on it. Counted independently of the dangling
	// traversal so neither sub-case influences the other.
	countVisited := map[string]bool{target: true}
	if total := spfDNSLookups(ctx, spfRecord, r, countVisited, 0); total > maxSPFLookups {
		findings = append(findings, finding.Finding{
			Subdomain:  target,
			Vector:     finding.VectorSPF,
			Confidence: finding.Potential,
			SPFLookups: total,
			Evidence: fmt.Sprintf(
				"SPF evaluation requires %d DNS-querying mechanisms (RFC 7208 §4.6.4 caps at %d — receivers return permerror; SPF check hard-fails)",
				total, maxSPFLookups),
		})
	}
	return findings, nil
}

// spfQueryingMechanisms counts the DNS-querying mechanisms and modifiers in a
// single SPF record per RFC 7208 §4.6.4: include, a, mx, ptr, exists, and
// redirect= each count as one lookup; ip4, ip6, exp, all, and the version tag
// do not. Both the bare and ":domain"/"=domain" forms of a/mx/include/redirect
// count, as do a/mx with only a "/cidr" dual-CIDR suffix. Qualifier prefixes
// ("+", "-", "~", "?") on mechanisms are stripped before matching.
func spfQueryingMechanisms(record string) int {
	count := 0
	for _, field := range strings.Fields(record) {
		// redirect= is a modifier; it never carries a qualifier prefix.
		if _, ok := strings.CutPrefix(field, "redirect="); ok {
			count++
			continue
		}
		// exp= is a modifier but is NOT counted (§4.6.4 explicitly excludes it).
		// Strip qualifier prefixes before matching mechanism names.
		mech := strings.TrimLeft(field, "+-~?")
		// Match each DNS-querying mechanism by name, allowing the optional
		// ":<argument>" or "/<cidr>" suffix that a, mx, ptr, and include may
		// carry. The trailing-byte check guards against false matches on tokens
		// that merely start with these short prefixes (e.g. "all" vs "a").
		switch {
		case mech == "a", strings.HasPrefix(mech, "a:"), strings.HasPrefix(mech, "a/"):
			count++
		case mech == "mx", strings.HasPrefix(mech, "mx:"), strings.HasPrefix(mech, "mx/"):
			count++
		case mech == "ptr", strings.HasPrefix(mech, "ptr:"):
			count++
		case strings.HasPrefix(mech, "include:"):
			count++
		case strings.HasPrefix(mech, "exists:"):
			count++
		}
	}
	return count
}

// spfDNSLookups walks the SPF policy graph rooted at record and returns the
// total number of DNS-querying mechanisms and modifiers per RFC 7208 §4.6.4.
// Each include:/redirect= target's downstream policy is recursed into when its
// TXT is reachable; an unreachable include/redirect target still contributes
// the one lookup the apex spent on it (already counted in record). Cycles and
// re-encountered domains are short-circuited via visited; bounded by
// maxSPFDepth as a hard recursion guard, mirroring the dangling traversal.
func spfDNSLookups(ctx context.Context, record string, r *resolver.Resolver, visited map[string]bool, depth int) int {
	if depth >= maxSPFDepth {
		return 0
	}
	total := spfQueryingMechanisms(record)
	for _, ref := range spfReferences(record) {
		if !ref.recursable() {
			continue
		}
		domain := ref.domain
		if domain == "" || visited[domain] {
			continue
		}
		visited[domain] = true
		txts, err := r.TXT(ctx, domain)
		if err != nil || len(txts) == 0 {
			continue
		}
		if included := extractSPF(txts); included != "" {
			total += spfDNSLookups(ctx, included, r, visited, depth+1)
		}
	}
	return total
}

// spfPermissiveAll reports the offending "all" mechanism token when an SPF
// record's catch-all qualifies as Pass, or "" when it does not. An "all"
// mechanism may carry a qualifier prefix: "+" (Pass), "-" (Fail), "~" (SoftFail),
// or "?" (Neutral). A missing qualifier defaults to "+" (Pass) per RFC 7208
// §4.6.2, so a bare "all" is as permissive as "+all". Only "+all" / "all" are
// flagged; "-all", "~all", and "?all" are secure-to-cautious and never flagged.
// The mechanism name is matched case-insensitively (qualifiers are not letters).
func spfPermissiveAll(record string) string {
	for _, field := range strings.Fields(record) {
		switch {
		case strings.EqualFold(field, "all"), strings.EqualFold(field, "+all"):
			return field
		}
	}
	return ""
}

// spfDeprecatedPtr reports the first offending "ptr" mechanism token observed
// in an SPF record, or "" when none is present. The "ptr" mechanism (RFC 7208
// §5.2.4) may appear bare ("ptr") or with an explicit domain argument
// ("ptr:<domain>"); both forms are flagged. A qualifier prefix ("+", "-", "~",
// "?") is preserved in the returned token so the evidence string names the
// exact field the operator should remove from their published record (e.g.
// "+ptr" vs "ptr:example.com"). The mechanism name is matched case-
// insensitively (consistent with spfPermissiveAll), and the surrounding
// strings.Fields split protects against partial-token false matches: a TXT
// fragment like "permitter" or "ptraffic.example.com" never matches because
// neither is a standalone token of the form "ptr"/"+ptr"/"ptr:..." after
// qualifier stripping.
func spfDeprecatedPtr(record string) string {
	for _, field := range strings.Fields(record) {
		// Strip the optional qualifier prefix the same way spfQueryingMechanisms
		// does for ptr — qualifiers are not letters, so the lowercased name is
		// what we test for the bare/colon-prefix forms.
		mech := strings.TrimLeft(field, "+-~?")
		lower := strings.ToLower(mech)
		if lower == "ptr" || strings.HasPrefix(lower, "ptr:") {
			return field
		}
	}
	return ""
}

// extractSPF returns the first TXT record that looks like an SPF policy.
func extractSPF(txts []string) string {
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1 ") || t == "v=spf1" {
			return t
		}
	}
	return ""
}

// spfReference is a single external domain referenced by an SPF record, tagged
// with the directive that referenced it so the finding's evidence can name it.
type spfReference struct {
	domain    string // lower-cased referenced domain
	directive string // the directive that referenced it: "include:", "redirect=", "a:", or "mx:"
}

// recursable reports whether the referenced domain hosts its own SPF policy that
// should be followed. include: and redirect= name another SPF record and so are
// recursed; a:/mx: name a host whose ADDRESS records are authorised — they do not
// pull in a downstream SPF policy, so their dangling check is terminal.
func (ref spfReference) recursable() bool {
	return ref.directive == "include:" || ref.directive == "redirect="
}

// spfReferences extracts the external domains a single SPF record points at via
// the include:, a:, and mx: mechanisms and the redirect= modifier, in record
// order. A redirect= modifier may legally appear anywhere in the record but
// applies only when no mechanism matches; for takeover detection its position is
// irrelevant — what matters is whether its target is claimable.
//
// For a:/mx: only the explicit-domain form ("a:domain", "mx:domain", optionally
// with a trailing "/cidr" or "//cidr" dual-CIDR suffix) references an external
// domain. A bare "a"/"mx" (or "a/24") points at the target's own records and is
// not a takeover surface, so it is skipped. A mechanism may carry a qualifier
// prefix ("+", "-", "~", "?"), which is stripped before matching.
func spfReferences(record string) []spfReference {
	var refs []spfReference
	for _, field := range strings.Fields(record) {
		// redirect= is a modifier; it never carries a qualifier prefix.
		if domain, ok := strings.CutPrefix(field, "redirect="); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain), directive: "redirect="})
			continue
		}

		// Mechanisms may be prefixed with a qualifier; strip it before matching.
		mech := strings.TrimLeft(field, "+-~?")

		if domain, ok := strings.CutPrefix(mech, "include:"); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain), directive: "include:"})
			continue
		}
		if domain, ok := spfDualCIDRDomain(mech, "a:"); ok {
			refs = append(refs, spfReference{domain: domain, directive: "a:"})
			continue
		}
		if domain, ok := spfDualCIDRDomain(mech, "mx:"); ok {
			refs = append(refs, spfReference{domain: domain, directive: "mx:"})
		}
	}
	return refs
}

// spfDualCIDRDomain extracts the external domain from an "a:" or "mx:" mechanism
// of the form "<prefix>domain", "<prefix>domain/24", or "<prefix>domain//64"
// (RFC 7208 §5.3/§5.4 dual-CIDR-length syntax). It returns ("", false) when mech
// does not start with prefix or carries no domain (a bare "a"/"mx", which the
// CutPrefix on "a:"/"mx:" already excludes). The trailing /ip4-cidr or //ip6-cidr
// is stripped — it constrains the matched IP range, not which domain is named.
func spfDualCIDRDomain(mech, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(mech, prefix)
	if !ok {
		return "", false
	}
	// Strip a trailing dual-CIDR suffix ("/24", "//64", or "/24//64"). The IPv4
	// CIDR (if any) is delimited by the first "/"; everything from there on is
	// CIDR syntax, not part of the domain.
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	domain := normaliseSPFDomain(rest)
	if domain == "" {
		return "", false
	}
	return domain, true
}

// normaliseSPFDomain lower-cases and trims an SPF-referenced domain.
func normaliseSPFDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

// spfIncludes parses include: mechanisms and the redirect= modifier from a
// single SPF record and recurses into the policies of domains that still exist.
func spfIncludes(ctx context.Context, record string, r *resolver.Resolver, visited map[string]bool, depth int) ([]finding.Finding, error) {
	if depth >= maxSPFDepth {
		return nil, nil
	}

	var findings []finding.Finding
	for _, ref := range spfReferences(record) {
		domain := ref.domain
		if domain == "" || visited[domain] {
			continue
		}
		visited[domain] = true

		// Use CNAMEChain (TypeA query) as the authoritative NXDOMAIN probe.
		// TXT returning (nil, nil) is ambiguous — domain may exist with no TXT.
		// ErrNXDomain from CNAMEChain means the domain is definitively gone.
		_, aErr := r.CNAMEChain(ctx, domain)
		if errors.Is(aErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  domain,
				Vector:     finding.VectorSPF,
				Confidence: finding.Potential,
				SPFInclude: domain,
				Evidence:   "SPF " + ref.directive + " domain is NXDOMAIN (claimable)",
			})
			continue
		}

		// a:/mx: mechanisms authorise the domain's address records directly; they
		// do not name a downstream SPF policy, so there is nothing to recurse into.
		if !ref.recursable() {
			continue
		}

		// Domain exists; try to recurse into its own SPF policy.
		txts, err := r.TXT(ctx, domain)
		if err != nil || len(txts) == 0 {
			continue
		}
		if included := extractSPF(txts); included != "" {
			sub, _ := spfIncludes(ctx, included, r, visited, depth+1)
			findings = append(findings, sub...)
		}
	}
	return findings, nil
}
