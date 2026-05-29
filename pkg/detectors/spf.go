package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// maxSPFDepth bounds recursive include: resolution. RFC 7208 caps SPF DNS
// lookups at 10; the build step should enforce that limit here.
const maxSPFDepth = 10

// SPF detects two classes of SPF weakness on a domain: a dangling reference
// (the SubdoMailing takeover) and a permissive "all" mechanism.
//
// Dangling-reference sub-case. Two SPF directives reference an external domain's
// policy and are therefore equally exploitable when that domain is unregistered:
//
//   - include:<domain> — a mechanism (RFC 7208 §5.2) that pulls in another
//     domain's SPF record; a passing result there contributes to the policy.
//   - redirect=<domain> — a modifier (RFC 7208 §6.1) that designates another
//     domain's SPF record as THE policy for the current domain when no
//     mechanism matches. A dangling redirect= is arguably higher-impact than a
//     dangling include: because the redirect target's policy replaces the local
//     one wholesale.
//
// Both yield the SubdoMailing takeover (Guardio Labs, Feb 2024): an attacker who
// registers the claimable target domain controls the SPF evaluation and can
// authorise spoofed mail. The claimable domain is carried in SPFInclude.
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
// Algorithm:
//  1. Resolve TXT records (resolver.TXT) and extract the SPF policy.
//  2. If the record's all mechanism qualifies as Pass, emit a Potential
//     permissive finding keyed on the target.
//  3. Parse include: mechanisms and the redirect= modifier, recursing up to
//     maxSPFDepth; for each referenced domain that is NXDOMAIN (claimable), emit
//     a Potential dangling finding.
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

	visited := map[string]bool{target: true}
	dangling, _ := spfIncludes(ctx, spfRecord, r, visited, 0)
	findings = append(findings, dangling...)
	return findings, nil
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
	domain   string // lower-cased referenced domain
	redirect bool   // true for a redirect= modifier, false for an include: mechanism
}

// spfReferences extracts the external domains a single SPF record points at via
// include: mechanisms and the redirect= modifier, in record order. A redirect=
// modifier may legally appear anywhere in the record but applies only when no
// mechanism matches; for takeover detection its position is irrelevant — what
// matters is whether its target is claimable.
func spfReferences(record string) []spfReference {
	var refs []spfReference
	for _, field := range strings.Fields(record) {
		if domain, ok := strings.CutPrefix(field, "include:"); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain)})
			continue
		}
		if domain, ok := strings.CutPrefix(field, "redirect="); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain), redirect: true})
		}
	}
	return refs
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
			evidence := "SPF include: domain is NXDOMAIN (claimable)"
			if ref.redirect {
				evidence = "SPF redirect= domain is NXDOMAIN (claimable)"
			}
			findings = append(findings, finding.Finding{
				Subdomain:  domain,
				Vector:     finding.VectorSPF,
				Confidence: finding.Potential,
				SPFInclude: domain,
				Evidence:   evidence,
			})
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
