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

// SPF detects subdomain takeover via a claimable SPF include: domain or
// redirect= modifier — the SubdoMailing vector (Guardio Labs, Feb 2024).
//
// Two SPF directives reference an external domain's policy and are therefore
// equally exploitable when that domain is unregistered:
//
//   - include:<domain> — a mechanism (RFC 7208 §5.2) that pulls in another
//     domain's SPF record; a passing result there contributes to the policy.
//   - redirect=<domain> — a modifier (RFC 7208 §6.1) that designates another
//     domain's SPF record as THE policy for the current domain when no
//     mechanism matches. A dangling redirect= is arguably higher-impact than a
//     dangling include: because the redirect target's policy replaces the local
//     one wholesale.
//
// Both yield the SubdoMailing takeover: an attacker who registers the claimable
// target domain controls the SPF evaluation and can authorise spoofed mail.
//
// Algorithm (handoff "Detection vectors / 3. SPF include takeover", extended):
//  1. Resolve TXT records (resolver.TXT) and extract the SPF policy.
//  2. Parse include: mechanisms and the redirect= modifier, recursing up to
//     maxSPFDepth.
//  3. For each referenced domain, check whether it is NXDOMAIN (claimable).
//  4. If a referenced domain is unregistered, emit a finding with
//     Vector=VectorSPF and Confidence=Potential.
func SPF(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	txts, err := r.TXT(ctx, target)
	if err != nil || len(txts) == 0 {
		return nil, nil
	}

	spfRecord := extractSPF(txts)
	if spfRecord == "" {
		return nil, nil
	}

	visited := map[string]bool{target: true}
	return spfIncludes(ctx, spfRecord, r, visited, 0)
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
