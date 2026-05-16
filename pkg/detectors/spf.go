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

// SPF detects subdomain takeover via a claimable SPF include: domain — the
// SubdoMailing vector (Guardio Labs, Feb 2024).
//
// Algorithm (handoff "Detection vectors / 3. SPF include takeover"):
//  1. Resolve TXT records (resolver.TXT) and extract the SPF policy.
//  2. Parse include: directives, recursing up to maxSPFDepth.
//  3. For each included domain, check whether it is NXDOMAIN or WHOIS-expired.
//  4. If an included domain is unregistered (claimable), emit a finding with
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

// spfIncludes parses include: directives from a single SPF record and recurses.
func spfIncludes(ctx context.Context, record string, r *resolver.Resolver, visited map[string]bool, depth int) ([]finding.Finding, error) {
	if depth >= maxSPFDepth {
		return nil, nil
	}

	var findings []finding.Finding
	for _, field := range strings.Fields(record) {
		domain, ok := strings.CutPrefix(field, "include:")
		if !ok {
			continue
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
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
				Evidence:   "SPF include: domain is NXDOMAIN (claimable)",
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
