package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// DefaultDKIMSelectors is the list of DKIM selectors graverobber probes when no
// override is supplied. DKIM public keys live at <selector>._domainkey.<domain>;
// organizations frequently publish them as CNAMEs delegating the key to an ESP
// (e.g. s1._domainkey.example.com → s1.domainkey.sendgrid.net). The selector
// name is not discoverable from DNS alone, so a passive scanner can only cover
// the common, well-known selectors used by the major email service providers.
//
// Sources: provider onboarding docs (SendGrid s1/s2, Google "google", Mailchimp
// k1, Amazon SES-style, Microsoft "selector1"/"selector2") and the SubdoMailing
// writeup (Guardio Labs, 2024).
var DefaultDKIMSelectors = []string{
	"default",   // generic / self-hosted
	"google",    // Google Workspace
	"k1",        // Mailchimp / Mandrill
	"k2",        // Mailchimp (secondary)
	"s1",        // SendGrid (primary)
	"s2",        // SendGrid (secondary)
	"selector1", // Microsoft 365
	"selector2", // Microsoft 365
	"dkim",      // common self-hosted name
	"mail",      // common self-hosted name
	"smtp",      // common self-hosted name
}

// DKIM detects subdomain takeover via a dangling DKIM selector CNAME.
//
// Algorithm (POST_V01.md Rank 6 — DKIM selector dangling CNAME detection):
//  1. For each selector, build the FQDN <selector>._domainkey.<target>.
//  2. Resolve its CNAME (resolver.RawCNAME). A selector with no CNAME (TXT key
//     published inline, or absent entirely) is not delegated and is skipped.
//  3. Follow the CNAME target with CNAMEChain; if the target is NXDOMAIN the ESP
//     resource is gone and the selector is reclaimable.
//  4. Emit a VectorDKIM finding with Confidence=Confirmed when the CNAME target
//     is NXDOMAIN (definitively dangling).
//
// selectors overrides DefaultDKIMSelectors when non-empty (the --selectors
// flag). Each selector is probed independently; one dangling selector does not
// short-circuit the others.
func DKIM(ctx context.Context, target string, r *resolver.Resolver, selectors []string) ([]finding.Finding, error) {
	if len(selectors) == 0 {
		selectors = DefaultDKIMSelectors
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate selectors within a single target

	for _, sel := range selectors {
		sel = strings.ToLower(strings.TrimSpace(sel))
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true

		host := sel + "._domainkey." + target

		cname, err := r.RawCNAME(ctx, host)
		if err != nil || cname == "" {
			// No CNAME at this selector (inline TXT key, absent record, or the
			// _domainkey label itself is NXDOMAIN with no alias) → not delegated,
			// nothing to take over.
			continue
		}

		// The selector delegates via CNAME. Check whether the delegated target
		// still exists. NXDOMAIN means the ESP resource is gone and reclaimable.
		_, chainErr := r.CNAMEChain(ctx, cname)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:    host,
				Vector:       finding.VectorDKIM,
				Confidence:   finding.Confirmed,
				CNAME:        cname,
				DKIMSelector: sel,
				Evidence:     "DKIM selector CNAME target is NXDOMAIN — ESP resource reclaimable",
			})
		}
	}

	return findings, nil
}
