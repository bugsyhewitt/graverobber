package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// knownMailProviders is the suffix list used to identify cloud mail providers
// whose hosted zones can be deleted and re-claimed by an attacker.
// A dangling MX pointing at one of these is classified as Confirmed; an
// unrecognised provider is Potential (the mail host is still NXDOMAIN, but we
// cannot confirm re-claimability without further research).
var knownMailProviders = []string{
	"google.com",                  // Google Workspace / Gmail MX
	"googlemail.com",              // Google legacy MX
	"outlook.com",                 // Microsoft 365
	"protection.outlook.com",      // Microsoft 365 EOP
	"mail.protection.outlook.com", // Microsoft 365 EOP (subdomain form)
	"sendgrid.net",                // Twilio SendGrid
	"mailgun.org",                 // Mailgun
	"amazonses.com",               // Amazon SES
	"mimecast.com",                // Mimecast
	"proofpoint.com",              // Proofpoint
	"pphosted.com",                // Proofpoint hosted
	"messagelabs.com",             // Symantec/Broadcom
	"barracuda.com",               // Barracuda
	"barracudanetworks.com",       // Barracuda
	"fastmail.com",                // Fastmail
	"zoho.com",                    // Zoho Mail
	"mailhostbox.com",             // MailHostBox
	"emailsrvr.com",               // Rackspace Email
}

// MX detects subdomain takeover via a dangling MX record.
//
// Algorithm (POST_V01.md Rank 3 — MX record dangling-record detection):
//  1. Resolve MX records for target (resolver.MX).
//  2. For each MX hostname, query CNAMEChain; if NXDOMAIN the mail host is gone.
//  3. Optionally match the MX hostname against knownMailProviders to detect
//     zone deletions on cloud mail providers.
//  4. Emit VectorMX findings:
//     - Confidence=Confirmed when the MX host is NXDOMAIN (definitively dangling).
//     - Confidence=Potential when the MX hostname matches a known provider suffix
//     but is not NXDOMAIN (possible zone deletion — further verification needed).
func MX(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	mxHosts, err := r.MX(ctx, target)
	if err != nil || len(mxHosts) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate by MX host within a single target

	for _, mx := range mxHosts {
		mx = strings.ToLower(strings.TrimSpace(mx))
		if mx == "" || seen[mx] {
			continue
		}
		seen[mx] = true

		_, chainErr := r.CNAMEChain(ctx, mx)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			// Mail host is definitively gone → Confirmed.
			findings = append(findings, finding.Finding{
				Subdomain:  target,
				Vector:     finding.VectorMX,
				Confidence: finding.Confirmed,
				MXHosts:    []string{mx},
				Evidence:   "MX host is NXDOMAIN — mail host does not exist",
			})
			continue
		}

		// Mail host resolves. Check whether it belongs to a known cloud mail
		// provider; if so, there is a potential (but unconfirmed) zone-deletion
		// risk worth surfacing for manual verification.
		if provider := matchMailProvider(mx); provider != "" {
			findings = append(findings, finding.Finding{
				Subdomain:  target,
				Vector:     finding.VectorMX,
				Service:    provider,
				Confidence: finding.Potential,
				MXHosts:    []string{mx},
				Evidence:   "MX host matches known cloud mail provider — verify zone ownership",
			})
		}
	}

	return findings, nil
}

// matchMailProvider returns the first knownMailProviders suffix that the MX
// hostname matches, or "" if none match.
func matchMailProvider(mx string) string {
	mx = strings.ToLower(mx)
	for _, suffix := range knownMailProviders {
		if strings.HasSuffix(mx, suffix) || strings.Contains(mx, suffix) {
			return suffix
		}
	}
	return ""
}
