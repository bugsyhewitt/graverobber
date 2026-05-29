package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// DMARC detects two DMARC weaknesses on a domain: a dangling reporting-address
// domain, and a monitor-only (p=none) policy.
//
// DMARC policy records live at _dmarc.<domain> as a TXT record and carry a
// mandatory policy tag plus two optional reporting URIs:
//
//	p=reject|quarantine|none                   (enforcement policy)
//	rua=mailto:aggregate@reports.example.net   (aggregate reports)
//	ruf=mailto:forensic@reports.example.net    (failure/forensic reports)
//
// Dangling-report-domain sub-case. Each mailto URI names a domain that receives
// mail on the policy owner's behalf. If that domain is NXDOMAIN (the reporting
// vendor was decommissioned, or the address points at a forgotten internal
// subdomain whose zone was deleted) an attacker who registers/claims it
// intercepts every DMARC report sent for the target — a reconnaissance goldmine
// exposing which spoofing attempts succeed, the target's full sending
// infrastructure, and IP reputation. RFC 7489 §7.1 further allows the report
// receiver's own published policy to be probed, so a dangling rua/ruf domain is
// a live, low-noise takeover signal. The finding carries the claimable domain in
// DMARCURI.
//
// Weak-policy sub-case. A policy of p=none is monitor-only: it instructs
// receivers to take NO action on a message that fails DMARC alignment, so
// spoofed mail that fails SPF and DKIM is still delivered to the inbox. RFC 7489
// §6.3 defines p=none as the deployment-bootstrap state, not a destination —
// publishing it indefinitely leaves the domain spoofable by anyone, which is the
// precondition every business-email-compromise and phishing campaign relies on.
// The case is materially worse when no rua= aggregate-reporting address is
// configured: the owner then has neither enforcement nor visibility, so an
// ongoing spoofing campaign is invisible. The finding carries the policy token
// in DMARCPolicy and notes in Evidence whether aggregate reporting is present.
//
// This vector completes graverobber's email-authentication coverage: SPF
// (include:), DKIM (selector CNAME / weak key), MX (mail host), and DMARC (report
// URI + policy strictness) are the record classes an attacker abuses to subvert
// SPF/DKIM/DMARC alignment. The DMARC vectors were documented in the
// SubdoMailing (Guardio Labs, 2024) and Hazy Hawk campaigns.
//
// Algorithm:
//  1. Resolve TXT records at _dmarc.<target>; extract the DMARC policy.
//  2. Parse the p= tag; if it is "none" emit a Potential weak-policy finding.
//  3. Parse the rua= and ruf= tags; split comma-separated URIs.
//  4. For each mailto: URI, extract the domain to the right of the "@".
//  5. Probe the domain with CNAMEChain; ErrNXDomain means it is claimable —
//     emit a Potential dangling-report-domain finding (DNS-only signal, no
//     fingerprint match, consistent with the SPF vector's classification).
func DMARC(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	txts, err := r.TXT(ctx, "_dmarc."+target)
	if err != nil || len(txts) == 0 {
		return nil, nil
	}

	record := extractDMARC(txts)
	if record == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// Weak-policy sub-case: p=none is monitor-only (no enforcement). It is keyed
	// on the target itself, not a report domain, so it is emitted once per record.
	if policy := dmarcPolicy(record); policy == "none" {
		hasReporting := len(dmarcReportDomains(record)) > 0
		evidence := "DMARC policy is p=none (monitor-only — spoofed mail is delivered)"
		if !hasReporting {
			evidence = "DMARC policy is p=none with no rua= aggregate reporting (no enforcement and no visibility)"
		}
		findings = append(findings, finding.Finding{
			Subdomain:   target,
			Vector:      finding.VectorDMARC,
			Confidence:  finding.Potential,
			DMARCPolicy: policy,
			Evidence:    evidence,
		})
	}

	domains := dmarcReportDomains(record)
	seen := map[string]bool{} // deduplicate report domains within a single target
	for _, domain := range domains {
		if domain == "" || domain == target || seen[domain] {
			continue
		}
		seen[domain] = true

		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe: TXT returning
		// (nil, nil) is ambiguous, whereas ErrNXDomain is definitive — mirrors
		// the SPF include: detector exactly.
		_, chainErr := r.CNAMEChain(ctx, domain)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  domain,
				Vector:     finding.VectorDMARC,
				Confidence: finding.Potential,
				DMARCURI:   domain,
				Evidence:   "DMARC rua/ruf report domain is NXDOMAIN (claimable — report interception)",
			})
		}
	}
	return findings, nil
}

// dmarcPolicy returns the lower-cased value of the p= tag from a DMARC record,
// or "" when no p= tag is present. The match is case-insensitive on the tag name
// and value (RFC 7489 tags are case-insensitive in practice). Only the top-level
// p= is read; the subdomain-policy sp= tag is intentionally ignored — graverobber
// scans concrete hosts, so the policy that governs the scanned name is p=.
func dmarcPolicy(record string) string {
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		lower := strings.ToLower(tag)
		if v, ok := strings.CutPrefix(lower, "p="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// extractDMARC returns the first TXT record that is a DMARC policy. Per RFC 7489
// §6.1 a DMARC record begins with "v=DMARC1" (case-insensitive on the version
// token in practice, though the tag itself is fixed-case in the spec).
func extractDMARC(txts []string) string {
	for _, t := range txts {
		trimmed := strings.TrimSpace(t)
		if strings.HasPrefix(trimmed, "v=DMARC1") {
			return trimmed
		}
	}
	return ""
}

// dmarcReportDomains extracts the set of report-receiving domains from the rua=
// and ruf= tags of a DMARC policy record. Each tag is a comma-separated list of
// DMARC URIs; the only scheme DMARC defines is "mailto:". An optional size limit
// may follow the address ("mailto:r@x.net!10m") and is stripped. The returned
// domains are lower-cased.
func dmarcReportDomains(record string) []string {
	var out []string
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		val, ok := cutDMARCTag(tag)
		if !ok {
			continue
		}
		for _, uri := range strings.Split(val, ",") {
			uri = strings.TrimSpace(uri)
			addr, ok := strings.CutPrefix(strings.ToLower(uri), "mailto:")
			if !ok {
				continue
			}
			// Strip an optional "!<size>" report-size limit (RFC 7489 §6.2).
			if i := strings.IndexByte(addr, '!'); i >= 0 {
				addr = addr[:i]
			}
			at := strings.LastIndexByte(addr, '@')
			if at < 0 || at == len(addr)-1 {
				continue
			}
			domain := strings.TrimSpace(addr[at+1:])
			if domain != "" {
				out = append(out, domain)
			}
		}
	}
	return out
}

// cutDMARCTag returns the value of a rua= or ruf= tag, or ("", false) when the
// tag is neither. The match is case-insensitive on the tag name.
func cutDMARCTag(tag string) (string, bool) {
	lower := strings.ToLower(tag)
	for _, prefix := range []string{"rua=", "ruf="} {
		if strings.HasPrefix(lower, prefix) {
			return tag[len(prefix):], true
		}
	}
	return "", false
}
