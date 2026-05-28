package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// DMARC detects subdomain takeover via a dangling DMARC reporting-address domain.
//
// DMARC policy records live at _dmarc.<domain> as a TXT record and may carry two
// reporting URIs:
//
//	rua=mailto:aggregate@reports.example.net   (aggregate reports)
//	ruf=mailto:forensic@reports.example.net    (failure/forensic reports)
//
// Each mailto URI names a domain that receives mail on the policy owner's behalf.
// If that domain is NXDOMAIN (the reporting vendor was decommissioned, or the
// address points at a forgotten internal subdomain whose zone was deleted) an
// attacker who registers/claims it intercepts every DMARC report sent for the
// target — a reconnaissance goldmine exposing which spoofing attempts succeed,
// the target's full sending infrastructure, and IP reputation. RFC 7489 §7.1
// further allows the report receiver's own published policy to be probed, so a
// dangling rua/ruf domain is a live, low-noise takeover signal.
//
// This vector completes graverobber's email-authentication coverage: SPF
// (include:), DKIM (selector CNAME), MX (mail host), and now DMARC (report URI)
// are the four record classes an attacker abuses to subvert SPF/DKIM/DMARC
// alignment. DMARC report-domain takeover was documented in the SubdoMailing
// (Guardio Labs, 2024) and Hazy Hawk campaigns alongside the SPF/MX vectors.
//
// Algorithm (mirrors SPF):
//  1. Resolve TXT records at _dmarc.<target>; extract the DMARC policy.
//  2. Parse the rua= and ruf= tags; split comma-separated URIs.
//  3. For each mailto: URI, extract the domain to the right of the "@".
//  4. Probe the domain with CNAMEChain; ErrNXDomain means it is claimable.
//  5. Emit a VectorDMARC finding with Confidence=Potential (DNS-only signal, no
//     fingerprint match — consistent with the SPF vector's classification).
func DMARC(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	txts, err := r.TXT(ctx, "_dmarc."+target)
	if err != nil || len(txts) == 0 {
		return nil, nil
	}

	record := extractDMARC(txts)
	if record == "" {
		return nil, nil
	}

	domains := dmarcReportDomains(record)
	if len(domains) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
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
