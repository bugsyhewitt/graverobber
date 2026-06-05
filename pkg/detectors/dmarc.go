package detectors

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// DMARC detects three DMARC weaknesses on a domain: a dangling reporting-address
// domain, a monitor-only (p=none) parent policy, and a weak subdomain policy
// (sp=none when the parent policy is p=reject or p=quarantine).
//
// DMARC policy records live at _dmarc.<domain> as a TXT record and carry a
// mandatory policy tag plus two optional reporting URIs:
//
//	p=reject|quarantine|none                   (enforcement policy)
//	rua=mailto:aggregate@reports.example.net   (aggregate reports)
//	ruf=mailto:forensic@reports.example.net    (failure/forensic reports)
//
// Dangling-report-host sub-case. RFC 7489 §6.2 defines each rua=/ruf= value as a
// comma-separated list of DMARC URIs, and §A.5 names "mailto:" and "https:" as
// the two registered transports. A mailto: URI names a domain that receives mail
// on the policy owner's behalf; an https: URI names a collector host that accepts
// the report over an HTTPS POST (the deployment model the large DMARC-as-a-service
// vendors offer). If the report host is NXDOMAIN (the reporting vendor was
// decommissioned, or the address points at a forgotten internal subdomain whose
// zone was deleted) an attacker who registers/claims it intercepts every DMARC
// report sent for the target — a reconnaissance goldmine exposing which spoofing
// attempts succeed, the target's full sending infrastructure, and IP reputation.
// RFC 7489 §7.1 further allows the report receiver's own published policy to be
// probed, so a dangling rua/ruf host is a live, low-noise takeover signal. The
// finding carries the claimable host in DMARCURI. Both transports are parsed: the
// mailto: case takes the host after the "@", the https: case takes the URL
// authority — the same dual-scheme handling the CAA iodef= (Rank 20) and TLSRPT
// rua= (Rank 22) report-host vectors use.
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
// Weak-subdomain-policy sub-case (new in Rotation 37). RFC 7489 §6.3 defines
// the optional sp= tag as an explicit override of the parent p= policy for all
// subdomains. When sp=none is set and the parent p= is "reject" or "quarantine",
// the parent domain is fully protected but every subdomain is freely spoofable:
// mail from <user>@<subdomain>.<target> passes DMARC alignment only against the
// subdomain's own DMARC record (if it has one), and in the absence of one inherits
// the sp=none policy — meaning no action is taken on failures. This is the "split
// enforcement" misconfiguration: a domain appears DMARC-protected at the apex but
// all subdomains remain spoofable, which is the precondition for subdomain
// phishing and business-email-compromise attacks targeting an organisation's
// subdomain namespace. The finding carries the sp= tag value in
// DMARCSubdomainPolicy; the parent enforcement policy is included in Evidence.
//
// Algorithm:
//  1. Resolve TXT records at _dmarc.<target>; extract the DMARC policy.
//  2. Parse the p= tag; if it is "none" emit a Potential weak-policy finding.
//  3. Parse the sp= tag; if it is "none" and p= is "reject" or "quarantine",
//     emit a Potential weak-subdomain-policy finding.
//  4. Parse the rua= and ruf= tags; split comma-separated URIs.
//  5. For each mailto: URI, extract the domain to the right of the "@"; for each
//     https:/http: URI, extract the URL authority host.
//  6. Probe the host with CNAMEChain; ErrNXDomain means it is claimable —
//     emit a Potential dangling-report-host finding (DNS-only signal, no
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

	policy := dmarcPolicy(record)

	// Weak-policy sub-case: p=none is monitor-only (no enforcement). It is keyed
	// on the target itself, not a report domain, so it is emitted once per record.
	if policy == "none" {
		hasReporting := len(dmarcReportHosts(record)) > 0
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

	// Weak-subdomain-policy sub-case: sp=none overrides the parent enforcement
	// policy for all subdomains. Only fires when the parent policy is enforcing
	// (p=reject or p=quarantine) — if p=none the parent-policy finding already
	// covers the domain and its subdomains.
	if policy == "reject" || policy == "quarantine" {
		if sp := dmarcSubdomainPolicy(record); sp == "none" {
			findings = append(findings, finding.Finding{
				Subdomain:            target,
				Vector:               finding.VectorDMARC,
				Confidence:           finding.Potential,
				DMARCSubdomainPolicy: sp,
				Evidence: fmt.Sprintf(
					"DMARC parent policy is p=%s (enforcing) but sp=none overrides "+
						"it for all subdomains — every subdomain is freely spoofable "+
						"(mail from <user>@<subdomain>.%s is not DMARC-protected)",
					policy, target,
				),
			})
		}
	}

	hosts := dmarcReportHosts(record)
	seen := map[string]bool{} // deduplicate report hosts within a single target
	for _, host := range hosts {
		if host == "" || host == target || seen[host] {
			continue
		}
		seen[host] = true

		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe: TXT returning
		// (nil, nil) is ambiguous, whereas ErrNXDomain is definitive — mirrors
		// the SPF include: detector exactly.
		_, chainErr := r.CNAMEChain(ctx, host)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  host,
				Vector:     finding.VectorDMARC,
				Confidence: finding.Potential,
				DMARCURI:   host,
				Evidence:   "DMARC rua/ruf report host is NXDOMAIN (claimable — report interception)",
			})
		}
	}
	return findings, nil
}

// dmarcPolicy returns the lower-cased value of the p= tag from a DMARC record,
// or "" when no p= tag is present. The match is case-insensitive on the tag name
// and value (RFC 7489 tags are case-insensitive in practice). Only the top-level
// p= is read; dmarcSubdomainPolicy handles the sp= tag separately.
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

// dmarcSubdomainPolicy returns the lower-cased value of the sp= tag from a
// DMARC record, or "" when no sp= tag is present. RFC 7489 §6.3 defines sp=
// as an optional override of the parent p= policy that applies specifically to
// subdomains. When sp= is absent, subdomains inherit the parent p= policy.
// When sp=none is explicit, every subdomain is monitor-only regardless of the
// parent p= value — which is the "split enforcement" misconfiguration this
// helper is used to detect.
func dmarcSubdomainPolicy(record string) string {
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		lower := strings.ToLower(tag)
		if v, ok := strings.CutPrefix(lower, "sp="); ok {
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

// dmarcReportHosts extracts the set of report-receiving hosts from the rua= and
// ruf= tags of a DMARC policy record. Each tag is a comma-separated list of DMARC
// URIs (RFC 7489 §6.2); §A.5 registers two transports — "mailto:" (the host is the
// domain after the "@") and "https:" (the host is the URL authority). An optional
// "!<size>" report-size limit may follow a mailto: address and is stripped. Any
// other scheme, or a URI with no host, is skipped — graverobber never probes a
// host it cannot positively identify. The returned hosts are lower-cased.
func dmarcReportHosts(record string) []string {
	var out []string
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		val, ok := cutDMARCTag(tag)
		if !ok {
			continue
		}
		for _, uri := range strings.Split(val, ",") {
			if host := dmarcURIHost(strings.TrimSpace(uri)); host != "" {
				out = append(out, host)
			}
		}
	}
	return out
}

// dmarcURIHost extracts the report-receiving host from a single DMARC URI and
// lower-cases it. RFC 7489 §A.5 registers "mailto:" and "https:" as the report
// transports: for mailto: the host is the domain after the "@" (with an optional
// trailing "!<size>" limit stripped per §6.2); for http/https the host is the URL
// authority. Any other scheme, or a URI with no host, returns "" so it is skipped.
// This mirrors the CAA iodef= (caaIodefHost) and BIMI (bimiURLHost) parsers in the
// same package, reusing the package-local cutPrefixFold for the case-insensitive
// scheme match (URI schemes are case-insensitive, RFC 3986 §3.1).
func dmarcURIHost(uri string) string {
	if uri == "" {
		return ""
	}

	if addr, ok := cutPrefixFold(uri, "mailto:"); ok {
		// Strip an optional "!<size>" report-size limit (RFC 7489 §6.2).
		if i := strings.IndexByte(addr, '!'); i >= 0 {
			addr = addr[:i]
		}
		at := strings.LastIndexByte(addr, '@')
		if at < 0 || at == len(addr)-1 {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(addr[at+1:]))
	}

	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return strings.ToLower(u.Hostname())
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
