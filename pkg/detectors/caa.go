package detectors

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// CAA detects misconfigurations in a domain's CAA (Certification Authority
// Authorization, RFC 8659) record set.
//
// A CAA record set restricts which Certificate Authorities may issue
// certificates for a domain. Each record carries a tag and a value:
//
//	issue "letsencrypt.org"      — only Let's Encrypt may issue end-entity certs
//	issuewild "digicert.com"     — only DigiCert may issue wildcard certs
//	issue ";"                    — NO CA may issue (the deny-all form)
//	iodef "mailto:sec@..."       — where to report violations
//
// CAA closes a real attack: without it, ANY of the ~150 publicly-trusted CAs
// will issue a certificate for the domain to anyone who passes that CA's
// (sometimes weak) domain-control validation, enabling man-in-the-middle TLS.
// graverobber flags three CAA misconfigurations:
//
// Dangling-issuer sub-case (Potential). An issue= or issuewild= tag names a CA
// domain that is NXDOMAIN. This is the SubdoMailing-class takeover applied to
// CAA: an attacker who registers the unregistered CA domain can stand up a CA
// (or an ACME endpoint impersonating one) that the target's CAA policy
// explicitly authorises to issue certificates for the target. The claimable
// domain is carried in CAAIssuer.
//
// Dangling-iodef sub-case (Potential). An iodef= tag (RFC 8659 §4.4) names the
// URL — a mailto: address or an http(s):// endpoint (RFC 6546) — where a CA
// reports a request to issue a certificate that the policy forbids. If that
// URL's host is NXDOMAIN, an attacker who registers it intercepts the CAA
// violation reports: a reconnaissance channel revealing exactly which CAs are
// being probed against the target's policy (i.e. mis-issuance/attack attempts),
// mirroring the DMARC rua/ruf report-interception case. The reporting plane is
// distinct from issuance, so it is the same dangling-host family applied to CAA
// telemetry rather than to certificate issuance. The claimable host is carried
// in CAAIssuer and the Evidence string calls out the iodef tag.
//
// Permissive sub-case (Potential). A CAA record set is present but an issue= or
// issuewild= tag authorises ANY CA via the wildcard value "*" (or "*;" with
// parameters). Publishing CAA and then naming "*" re-opens the very hole CAA
// exists to close, while signalling (falsely) that issuance is controlled — a
// configuration mistake worth surfacing. Evidence names the offending tag.
//
// CAA is opt-out via the scanner's NoCAA option, consistent with the other
// DNS-only vectors. Confidence is Potential: a DNS-only signal with no
// fingerprint match, mirroring the SPF/DMARC classification. Findings are keyed
// on the target itself (the misconfigured domain), not on a remote resource.
//
// A domain with NO CAA record set is the permissive default; that case is the
// internet-wide norm and is intentionally NOT flagged, to keep the vector
// low-noise and pipeline-friendly. Only a present-but-broken policy is reported.
//
// Algorithm:
//  1. Resolve CAA records at target. If none, return no findings.
//  2. For each issue/issuewild tag, parse the CA domain from the value.
//     - value "*" (any CA): emit a Potential permissive-CAA finding.
//     - a concrete CA domain that is NXDOMAIN: emit a Potential dangling finding.
//  3. For each iodef tag, parse the report host from the URL.
//     - a host that is NXDOMAIN: emit a Potential dangling-iodef finding.
func CAA(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	records, err := r.CAA(ctx, target)
	if err != nil || len(records) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate CA / report domains within a single target
	flaggedWildcard := false  // emit the "any CA" finding at most once per target

	for _, rec := range records {
		// iodef= names the report-receiving URL, not a CA. Its host is checked for
		// the dangling-report (report-interception) sub-case.
		if rec.Tag == "iodef" {
			host := caaIodefHost(rec.Value)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true

			_, chainErr := r.CNAMEChain(ctx, host)
			if errors.Is(chainErr, resolver.ErrNXDomain) {
				findings = append(findings, finding.Finding{
					Subdomain:  target,
					Vector:     finding.VectorCAA,
					Confidence: finding.Potential,
					CAAIssuer:  host,
					Evidence:   "CAA iodef report host " + host + " is NXDOMAIN (claimable — attacker could intercept CAA violation reports)",
				})
			}
			continue
		}

		if rec.Tag != "issue" && rec.Tag != "issuewild" {
			continue // unknown tags do not authorise issuance
		}

		domain := caaIssuerDomain(rec.Value)

		// "*" authorises any CA — the permissive misconfiguration.
		if domain == "*" {
			if flaggedWildcard {
				continue
			}
			flaggedWildcard = true
			findings = append(findings, finding.Finding{
				Subdomain:  target,
				Vector:     finding.VectorCAA,
				Confidence: finding.Potential,
				Evidence:   "CAA " + rec.Tag + ` "*" authorises any CA to issue (permissive — defeats the CAA control)`,
			})
			continue
		}

		// A bare ";" (deny-all) or an empty value is the secure case — skip.
		if domain == "" {
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true

		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe, exactly as the
		// SPF include: and DMARC report-domain detectors use it.
		_, chainErr := r.CNAMEChain(ctx, domain)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  target,
				Vector:     finding.VectorCAA,
				Confidence: finding.Potential,
				CAAIssuer:  domain,
				Evidence:   "CAA " + rec.Tag + " names CA domain " + domain + " which is NXDOMAIN (claimable — attacker-controlled CA could be authorised)",
			})
		}
	}
	return findings, nil
}

// caaIssuerDomain extracts the CA domain from a CAA issue/issuewild value and
// lower-cases it. Per RFC 8659 §4.2 the value is an "issuer-domain-name"
// optionally followed by ";"-separated parameters (e.g.
// `letsencrypt.org; validationmethods=dns-01`). The special value ";" (and the
// empty string) means "no CA may issue" — the deny-all form — and is returned as
// "". A lone "*" authorises any CA and is returned verbatim as "*".
func caaIssuerDomain(value string) string {
	value = strings.TrimSpace(value)
	// Take the part before the first ";" — that is the issuer-domain-name.
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	value = strings.TrimSpace(value)
	if value == "*" {
		return "*"
	}
	return strings.ToLower(value)
}

// caaIodefHost extracts the report-receiving host from a CAA iodef= value and
// lower-cases it. Per RFC 8659 §4.4 the value is a URL identifying where a CA
// sends Incident Object Description Exchange Format reports; RFC 6546 defines the
// transports, so in practice the scheme is "mailto:" (the host is the part after
// the "@") or "http"/"https" (the host is the URL authority). Any other scheme,
// or a value with no host, returns "" so it is skipped. The match mirrors the
// DMARC rua/ruf mailto parser and the BIMI http(s) URL parser already in the
// codebase.
func caaIodefHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if addr, ok := cutPrefixFold(value, "mailto:"); ok {
		at := strings.LastIndexByte(addr, '@')
		if at < 0 || at == len(addr)-1 {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(addr[at+1:]))
	}

	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// cutPrefixFold is strings.CutPrefix with an ASCII-case-insensitive prefix match,
// used so an "MAILTO:" scheme (URI schemes are case-insensitive, RFC 3986 §3.1)
// is recognised the same as "mailto:".
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
