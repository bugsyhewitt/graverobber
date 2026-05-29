package detectors

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// tlsRptOwnerPrefix is the owner-name prefix for the SMTP TLS Reporting (TLSRPT,
// RFC 8460 §3) policy record. A domain that opts into TLSRPT publishes a TXT
// record at _smtp._tls.<domain> carrying "v=TLSRPTv1; rua=<report-destinations>".
const tlsRptOwnerPrefix = "_smtp._tls."

// tlsRptVersionToken is the mandatory version field of a valid TLSRPT record.
// RFC 8460 §3 requires the record to begin with "v=TLSRPTv1"; a TXT record at
// the TLSRPT owner name that lacks it is not a TLSRPT policy and is ignored,
// keeping the detector from firing on unrelated TXT records that share the owner
// name.
const tlsRptVersionToken = "v=tlsrptv1"

// TLSRPT detects a dangling SMTP TLS Reporting (TLSRPT, RFC 8460) report
// destination: a domain that advertises TLSRPT via a "v=TLSRPTv1" TXT record at
// _smtp._tls.<domain> whose rua= report destination — a mailto: address domain
// or an https: collector host — is NXDOMAIN.
//
// TLSRPT is the diagnostic feedback channel for SMTP TLS security (MTA-STS,
// RFC 8461, and DANE/TLSA, RFC 7672). A sending MTA that fails to negotiate the
// TLS the recipient's MTA-STS policy or DANE pin requires emits a daily report
// describing the failure to the addresses the recipient names in its rua= tag.
// The destinations are, in practice, a third-party reporting vendor's mailbox
// (rua=mailto:tls-reports@vendor.example) or an HTTPS collector
// (rua=https://reports.vendor.example/v1/tlsrpt). When that destination is
// decommissioned — the vendor mailbox domain is retired, the hosted zone is
// deleted, the collector subdomain is removed — but the TLSRPT TXT record is
// left behind, the deployment becomes a takeover vector:
//
//   - An attacker who reclaims the dangling report destination (re-registers the
//     gone mailto domain, re-creates the deleted collector host) receives every
//     TLSRPT report sent for the target. These reports are a reconnaissance
//     goldmine: they enumerate the target's sending counterparties, expose the
//     IPs and MX hosts involved in delivery, and — critically — reveal in real
//     time which senders are failing TLS to the domain. An attacker mounting an
//     active TLS-downgrade or MITM against the target's inbound mail can watch
//     the very failure reports that would otherwise alert the domain owner,
//     silently confirming and tuning the attack while the owner is blinded. This
//     is the same dangling-report-destination pattern the DMARC rua/ruf vector
//     covers (report interception), applied to the SMTP-TLS reporting plane and
//     completing graverobber's coverage of the MTA-STS/DANE control surface
//     (MTA-STS policy host + TLSA pin + TLSRPT report destination).
//
// A domain with no TLSRPT record, or whose report destinations all resolve, is
// the healthy case and is intentionally NOT flagged — only an advertised-but-
// orphaned report destination is reported, keeping the vector low-noise and
// pipeline-friendly, consistent with the other DNS-only vectors.
//
// The finding is keyed on the target, carries the TLSRPT owner name in Service
// and the dangling report host in TLSRPTURIHost, and is classified Potential: a
// DNS-only signal (NXDOMAIN with no fingerprint match), matching the
// SPF/DMARC/CAA/TLSA/MTA-STS/BIMI tier.
//
// Algorithm:
//  1. Resolve TXT at _smtp._tls.<target>. If no record begins with "v=TLSRPTv1",
//     the domain does not advertise TLSRPT — return no findings.
//  2. Parse the rua= tag (a comma-separated list of mailto:/https: destinations)
//     and extract the host of each: the domain after "@" for mailto:, the URL
//     host for https:.
//  3. For each distinct report host, probe it with CNAMEChain (the authoritative
//     NXDOMAIN probe). ErrNXDomain means the destination is gone — emit a
//     Potential finding naming the dangling host.
func TLSRPT(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	target = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
	if target == "" {
		return nil, nil
	}

	owner := tlsRptOwnerPrefix + target
	txts, err := r.TXT(ctx, owner)
	if err != nil {
		return nil, nil
	}

	record, ok := extractTLSRPT(txts)
	if !ok {
		// No TLSRPT policy is advertised, so there is nothing to dangle.
		return nil, nil
	}

	hosts := tlsRptReportHosts(record)
	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate report hosts within a single target
	for _, host := range hosts {
		if host == "" || host == target || seen[host] {
			continue
		}
		seen[host] = true

		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe, exactly as the
		// DMARC/SPF/MX/CAA/TLSA/MTA-STS/BIMI detectors use it.
		_, chainErr := r.CNAMEChain(ctx, host)
		if !errors.Is(chainErr, resolver.ErrNXDomain) {
			continue // destination resolves (healthy) or lookup indeterminate
		}
		findings = append(findings, finding.Finding{
			Subdomain:     target,
			Vector:        finding.VectorTLSRPT,
			Confidence:    finding.Potential,
			Service:       owner,
			TLSRPTURIHost: host,
			Evidence: "TLSRPT record at " + owner + " rua= report destination host " + host +
				" is NXDOMAIN (dangling SMTP-TLS report destination — reclaimable to " +
				"intercept TLS failure reports and mask an active TLS-downgrade attack)",
		})
	}
	return findings, nil
}

// extractTLSRPT returns the first TXT record that is a TLSRPT policy. Per
// RFC 8460 §3 a TLSRPT record's first field is "v=TLSRPTv1" (the comparison is
// case-insensitive and tolerant of surrounding whitespace). The returned record
// is trimmed of surrounding whitespace; tag values are preserved verbatim (URLs
// and addresses must not be altered).
func extractTLSRPT(txts []string) (string, bool) {
	for _, txt := range txts {
		fields := strings.Split(txt, ";")
		if len(fields) == 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(fields[0])) == tlsRptVersionToken {
			return strings.TrimSpace(txt), true
		}
	}
	return "", false
}

// tlsRptReportHosts extracts the set of report-destination hosts from the rua=
// tag of a TLSRPT record. RFC 8460 §3 defines rua= as a comma-separated list of
// destinations, each either a "mailto:" address or an "https:" URI. For a
// mailto: destination the host is the domain to the right of the last "@"; for
// an https: destination the host is the URL's hostname. Any other scheme (and a
// mailto: with no domain) names no remote host to probe and is skipped. The
// returned hosts are lower-cased.
func tlsRptReportHosts(record string) []string {
	var out []string
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		lower := strings.ToLower(tag)
		val, ok := strings.CutPrefix(lower, "rua=")
		if !ok {
			continue
		}
		// Re-slice the original (case-preserving) value so destination hosts keep
		// their wire form before lower-casing; the prefix match above is on the
		// lower-cased copy only.
		val = tag[len(tag)-len(val):]
		for _, dest := range strings.Split(val, ",") {
			dest = strings.TrimSpace(dest)
			if dest == "" {
				continue
			}
			lowerDest := strings.ToLower(dest)
			switch {
			case strings.HasPrefix(lowerDest, "mailto:"):
				addr := dest[len("mailto:"):]
				at := strings.LastIndexByte(addr, '@')
				if at < 0 || at == len(addr)-1 {
					continue
				}
				if domain := strings.ToLower(strings.TrimSpace(addr[at+1:])); domain != "" {
					out = append(out, domain)
				}
			case strings.HasPrefix(lowerDest, "https:"):
				u, err := url.Parse(dest)
				if err != nil {
					continue
				}
				if host := strings.ToLower(u.Hostname()); host != "" {
					out = append(out, host)
				}
			default:
				// Any other scheme names no remote host to probe.
			}
		}
	}
	return out
}
