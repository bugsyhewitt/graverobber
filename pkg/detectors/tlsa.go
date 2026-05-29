package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// tlsaSMTPPrefix is the DANE-for-SMTP owner-name prefix (RFC 7672 §2). A mail
// exchanger that opts into DANE publishes its TLSA pin at
// _25._tcp.<mxhost> — port 25 (SMTP), TCP. graverobber probes this canonical
// location for each MX host; other ports/protocols are out of scope for the
// mail-takeover vector this detector defends.
const tlsaSMTPPrefix = "_25._tcp."

// TLSA detects a dangling DANE pin: a domain that publishes a TLSA record
// (RFC 6698) for a mail exchanger whose MX host is NXDOMAIN.
//
// DANE for SMTP (RFC 7672) lets a domain pin its mail server's TLS certificate
// in DNS at _25._tcp.<mxhost>, secured by DNSSEC, so a sending MTA can verify
// the certificate without relying on the public CA system. The pin is only as
// healthy as the host it covers. When the MX host is removed (the mail vendor is
// decommissioned, the hosted zone is deleted, the subdomain is retired) but the
// TLSA record is left behind, two things happen:
//
//   - Every DANE-validating sender hard-fails delivery to the domain: RFC 7672
//     §2.2 makes a published-but-unmatchable pin a permanent TLS failure, so the
//     orphaned record silently black-holes inbound mail.
//   - Because DANE mandates DNSSEC, the stale pin is authenticated. An attacker
//     who reclaims the gone mail host (re-registers the domain, or re-creates the
//     deleted hosted zone) can stand up an SMTP server presenting a certificate
//     that matches the still-published TLSA association and be trusted by every
//     DANE sender — a DANE-blessed mail interception path.
//
// This mirrors the dangling-record pattern the MX, SPF-include, DMARC-report,
// and CAA-issuer vectors already cover, extended to the DANE control plane. The
// finding is keyed on the target, carries the DANE owner name in TLSAName and
// the dangling mail host in MXHosts, and is classified Potential: it is a
// DNS-only signal (NXDOMAIN with no fingerprint match), consistent with the
// other DNS-only vectors.
//
// A domain with no TLSA records, or whose TLSA-pinned MX hosts all resolve, is
// the healthy case and is intentionally NOT flagged — only a present-but-orphaned
// pin is reported, keeping the vector low-noise and pipeline-friendly.
//
// Algorithm:
//  1. Resolve MX records for target. If none, return no findings.
//  2. For each MX host, query TLSA at _25._tcp.<mxhost>. If no pin, skip.
//  3. If a pin exists, probe the MX host with CNAMEChain; ErrNXDomain means the
//     pinned mail host is gone — emit a Potential dangling-DANE finding.
func TLSA(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	mxHosts, err := r.MX(ctx, target)
	if err != nil || len(mxHosts) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate by MX host within a single target

	for _, mx := range mxHosts {
		mx = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(mx, ".")))
		if mx == "" || seen[mx] {
			continue
		}
		seen[mx] = true

		owner := tlsaSMTPPrefix + mx
		count, tErr := r.TLSA(ctx, owner)
		if tErr != nil || count == 0 {
			// No DANE pin for this mail host (or a transient lookup error) — there
			// is nothing to dangle, so this host is not a TLSA finding.
			continue
		}

		// A pin exists. Is the host it covers gone? CNAMEChain (TypeA) is the
		// authoritative NXDOMAIN probe, exactly as the MX/SPF/DMARC/CAA detectors
		// use it.
		_, chainErr := r.CNAMEChain(ctx, mx)
		if errors.Is(chainErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  target,
				Vector:     finding.VectorTLSA,
				Confidence: finding.Potential,
				TLSAName:   owner,
				MXHosts:    []string{mx},
				Evidence:   "DANE TLSA pin published at " + owner + " but MX host " + mx + " is NXDOMAIN (dangling DANE pin — hard-fails inbound mail; reclaimable for DANE-trusted interception)",
			})
		}
	}

	return findings, nil
}
