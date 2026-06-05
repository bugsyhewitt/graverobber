package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// autodiscoverHosts are the well-known mail-client autoconfiguration hostnames
// graverobber probes for a dangling CNAME. Each is a host that mail clients
// query automatically — without any user action — to discover a domain's mail
// server settings:
//
//   - "autodiscover.<domain>": the Microsoft Exchange / Outlook Autodiscover
//     endpoint (MS-OXDSCLI). Outlook and the ActiveSync clients on every major
//     mobile platform probe https://autodiscover.<domain>/autodiscover/
//     autodiscover.xml during account setup. A hosted-Exchange / Microsoft-365
//     tenant publishes it as a CNAME to autodiscover.outlook.com (or a
//     third-party mail host).
//   - "autoconfig.<domain>": the Mozilla Thunderbird autoconfiguration endpoint
//     (and the de-facto cross-client convention). Clients probe
//     https://autoconfig.<domain>/mail/config-v1.1.xml during setup. It is
//     likewise commonly a CNAME to a mail-hosting provider.
//
// These two cover the autoconfiguration plane that the apex-CNAME fingerprint,
// the DNS-zone (NS/AXFR), and the email-authentication-record (SPF/DKIM/DMARC/
// MTA-STS/TLSRPT/BIMI) vectors do not — none of them probe the host a mail
// client auto-resolves to fetch its server settings.
var autodiscoverHosts = []string{"autodiscover.", "autoconfig."}

// Autodiscover detects a dangling mail-client autoconfiguration host: a domain
// whose autodiscover.<domain> (Microsoft Exchange/Outlook) or
// autoconfig.<domain> (Mozilla Thunderbird and the general convention) name is
// published but resolves to NXDOMAIN.
//
// Mail clients fetch their incoming/outgoing server settings (IMAP/POP/SMTP
// host, port, TLS mode, and the username/auth scheme) automatically from these
// hosts during account setup — Outlook and mobile ActiveSync clients from
// autodiscover.<domain>, Thunderbird from autoconfig.<domain>. The hosts are, in
// practice, a CNAME to a hosting provider (autodiscover.outlook.com for
// Microsoft 365, or a third-party mail host).
//
// When an organisation migrates off a hosted mail tenant — the Microsoft 365
// tenant is closed, the third-party mail host is decommissioned, the hosted zone
// is deleted — but the autodiscover/autoconfig CNAME is left behind, the
// deployment becomes a takeover vector:
//
//   - An attacker who reclaims the dangling host (re-registers the gone CNAME
//     target, re-creates the released resource) serves a forged
//     autoconfiguration payload. Because the client fetches it automatically and
//     trusts it to configure the account, the attacker hands every auto-probing
//     client an attacker-controlled IMAP/SMTP server and a prompt for the user's
//     mailbox credentials — a silent, high-yield credential-harvesting and
//     mail-interception path. This is the same dangling-host pattern the CNAME,
//     MX, MTA-STS, and TLSRPT vectors cover, applied to the mail-client
//     autoconfiguration plane.
//
// A domain whose autodiscover/autoconfig hosts still resolve, or that publishes
// neither, is the healthy case and is intentionally NOT flagged — only an
// NXDOMAIN host is reported, keeping the vector low-noise and pipeline-friendly,
// consistent with the other DNS-only vectors.
//
// The detector first confirms the target apex itself resolves (is a live
// domain). If the apex is NXDOMAIN the whole domain is dead — its
// autodiscover/autoconfig hosts are then trivially NXDOMAIN too, but that is not
// an autoconfiguration-host takeover (there is no live organisation whose mail
// clients would auto-probe them), so the detector emits nothing rather than a
// low-value finding on a dead domain. This apex gate keeps the vector to the
// genuine takeover precondition — a live organisation with a decommissioned
// mail-autoconfiguration host — mirroring the signal-first gating the MTA-STS,
// TLSRPT, and BIMI detectors get from requiring an advertised TXT record.
//
// Each finding is keyed on the target, carries the dangling autoconfiguration
// host in Service and the claimable CNAME target (or the host itself) in CNAME,
// and is classified Potential: a DNS-only signal (NXDOMAIN with no fingerprint
// match), matching the SPF/DMARC/CAA/TLSA/MTA-STS/BIMI/TLSRPT tier.
//
// Algorithm:
//  1. Confirm the target apex resolves. If CNAMEChain(target) is ErrNXDomain the
//     domain is dead — return no findings.
//  2. For each well-known autoconfiguration host (autodiscover.<target>,
//     autoconfig.<target>), probe it with CNAMEChain (the authoritative NXDOMAIN
//     probe). ErrNXDomain means the host is gone — emit a Potential finding,
//     recording the dangling CNAME target (if any) so the operator sees what to
//     claim. A host that resolves, or whose lookup is indeterminate, is skipped.
func Autodiscover(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	target = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
	if target == "" {
		return nil, nil
	}

	// Apex gate: only a live domain has mail clients that auto-probe its
	// autoconfiguration hosts. A NXDOMAIN apex is a dead domain, not an
	// autoconfiguration-host takeover, so it is not flagged here.
	if _, apexErr := r.CNAMEChain(ctx, target); errors.Is(apexErr, resolver.ErrNXDomain) {
		return nil, nil
	}

	var findings []finding.Finding
	for _, prefix := range autodiscoverHosts {
		host := prefix + target

		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe, exactly as the
		// MX/SPF/DMARC/CAA/TLSA/MTA-STS/BIMI/TLSRPT detectors use it. The chain
		// (if any) names the dangling target the attacker would reclaim.
		chain, chainErr := r.CNAMEChain(ctx, host)
		if !errors.Is(chainErr, resolver.ErrNXDomain) {
			// Host resolves (healthy) or the lookup was indeterminate — no finding
			// either way; this vector reports only a confirmed-gone host.
			continue
		}

		// The claimable resource is the final CNAME target when the host is a
		// CNAME (the common deployment); otherwise the host itself is the
		// dangling name.
		claimable := host
		if len(chain) > 0 {
			claimable = chain[len(chain)-1]
		}

		findings = append(findings, finding.Finding{
			Subdomain:  target,
			Vector:     finding.VectorAutodiscover,
			Confidence: finding.Potential,
			Service:    host,
			CNAME:      claimable,
			Evidence: "mail-client autoconfiguration host " + host +
				" is NXDOMAIN (dangling autodiscover/autoconfig host — reclaimable to " +
				"serve a forged autoconfiguration payload that points mail clients at an " +
				"attacker-controlled IMAP/SMTP server and harvests mailbox credentials)",
		})
	}
	return findings, nil
}
