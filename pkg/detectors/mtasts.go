package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// mtaStsTXTPrefix is the owner-name prefix for the MTA-STS policy-signal TXT
// record (RFC 8461 §3.1). A domain that opts into SMTP MTA Strict Transport
// Security publishes "v=STSv1; id=..." at _mta-sts.<domain>.
const mtaStsTXTPrefix = "_mta-sts."

// mtaStsPolicyPrefix is the host that serves the MTA-STS policy file. RFC 8461
// §3.3 fixes the policy URL at https://mta-sts.<domain>/.well-known/mta-sts.txt,
// so the policy host is always mta-sts.<domain>. graverobber probes this host for
// existence; the takeover is the dangling host, not the policy file contents.
const mtaStsPolicyPrefix = "mta-sts."

// mtaStsVersionToken is the mandatory version field of a valid MTA-STS TXT
// record. RFC 8461 §3.1 requires the record to begin with "v=STSv1"; a TXT
// record at _mta-sts.<domain> that lacks it is not an MTA-STS policy signal and
// is ignored, keeping the detector from firing on unrelated TXT records that
// happen to share the prefix.
const mtaStsVersionToken = "v=stsv1"

// MTASTS detects a dangling MTA-STS policy host: a domain that advertises
// SMTP MTA-STS (RFC 8461) via a "_mta-sts" TXT policy signal but whose policy
// host "mta-sts.<domain>" is NXDOMAIN.
//
// MTA-STS lets a domain declare that sending mail servers MUST use TLS with a
// valid, matching certificate when delivering to it, defeating the active
// downgrade and MX-redirection attacks that plain opportunistic STARTTLS allows.
// A domain opts in with two coupled pieces of infrastructure:
//
//   - A TXT record at _mta-sts.<domain> carrying "v=STSv1; id=<policy-id>" — the
//     signal that a policy exists (RFC 8461 §3.1).
//   - A policy file served over HTTPS at
//     https://mta-sts.<domain>/.well-known/mta-sts.txt, which lists the
//     authorised MX hosts and the enforcement mode (RFC 8461 §3.2-§3.3). The
//     policy host mta-sts.<domain> is, in practice, a CNAME to a hosting
//     provider (a CDN bucket, a SaaS MTA-STS host, an app platform).
//
// When the policy host is decommissioned — the provider resource is released,
// the hosted zone is deleted, the subdomain is retired — but the _mta-sts TXT
// signal is left behind, the deployment becomes a takeover vector:
//
//   - An attacker who reclaims the dangling mta-sts.<domain> host (re-registers
//     the gone target, re-creates the deleted resource) can serve an arbitrary
//     MTA-STS policy file. A forged "mode: none" policy disables TLS enforcement
//     wholesale, re-opening the downgrade attack MTA-STS exists to close; a
//     forged "mx:" list authorises the attacker's own mail server, steering
//     inbound mail through it under a policy senders trust. This is the same
//     dangling-host pattern the CNAME, MX, SPF-include, DMARC-report, CAA-issuer,
//     and TLSA vectors cover, applied to the MTA-STS control plane.
//
// A domain with no _mta-sts TXT record, or whose policy host still resolves, is
// the healthy case and is intentionally NOT flagged — only an advertised-but-
// orphaned policy host is reported, keeping the vector low-noise and
// pipeline-friendly, consistent with the other DNS-only vectors.
//
// The finding is keyed on the target, carries the policy host in Service and the
// claimable target in CNAME, and is classified Potential: a DNS-only signal
// (NXDOMAIN with no fingerprint match), matching the SPF/DMARC/CAA/TLSA tier.
//
// Algorithm:
//  1. Resolve TXT at _mta-sts.<target>. If no record begins with "v=STSv1",
//     the domain does not advertise MTA-STS — return no findings.
//  2. Probe mta-sts.<target> with CNAMEChain (the authoritative NXDOMAIN probe).
//     ErrNXDomain means the policy host is gone — emit a Potential finding,
//     recording the dangling CNAME target (if any) so the operator sees what to
//     claim.
func MTASTS(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	target = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
	if target == "" {
		return nil, nil
	}

	txts, err := r.TXT(ctx, mtaStsTXTPrefix+target)
	if err != nil {
		return nil, nil
	}
	if !hasMTASTSPolicySignal(txts) {
		// No MTA-STS policy is advertised, so there is nothing to dangle.
		return nil, nil
	}

	policyHost := mtaStsPolicyPrefix + target

	// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe, exactly as the
	// MX/SPF/DMARC/CAA/TLSA detectors use it. The chain (if any) names the
	// dangling target the attacker would reclaim.
	chain, chainErr := r.CNAMEChain(ctx, policyHost)
	if !errors.Is(chainErr, resolver.ErrNXDomain) {
		// Policy host resolves (healthy) or the lookup was indeterminate — no
		// finding either way; this vector reports only a confirmed-gone host.
		return nil, nil
	}

	// The claimable resource is the final CNAME target when the policy host is a
	// CNAME (the common deployment); otherwise the policy host itself is the
	// dangling name.
	claimable := policyHost
	if len(chain) > 0 {
		claimable = chain[len(chain)-1]
	}

	return []finding.Finding{{
		Subdomain:  target,
		Vector:     finding.VectorMTASTS,
		Confidence: finding.Potential,
		Service:    policyHost,
		CNAME:      claimable,
		Evidence: "MTA-STS policy advertised at " + mtaStsTXTPrefix + target +
			" but policy host " + policyHost + " is NXDOMAIN (dangling MTA-STS host — " +
			"reclaimable to serve a forged policy that disables TLS enforcement or redirects mail)",
	}}, nil
}

// hasMTASTSPolicySignal reports whether any TXT record is a valid MTA-STS policy
// signal: per RFC 8461 §3.1 the record's first field must be "v=STSv1". The
// comparison is case-insensitive and tolerant of surrounding whitespace so a
// record published as "V=STSv1 ; id=..." is still recognised.
func hasMTASTSPolicySignal(txts []string) bool {
	for _, t := range txts {
		fields := strings.Split(t, ";")
		if len(fields) == 0 {
			continue
		}
		first := strings.ToLower(strings.TrimSpace(fields[0]))
		if first == mtaStsVersionToken {
			return true
		}
	}
	return false
}
