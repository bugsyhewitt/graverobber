package engine

import (
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// The NS-takeover class (D7 / §9).
//
// A dangling NS delegation — the subdomain's nameserver records point at a
// managed-DNS provider zone that has been deleted and can be re-registered —
// grants control of the ENTIRE subdomain zone (every A/AAAA, MX, TXT, wildcard,
// and sub-delegation under it), not just one CNAME record's content. That is
// categorically worse than a CNAME content takeover, so graverobber treats it as
// its own higher-severity class: rule `takeover.ns.<provider>`, severity
// `critical` (vs `high` for the CNAME content class). Flattening NS into the
// CNAME takeover class (A8) understates the impact by a whole tier.
//
// graverobber already detects dangling/lame NS delegations in pkg/detectors
// (the mature NS detector, which distinguishes the zone-deleted and partial-lame
// sub-cases and scores a known takeoverable provider as CONFIRMED). This package
// does NOT re-enumerate or re-detect (A9). Instead PromoteNS lifts an existing
// NS finding into the critical takeover.ns class — stamping the rule, the
// critical severity, the detected state, and the whole-zone blast radius — so the
// confirmation pipeline and downstream enrichment see NS as the distinct class
// the packet mandates.

// nsProviderSlug maps a provider/nameserver label to a short, stable rule slug
// used in `takeover.ns.<slug>`. It reuses the same sla slugification the CNAME
// class uses (lower-case, runs of separators collapsed to one hyphen) and then
// strips a trailing " (ns)" annotation the detector may attach.
func nsProviderSlug(provider string) string {
	p := strings.TrimSpace(provider)
	p = strings.TrimSuffix(strings.ToLower(p), "(ns)")
	slug := adapterSlug(p)
	if slug == "" {
		return "unknown"
	}
	return slug
}

// NSRule returns the takeover rule for a dangling-NS finding against the given
// provider label, e.g. "takeover.ns.route53". An empty/unknown provider yields
// "takeover.ns.unknown".
func NSRule(provider string) string {
	return "takeover.ns." + nsProviderSlug(provider)
}

// NSBlastRadius is the fixed, categorical blast radius of a whole-zone NS
// takeover. Unlike a CNAME content takeover (characterized per-FQDN in
// pkg/confirm), an NS takeover always grants the entire zone, so the blast radius
// is structural, not host-dependent.
const NSBlastRadius = "whole-zone control: every record under the delegation (A/AAAA, CNAME, wildcards), " +
	"MX + SPF/DKIM/DMARC (email spoofing & interception), and all sub-delegations — categorically worse than a single CNAME content takeover"

// PromoteNS lifts a dangling-NS finding (finding.VectorNS, produced by the mature
// pkg/detectors NS detector) into graverobber's critical takeover.ns class. It
// returns a copy with:
//
//   - Rule       = takeover.ns.<provider>
//   - State      = detected
//   - Severity   = critical (whole-zone control)
//   - Confidence preserved from the detector (CONFIRMED when a known takeoverable
//     provider was matched, POTENTIAL otherwise) — the detection certainty is
//     unchanged; only the takeover classification is added.
//
// A finding whose Vector is not VectorNS is returned unchanged (defensive: this
// helper is a no-op on anything but an NS finding). PromoteNS does not perform
// any I/O — it is a pure classification step over an already-detected finding,
// honoring A9 (no re-enumeration).
func PromoteNS(f finding.Finding) finding.Finding {
	if f.Vector != finding.VectorNS {
		return f
	}
	out := f
	out.Rule = NSRule(f.Service)
	out.State = finding.StateDetected
	out.Severity = finding.SeverityCritical
	if strings.TrimSpace(out.Evidence) == "" {
		out.Evidence = "dangling NS delegation (whole-zone takeover candidate)"
	}
	return out
}

// IsNSTakeover reports whether a finding is in the NS-takeover class (a
// takeover.ns.* rule). Used by the confirmer/enrichment to apply the critical
// severity and the whole-zone blast radius and, where a clean zone-claim adapter
// exists, the (higher-risk) NS confirmation path.
func IsNSTakeover(f finding.Finding) bool {
	return strings.HasPrefix(f.Rule, "takeover.ns.")
}
