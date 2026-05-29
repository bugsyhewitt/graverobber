package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// maxSPFDepth bounds recursive include: resolution. RFC 7208 caps SPF DNS
// lookups at 10; the build step should enforce that limit here.
const maxSPFDepth = 10

// SPF detects two classes of SPF weakness on a domain: a dangling reference
// (the SubdoMailing takeover) and a permissive "all" mechanism.
//
// Dangling-reference sub-case. Four SPF directives reference an external
// domain and are therefore equally exploitable when that domain is unregistered:
//
//   - include:<domain> — a mechanism (RFC 7208 §5.2) that pulls in another
//     domain's SPF record; a passing result there contributes to the policy.
//   - redirect=<domain> — a modifier (RFC 7208 §6.1) that designates another
//     domain's SPF record as THE policy for the current domain when no
//     mechanism matches. A dangling redirect= is arguably higher-impact than a
//     dangling include: because the redirect target's policy replaces the local
//     one wholesale.
//   - a:<domain> — a mechanism (RFC 7208 §5.3) that passes when the sender's IP
//     matches an A/AAAA record of the named domain. With an explicit domain
//     argument it authorises that external domain's address records to send mail
//     as the target.
//   - mx:<domain> — a mechanism (RFC 7208 §5.4) that passes when the sender's IP
//     matches an A/AAAA record of one of the named domain's MX hosts. With an
//     explicit domain argument it authorises that external domain's mail-host
//     addresses to send as the target.
//
// All four yield the SubdoMailing takeover (Guardio Labs, Feb 2024): an attacker
// who registers the claimable target domain controls the SPF evaluation and can
// authorise spoofed mail. For a:/mx: the attacker simply points the reclaimed
// domain's A (or MX) records at their own sending host and every message they
// send passes SPF for the target. The claimable domain is carried in SPFInclude.
//
// Bare a/mx mechanisms with NO ":domain" argument (e.g. "a", "a/24", "mx",
// "mx//64") reference the TARGET's own A/MX records, not an external domain, so
// they are not a takeover surface and are intentionally NOT extracted.
//
// Permissive-policy sub-case. The "all" mechanism is the catch-all that ends a
// well-formed SPF record (RFC 7208 §5.1); its qualifier decides the result for
// any sender not matched by an earlier mechanism: "-all" (Fail, the secure
// default), "~all" (SoftFail), "?all" (Neutral), and "+all" (Pass). A "+all"
// policy — or a bare "all", which §4.6.2 treats as "+all" — explicitly
// authorises EVERY host on the internet to send mail as the domain, which
// defeats the entire purpose of publishing SPF: the domain is fully spoofable
// and any forged mail passes SPF alignment. This mirrors the DMARC p=none
// weak-policy sub-case: a present-but-toothless email-authentication record. The
// offending token is carried in SPFAll and the finding is keyed on the target
// itself (not an external domain), so it is emitted once per record.
//
// Algorithm:
//  1. Resolve TXT records (resolver.TXT) and extract the SPF policy.
//  2. If the record's all mechanism qualifies as Pass, emit a Potential
//     permissive finding keyed on the target.
//  3. Parse include: mechanisms and the redirect= modifier, recursing up to
//     maxSPFDepth; for each referenced domain that is NXDOMAIN (claimable), emit
//     a Potential dangling finding.
func SPF(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	txts, err := r.TXT(ctx, target)
	if err != nil || len(txts) == 0 {
		return nil, nil
	}

	spfRecord := extractSPF(txts)
	if spfRecord == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// Permissive-policy sub-case: a Pass-qualified "all" mechanism authorises any
	// sender. Keyed on the target itself, so it is emitted once per record. This
	// is checked only against the apex record (not recursed includes): the all
	// mechanism that governs the scanned name is the one in its own record.
	if token := spfPermissiveAll(spfRecord); token != "" {
		findings = append(findings, finding.Finding{
			Subdomain:  target,
			Vector:     finding.VectorSPF,
			Confidence: finding.Potential,
			SPFAll:     token,
			Evidence:   "SPF policy ends in " + token + " (Pass — authorises any host to send mail as the domain; domain is spoofable)",
		})
	}

	visited := map[string]bool{target: true}
	dangling, _ := spfIncludes(ctx, spfRecord, r, visited, 0)
	findings = append(findings, dangling...)
	return findings, nil
}

// spfPermissiveAll reports the offending "all" mechanism token when an SPF
// record's catch-all qualifies as Pass, or "" when it does not. An "all"
// mechanism may carry a qualifier prefix: "+" (Pass), "-" (Fail), "~" (SoftFail),
// or "?" (Neutral). A missing qualifier defaults to "+" (Pass) per RFC 7208
// §4.6.2, so a bare "all" is as permissive as "+all". Only "+all" / "all" are
// flagged; "-all", "~all", and "?all" are secure-to-cautious and never flagged.
// The mechanism name is matched case-insensitively (qualifiers are not letters).
func spfPermissiveAll(record string) string {
	for _, field := range strings.Fields(record) {
		switch {
		case strings.EqualFold(field, "all"), strings.EqualFold(field, "+all"):
			return field
		}
	}
	return ""
}

// extractSPF returns the first TXT record that looks like an SPF policy.
func extractSPF(txts []string) string {
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1 ") || t == "v=spf1" {
			return t
		}
	}
	return ""
}

// spfReference is a single external domain referenced by an SPF record, tagged
// with the directive that referenced it so the finding's evidence can name it.
type spfReference struct {
	domain    string // lower-cased referenced domain
	directive string // the directive that referenced it: "include:", "redirect=", "a:", or "mx:"
}

// recursable reports whether the referenced domain hosts its own SPF policy that
// should be followed. include: and redirect= name another SPF record and so are
// recursed; a:/mx: name a host whose ADDRESS records are authorised — they do not
// pull in a downstream SPF policy, so their dangling check is terminal.
func (ref spfReference) recursable() bool {
	return ref.directive == "include:" || ref.directive == "redirect="
}

// spfReferences extracts the external domains a single SPF record points at via
// the include:, a:, and mx: mechanisms and the redirect= modifier, in record
// order. A redirect= modifier may legally appear anywhere in the record but
// applies only when no mechanism matches; for takeover detection its position is
// irrelevant — what matters is whether its target is claimable.
//
// For a:/mx: only the explicit-domain form ("a:domain", "mx:domain", optionally
// with a trailing "/cidr" or "//cidr" dual-CIDR suffix) references an external
// domain. A bare "a"/"mx" (or "a/24") points at the target's own records and is
// not a takeover surface, so it is skipped. A mechanism may carry a qualifier
// prefix ("+", "-", "~", "?"), which is stripped before matching.
func spfReferences(record string) []spfReference {
	var refs []spfReference
	for _, field := range strings.Fields(record) {
		// redirect= is a modifier; it never carries a qualifier prefix.
		if domain, ok := strings.CutPrefix(field, "redirect="); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain), directive: "redirect="})
			continue
		}

		// Mechanisms may be prefixed with a qualifier; strip it before matching.
		mech := strings.TrimLeft(field, "+-~?")

		if domain, ok := strings.CutPrefix(mech, "include:"); ok {
			refs = append(refs, spfReference{domain: normaliseSPFDomain(domain), directive: "include:"})
			continue
		}
		if domain, ok := spfDualCIDRDomain(mech, "a:"); ok {
			refs = append(refs, spfReference{domain: domain, directive: "a:"})
			continue
		}
		if domain, ok := spfDualCIDRDomain(mech, "mx:"); ok {
			refs = append(refs, spfReference{domain: domain, directive: "mx:"})
		}
	}
	return refs
}

// spfDualCIDRDomain extracts the external domain from an "a:" or "mx:" mechanism
// of the form "<prefix>domain", "<prefix>domain/24", or "<prefix>domain//64"
// (RFC 7208 §5.3/§5.4 dual-CIDR-length syntax). It returns ("", false) when mech
// does not start with prefix or carries no domain (a bare "a"/"mx", which the
// CutPrefix on "a:"/"mx:" already excludes). The trailing /ip4-cidr or //ip6-cidr
// is stripped — it constrains the matched IP range, not which domain is named.
func spfDualCIDRDomain(mech, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(mech, prefix)
	if !ok {
		return "", false
	}
	// Strip a trailing dual-CIDR suffix ("/24", "//64", or "/24//64"). The IPv4
	// CIDR (if any) is delimited by the first "/"; everything from there on is
	// CIDR syntax, not part of the domain.
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	domain := normaliseSPFDomain(rest)
	if domain == "" {
		return "", false
	}
	return domain, true
}

// normaliseSPFDomain lower-cases and trims an SPF-referenced domain.
func normaliseSPFDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

// spfIncludes parses include: mechanisms and the redirect= modifier from a
// single SPF record and recurses into the policies of domains that still exist.
func spfIncludes(ctx context.Context, record string, r *resolver.Resolver, visited map[string]bool, depth int) ([]finding.Finding, error) {
	if depth >= maxSPFDepth {
		return nil, nil
	}

	var findings []finding.Finding
	for _, ref := range spfReferences(record) {
		domain := ref.domain
		if domain == "" || visited[domain] {
			continue
		}
		visited[domain] = true

		// Use CNAMEChain (TypeA query) as the authoritative NXDOMAIN probe.
		// TXT returning (nil, nil) is ambiguous — domain may exist with no TXT.
		// ErrNXDomain from CNAMEChain means the domain is definitively gone.
		_, aErr := r.CNAMEChain(ctx, domain)
		if errors.Is(aErr, resolver.ErrNXDomain) {
			findings = append(findings, finding.Finding{
				Subdomain:  domain,
				Vector:     finding.VectorSPF,
				Confidence: finding.Potential,
				SPFInclude: domain,
				Evidence:   "SPF " + ref.directive + " domain is NXDOMAIN (claimable)",
			})
			continue
		}

		// a:/mx: mechanisms authorise the domain's address records directly; they
		// do not name a downstream SPF policy, so there is nothing to recurse into.
		if !ref.recursable() {
			continue
		}

		// Domain exists; try to recurse into its own SPF policy.
		txts, err := r.TXT(ctx, domain)
		if err != nil || len(txts) == 0 {
			continue
		}
		if included := extractSPF(txts); included != "" {
			sub, _ := spfIncludes(ctx, included, r, visited, depth+1)
			findings = append(findings, sub...)
		}
	}
	return findings, nil
}
