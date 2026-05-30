package detectors

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// minDKIMKeyBits is the RSA modulus floor below which an inline DKIM key is
// reported as weak. RFC 8301 (Jan 2018) updated RFC 6376 to require signers and
// verifiers to support 1024–4096-bit keys and to deprecate anything shorter:
// "Signers MUST use RSA keys of at least 1024 bits." A 512-bit DKIM key has
// been factored in hours on commodity hardware (the 2012 Zachary Harris
// disclosure against Google, eBay, PayPal, et al.), and 768-bit RSA fell to an
// academic factoring effort in 2009. Any key strictly below 1024 bits lets an
// attacker recover the private key and forge DKIM-passing mail without ever
// touching DNS, so it is a real, exploitable spoofing weakness independent of
// the dangling-CNAME case.
const minDKIMKeyBits = 1024

// staleSelectorYearGap is the minimum age (in whole years, current year minus
// the year embedded in the selector name) at which a published DKIM key is
// reported as a rotation-hint finding. Operators rotate DKIM keys by spinning
// up a new selector containing the rotation date (e.g. "dkim2024",
// "mar2024", "key2024") and pointing mail flow at it; a selector still
// publishing a key two-plus calendar years later is a strong signal that the
// rotation never happened. The threshold is conservative — one year of lag is
// common during a controlled overlap window — but two years exceeds every
// mainstream rotation guidance (M3AAWG Sender Best Common Practices §6,
// NIST SP 800-177r1 §4.5.2, RFC 6376 §3.6.1) and is unambiguously stale.
const staleSelectorYearGap = 2

// selectorYearLow and selectorYearHigh bracket the range of 4-digit substrings
// graverobber treats as a candidate "year embedded in the selector name".
// DKIM was published as RFC 4871 in May 2007; selectors carrying a year before
// 2000 are overwhelmingly false positives (random version numbers, ticket IDs,
// vendor account numbers like "u123" / "u4567"). The upper bound prevents a
// far-future year from being treated as stale during a clock-skew window.
const (
	selectorYearLow  = 2000
	selectorYearHigh = 2100
)

// selectorYearRE captures the first 4-digit substring in a DKIM selector name
// that is not adjacent to another digit on either side — so it matches the
// "2019" in "dkim2019", "mar2019", "2019-key", or "key-2019-rot", but not the
// embedded "2019" in "u20191234" (a vendor account number) or "1234567" (a
// long opaque selector). The non-digit boundary (or string edge) on each side
// is what filters out the long-numeric vendor selectors that would otherwise
// dominate the false-positive surface.
var selectorYearRE = regexp.MustCompile(`(?:^|[^0-9])([0-9]{4})(?:[^0-9]|$)`)

// nowFn is the clock used to compute the current year for the rotation-hint
// check. It is var so tests can pin a deterministic "now" without depending on
// the real calendar (the staleness threshold rolls forward each January).
var nowFn = func() time.Time { return time.Now().UTC() }

// DefaultDKIMSelectors is the list of DKIM selectors graverobber probes when no
// override is supplied. DKIM public keys live at <selector>._domainkey.<domain>;
// organizations frequently publish them as CNAMEs delegating the key to an ESP
// (e.g. s1._domainkey.example.com → s1.domainkey.sendgrid.net). The selector
// name is not discoverable from DNS alone, so a passive scanner can only cover
// the common, well-known selectors used by the major email service providers.
//
// Sources: provider onboarding docs (SendGrid s1/s2, Google "google", Mailchimp
// k1, Amazon SES-style, Microsoft "selector1"/"selector2") and the SubdoMailing
// writeup (Guardio Labs, 2024).
var DefaultDKIMSelectors = []string{
	"default",   // generic / self-hosted
	"google",    // Google Workspace
	"k1",        // Mailchimp / Mandrill
	"k2",        // Mailchimp (secondary)
	"s1",        // SendGrid (primary)
	"s2",        // SendGrid (secondary)
	"selector1", // Microsoft 365
	"selector2", // Microsoft 365
	"dkim",      // common self-hosted name
	"mail",      // common self-hosted name
	"smtp",      // common self-hosted name
}

// DKIM detects two DKIM-selector weaknesses, both of which let an attacker sign
// mail that passes DKIM verification for the target domain.
//
// Algorithm:
//  1. For each selector, build the FQDN <selector>._domainkey.<target>.
//  2. Resolve its CNAME (resolver.RawCNAME).
//     a. If the selector is delegated via CNAME, follow the target with
//     CNAMEChain; if the target is NXDOMAIN the ESP resource is gone and the
//     selector is reclaimable — emit a Confidence=Confirmed VectorDKIM
//     finding (the original Rank 6 dangling-CNAME case).
//     b. If the selector is NOT delegated, look up its TXT record and parse the
//     inline DKIM key. If the published RSA public key is below the RFC 8301
//     1024-bit floor (minDKIMKeyBits), emit a Confidence=Likely VectorDKIM
//     finding carrying DKIMKeyBits — a short key can be factored to recover
//     the private key and forge DKIM-passing mail.
//
// The two cases are mutually exclusive per selector: a selector either delegates
// via CNAME or publishes a key inline, never both. selectors overrides
// DefaultDKIMSelectors when non-empty (the --selectors flag). Each selector is
// probed independently; one finding does not short-circuit the others.
func DKIM(ctx context.Context, target string, r *resolver.Resolver, selectors []string) ([]finding.Finding, error) {
	if len(selectors) == 0 {
		selectors = DefaultDKIMSelectors
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate selectors within a single target

	for _, sel := range selectors {
		sel = strings.ToLower(strings.TrimSpace(sel))
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true

		host := sel + "._domainkey." + target

		cname, err := r.RawCNAME(ctx, host)
		if err == nil && cname != "" {
			// The selector delegates via CNAME. Check whether the delegated
			// target still exists. NXDOMAIN means the ESP resource is gone and
			// reclaimable.
			_, chainErr := r.CNAMEChain(ctx, cname)
			if errors.Is(chainErr, resolver.ErrNXDomain) {
				findings = append(findings, finding.Finding{
					Subdomain:    host,
					Vector:       finding.VectorDKIM,
					Confidence:   finding.Confirmed,
					CNAME:        cname,
					DKIMSelector: sel,
					Evidence:     "DKIM selector CNAME target is NXDOMAIN — ESP resource reclaimable",
				})
				continue
			}
			// Live CNAME delegation — the selector still publishes a key via the
			// ESP. A stale-year selector name here is a rotation-hint signal:
			// the published key has been live under the same selector across
			// the entire stale window. Fire the rotation-hint check, then move
			// on (no inline-key check applies to a CNAME-delegated selector).
			if year, stale := staleSelectorYear(sel, nowFn()); stale {
				findings = append(findings, staleDKIMFinding(host, sel, year))
			}
			continue
		}

		// Not delegated via CNAME. The selector may publish a DKIM key inline as
		// a TXT record. Fetch it and check the RSA modulus size: a key below the
		// RFC 8301 floor is factorable and lets an attacker forge signatures.
		txts, txtErr := r.TXT(ctx, host)
		if txtErr != nil || len(txts) == 0 {
			continue
		}
		if !isDKIMKeyRecord(txts) {
			continue
		}
		if bits, ok := weakDKIMKeyBits(txts); ok {
			findings = append(findings, finding.Finding{
				Subdomain:    host,
				Vector:       finding.VectorDKIM,
				Confidence:   finding.Likely,
				DKIMSelector: sel,
				DKIMKeyBits:  bits,
				Evidence: fmt.Sprintf(
					"DKIM selector publishes a %d-bit RSA key (below the RFC 8301 %d-bit floor) — factorable, forgeable signatures",
					bits, minDKIMKeyBits),
			})
		}
		// Rotation-hint fires independently of weak-key: a healthy 2048-bit
		// key under a stale-named selector is still a stale key.
		if year, stale := staleSelectorYear(sel, nowFn()); stale {
			findings = append(findings, staleDKIMFinding(host, sel, year))
		}
	}

	return findings, nil
}

// weakDKIMKeyBits inspects the TXT records published at a DKIM selector and
// reports the RSA modulus size when it is below minDKIMKeyBits. The bool result
// is true only for a parsed RSA key that is genuinely too short; it is false for
// a non-DKIM record, a revoked key (empty p=), a non-RSA key type, a key that
// meets the floor, or any record that cannot be parsed (graverobber never
// reports a finding it cannot substantiate).
//
// A DKIM key record is a TXT value of semicolon-separated tag=value pairs, e.g.
//
//	v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo or PKCS#1 public key>
//
// The p= value is the base64-encoded public key. Per RFC 6376 the key is a
// DER-encoded SubjectPublicKeyInfo (X.509), though some signers emit a bare
// PKCS#1 RSAPublicKey; weakDKIMKeyBits accepts either.
func weakDKIMKeyBits(txts []string) (int, bool) {
	for _, txt := range txts {
		tags := parseDKIMTags(txt)
		// A DKIM key record either carries v=DKIM1 or, very commonly, omits v=
		// and is identified by the presence of p=. Require a p= tag; if v= is
		// present it must say DKIM1 (case-insensitive) to avoid misreading an
		// unrelated TXT record that happens to contain a "p=" substring.
		p, hasP := tags["p"]
		if !hasP {
			continue
		}
		if v, hasV := tags["v"]; hasV && !strings.EqualFold(v, "DKIM1") {
			continue
		}
		// k= defaults to "rsa" when absent (RFC 6376 §3.6.1). Only RSA keys have
		// a meaningful modulus-size weakness here; ed25519 keys are fixed-size
		// and out of scope for this check.
		if k, hasK := tags["k"]; hasK && !strings.EqualFold(k, "rsa") {
			continue
		}
		if p == "" {
			// Empty p= is an explicitly revoked key, not a weak key.
			continue
		}
		bits, ok := rsaPublicKeyBits(p)
		if !ok {
			continue
		}
		if bits < minDKIMKeyBits {
			return bits, true
		}
	}
	return 0, false
}

// parseDKIMTags splits a DKIM TXT record into its tag=value map. Tag names are
// lower-cased; whitespace around tags and values is trimmed. Values are kept
// verbatim (base64 in p= must not be altered). A bare tag with no '=' is
// ignored.
func parseDKIMTags(txt string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		if key == "" {
			continue
		}
		// The p= value may legitimately contain internal whitespace (folded
		// base64); strip all whitespace so base64 decoding succeeds.
		val := strings.TrimSpace(kv[1])
		if key == "p" {
			val = strings.Join(strings.Fields(val), "")
		}
		tags[key] = val
	}
	return tags
}

// rsaPublicKeyBits base64-decodes a DKIM p= value and returns the RSA modulus
// bit length. It accepts both the RFC 6376 DER SubjectPublicKeyInfo encoding
// (the common case) and a bare PKCS#1 RSAPublicKey. The bool is false when the
// value is not valid base64, not a parseable RSA public key, or not RSA.
func rsaPublicKeyBits(p string) (int, bool) {
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		// Some records use base64 without padding; try the raw encoding too.
		der, err = base64.RawStdEncoding.DecodeString(p)
		if err != nil {
			return 0, false
		}
	}

	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub.N.BitLen(), true
		}
		return 0, false // parsed, but not an RSA key (e.g. ed25519)
	}

	// Fall back to a bare PKCS#1 RSAPublicKey, which some signers publish.
	if rsaPub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rsaPub.N.BitLen(), true
	}

	return 0, false
}

// isDKIMKeyRecord reports whether any TXT value at the selector looks like a
// DKIM key record (carries a p= tag and, if v= is present, says DKIM1). It is
// the gate the rotation-hint and weak-key checks share so an unrelated TXT
// record (a domain-verification token, an SPF macro stash) at the same name
// does not trigger a DKIM finding.
func isDKIMKeyRecord(txts []string) bool {
	for _, txt := range txts {
		tags := parseDKIMTags(txt)
		if _, hasP := tags["p"]; !hasP {
			continue
		}
		if v, hasV := tags["v"]; hasV && !strings.EqualFold(v, "DKIM1") {
			continue
		}
		return true
	}
	return false
}

// staleSelectorYear extracts a 4-digit year embedded in a DKIM selector name
// and reports it when the gap between that year and now is at least
// staleSelectorYearGap whole calendar years. The boundary regex skips long
// numeric runs (vendor account ids like u20191234) so only standalone years
// match. Only the first match in the selector is considered — selector names
// rarely encode more than one date, and a deterministic single-result rule
// keeps the finding's evidence string unambiguous.
func staleSelectorYear(selector string, now time.Time) (int, bool) {
	m := selectorYearRE.FindStringSubmatch(selector)
	if len(m) < 2 {
		return 0, false
	}
	year, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	if year < selectorYearLow || year > selectorYearHigh {
		return 0, false
	}
	if now.Year()-year < staleSelectorYearGap {
		return 0, false
	}
	return year, true
}

// staleDKIMFinding constructs the rotation-hint VectorDKIM finding. Confidence
// is Potential — the staleness is a strong hint, not a cryptographic proof of
// weakness on its own (the key may still be modern-strength), so it sits in
// the same tier as the SPF / DMARC / CAA misconfiguration findings.
func staleDKIMFinding(host, sel string, year int) finding.Finding {
	return finding.Finding{
		Subdomain:     host,
		Vector:        finding.VectorDKIM,
		Confidence:    finding.Potential,
		DKIMSelector:  sel,
		DKIMStaleYear: year,
		Evidence: fmt.Sprintf(
			"DKIM selector name embeds the year %d (%d+ years stale) — published key has not been rotated against the M3AAWG / NIST SP 800-177 annual-rotation guidance; a past key compromise stays exploitable",
			year, staleSelectorYearGap),
	}
}
