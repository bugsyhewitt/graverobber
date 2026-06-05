package detectors

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

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

// mtaStsPolicyPath is the fixed well-known path for the MTA-STS policy file.
// RFC 8461 §3.3 requires it to be served at exactly this URL path.
const mtaStsPolicyPath = "/.well-known/mta-sts.txt"

// mtaStsVersionToken is the mandatory version field of a valid MTA-STS TXT
// record. RFC 8461 §3.1 requires the record to begin with "v=STSv1"; a TXT
// record at _mta-sts.<domain> that lacks it is not an MTA-STS policy signal and
// is ignored, keeping the detector from firing on unrelated TXT records that
// happen to share the prefix.
const mtaStsVersionToken = "v=stsv1"

// mtaStsPolicyFetchTimeout caps the HTTP GET of the policy file at a small,
// single-shot budget. The mode check is an active probe; it must be bounded so
// a slow host cannot stall a worker goroutine.
const mtaStsPolicyFetchTimeout = 8 * time.Second

// mtaStsPolicyMaxBytes caps the policy file read. A legitimate MTA-STS policy
// is a handful of key:value lines; 64 KiB is more than enough and prevents a
// hostile host from streaming multi-MB bodies.
const mtaStsPolicyMaxBytes = 64 << 10 // 64 KiB

// MTASTS detects two sub-cases of MTA-STS misconfiguration:
//
//  1. Dangling policy host: the domain advertises SMTP MTA-STS via a "_mta-sts"
//     TXT policy signal but its policy host "mta-sts.<domain>" is NXDOMAIN. An
//     attacker who reclaims the dangling host can serve a forged MTA-STS policy,
//     disabling TLS enforcement or steering inbound mail.
//
//  2. Weak policy mode: the policy host resolves and the policy file is
//     reachable, but its "mode:" field is "none" or "testing" — not "enforce".
//     Both of these are the same disposition class as DMARC p=none: TLS
//     enforcement is absent ("none") or advisory-only ("testing"), so the
//     downgrade and MX-redirection attacks MTA-STS exists to defeat are still
//     possible. The MTASTSMode field carries the mode token.
//
// MTA-STS (RFC 8461) lets a domain declare that sending mail servers MUST use
// TLS when delivering to it. A domain opts in with a TXT record at
// _mta-sts.<domain> and a policy file at
// https://mta-sts.<domain>/.well-known/mta-sts.txt.
//
// Sub-case 1 (dangling host) is a DNS-only probe and emits a Potential finding,
// matching the SPF/DMARC/CAA/TLSA tier. The finding carries the dangling policy
// host in Service and the claimable CNAME target (or the policy host itself) in
// CNAME.
//
// Sub-case 2 (weak mode) is an active HTTP probe. The finding carries the policy
// host in Service and the mode token in MTASTSMode. It is classified Potential
// (no fingerprint match; the mode value is the authoritative signal).
//
// Algorithm:
//  1. Resolve TXT at _mta-sts.<target>. If no record begins with "v=STSv1",
//     the domain does not advertise MTA-STS — return no findings.
//  2. Probe mta-sts.<target> with CNAMEChain.
//     - ErrNXDomain: policy host is gone — emit the dangling-host finding (sub-case 1).
//     - Anything else: policy host resolves — fetch the policy file and check mode (sub-case 2).
//  3. For sub-case 2: GET https://mta-sts.<target>/.well-known/mta-sts.txt.
//     Parse the mode: field. If mode is "none" or "testing", emit a weak-mode finding.
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
	if errors.Is(chainErr, resolver.ErrNXDomain) {
		// Sub-case 1: dangling policy host. The claimable resource is the final
		// CNAME target when the policy host is a CNAME (the common deployment);
		// otherwise the policy host itself is the dangling name.
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

	// Policy host resolves (or lookup was indeterminate). Try sub-case 2: fetch
	// the policy file and check the mode: field. A lookup error (not NXDOMAIN)
	// means we cannot determine the host state — skip the mode check to avoid
	// false positives from transient DNS errors.
	if chainErr != nil {
		// Indeterminate DNS state — do not emit a finding.
		return nil, nil
	}

	// Sub-case 2: fetch the MTA-STS policy file and inspect the mode: field.
	mode, fetchErr := mtaStsFetchMode(ctx, policyHost)
	if fetchErr != nil {
		// Policy host is up but not serving the policy file (HTTP error, timeout,
		// TLS mismatch, etc.); treat as indeterminate — do not emit a finding. A
		// domain that serves the correct policy file should have no issue here.
		return nil, nil
	}

	// mode is always lowercase after mtaStsFetchMode.
	switch mode {
	case "none", "testing":
		return []finding.Finding{{
			Subdomain:  target,
			Vector:     finding.VectorMTASTS,
			Confidence: finding.Potential,
			Service:    policyHost,
			MTASTSMode: mode,
			Evidence: "MTA-STS policy at " + policyHost + " is mode: " + mode +
				" — TLS enforcement is " + mtaStsModeExplanation(mode) +
				"; SMTP senders are not required to enforce TLS for mail destined to " + target +
				", leaving the domain vulnerable to active-downgrade and MX-redirection attacks" +
				" (RFC 8461 §3.2 — upgrade to mode: enforce to activate protection)",
		}}, nil
	default:
		// mode: enforce or an unrecognised token — no finding.
		return nil, nil
	}
}

// mtaStsModeExplanation returns a short human-readable description of why
// the given MTA-STS mode fails to provide TLS enforcement.
func mtaStsModeExplanation(mode string) string {
	switch mode {
	case "none":
		return "completely disabled (senders MUST treat the policy as absent)"
	case "testing":
		return "monitor-only (senders MAY apply TLS but MUST NOT fail delivery on violations)"
	default:
		return "not active"
	}
}

// mtaStsFetchMode fetches the MTA-STS policy file at
// https://<policyHost>/.well-known/mta-sts.txt and returns the value of the
// "mode:" field, lower-cased and trimmed, or an error if the fetch or parse
// failed. An empty string is returned (with a nil error) when the policy file
// was fetched but contained no mode: field.
func mtaStsFetchMode(ctx context.Context, policyHost string) (string, error) {
	policyURL := "https://" + policyHost + mtaStsPolicyPath

	// Use a short-lived client with a dedicated timeout and TLS that skips
	// certificate verification — the takeover signal is the mode value, not the
	// certificate; a mismatched cert is itself an additional signal but skipping
	// verification ensures we can read the mode even when the cert is wrong.
	// This mirrors the TLSAHTTPS detector's tls.Dial approach.
	httpClient := &http.Client{
		Timeout: mtaStsPolicyFetchTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil // policy file not served; indeterminate
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, mtaStsPolicyMaxBytes))
	if err != nil {
		return "", err
	}

	return parseMTASTSMode(string(body)), nil
}

// parseMTASTSMode extracts the value of the "mode:" key from an MTA-STS policy
// body (RFC 8461 §3.2). The policy is a set of "key: value" lines; fields are
// separated by CRLF or LF. The function returns the first "mode:" value found,
// lower-cased and trimmed, or an empty string if no mode: field is present.
func parseMTASTSMode(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(strings.ToLower(line), "mode:") {
			continue
		}
		val := strings.TrimSpace(line[len("mode:"):])
		return strings.ToLower(val)
	}
	return ""
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
