package detectors

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// bimiTXTSuffix is the owner-name infix for a BIMI record. BIMI (Brand
// Indicators for Message Identification) publishes its record at
// <selector>._bimi.<domain>; the near-universal selector is "default", so a
// passive scanner probes default._bimi.<domain>.
const bimiTXTSuffix = "._bimi."

// bimiDefaultSelector is the conventional BIMI selector. The selector is named
// in the DKIM-style "v=bimi1" alignment but, in practice, virtually every
// deployment uses "default" (the BIMI selector is signalled in the message's
// BIMI-Selector header and defaults to "default" when absent). graverobber
// probes this single selector — like the MTA-STS policy host, the takeover is in
// the asset host the record points at, not in selector enumeration.
const bimiDefaultSelector = "default"

// bimiVersionToken is the mandatory version field of a valid BIMI record. The
// BIMI specification requires the record to begin with "v=BIMI1"; a TXT record at
// the BIMI owner name that lacks it is not a BIMI record and is ignored, keeping
// the detector from firing on unrelated TXT records that share the owner name.
const bimiVersionToken = "v=bimi1"

// BIMI detects a dangling BIMI asset host: a domain that advertises BIMI (Brand
// Indicators for Message Identification) via a "v=BIMI1" TXT record whose l=
// (logo) or a= (VMC certificate) URL points at a host that is NXDOMAIN.
//
// BIMI lets a domain publish a brand logo — optionally backed by a Verified Mark
// Certificate (VMC) — that BIMI-aware mail clients (Gmail, Apple Mail, Yahoo,
// Fastmail) fetch and render next to authenticated mail from the domain. It is a
// pure trust-signalling feature: the logo only displays for mail that already
// passes DMARC at enforcement, so the logo is, to the recipient, a visual mark of
// authenticity. A domain opts in by publishing at <selector>._bimi.<domain> a TXT
// record of the form:
//
//		v=BIMI1; l=https://images.example.com/brand/logo.svg; a=https://certs.example.com/vmc.pem
//
//	  - l= names the HTTPS URL of the SVG Tiny P/S logo (mandatory for display).
//	  - a= names the HTTPS URL of the VMC (.pem) that cryptographically binds the
//	    logo to the brand (optional, but required by Gmail and the strictest tier).
//
// Both URLs are, in practice, hosted on a brand subdomain or a vendor host (a CDN
// bucket, a BIMI-as-a-service provider). When that asset host is decommissioned —
// the bucket is released, the hosted zone is deleted, the brand-asset subdomain is
// retired — but the BIMI TXT record is left behind, the deployment becomes a
// takeover vector:
//
//   - An attacker who reclaims the dangling asset host (re-registers the gone
//     domain, re-creates the deleted resource) can serve an arbitrary logo at the
//     l= URL and, where the VMC host is the reclaimed one, an arbitrary VMC at the
//     a= URL. Because BIMI logos display only beside DMARC-passing mail, the forged
//     logo lends an attacker's spoofing campaign the exact visual trust mark BIMI
//     exists to confer — a brand-impersonation surface. This is the same
//     dangling-host pattern the CNAME, MX, SPF-include, DMARC-report, CAA-issuer,
//     TLSA, and MTA-STS vectors cover, applied to the BIMI asset plane.
//
// A domain with no BIMI TXT record, or whose l=/a= asset hosts all resolve, is the
// healthy case and is intentionally NOT flagged — only an advertised-but-orphaned
// asset host is reported, keeping the vector low-noise and pipeline-friendly,
// consistent with the other DNS-only vectors.
//
// The finding is keyed on the target, carries the BIMI owner name in Service and
// the dangling asset host in BIMIURIHost, and is classified Potential: a DNS-only
// signal (NXDOMAIN with no fingerprint match), matching the SPF/DMARC/CAA/TLSA/
// MTA-STS tier.
//
// Algorithm:
//  1. Resolve TXT at default._bimi.<target>. If no record begins with "v=BIMI1",
//     the domain does not advertise BIMI — return no findings.
//  2. Parse the l= and a= tag values as URLs and extract their hostnames.
//  3. For each distinct asset host, probe it with CNAMEChain (the authoritative
//     NXDOMAIN probe). ErrNXDomain means the asset host is gone — emit a Potential
//     finding naming the dangling host and which tag (l=/a=) referenced it.
func BIMI(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	target = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
	if target == "" {
		return nil, nil
	}

	owner := bimiDefaultSelector + bimiTXTSuffix + target
	txts, err := r.TXT(ctx, owner)
	if err != nil {
		return nil, nil
	}

	tags, ok := parseBIMIRecord(txts)
	if !ok {
		// No BIMI policy is advertised, so there is nothing to dangle.
		return nil, nil
	}

	// Probe the asset hosts named by the l= (logo) and a= (VMC) tags. A single
	// host may back both URLs; deduplicate so we emit one finding per dangling
	// host, attributing every tag that pointed at it.
	type assetHost struct {
		host string
		tags []string
	}
	var ordered []*assetHost
	index := map[string]*assetHost{}
	addHost := func(tag, rawURL string) {
		host := bimiURLHost(rawURL)
		if host == "" {
			return
		}
		if a, seen := index[host]; seen {
			a.tags = append(a.tags, tag)
			return
		}
		a := &assetHost{host: host, tags: []string{tag}}
		index[host] = a
		ordered = append(ordered, a)
	}
	addHost("l=", tags["l"])
	addHost("a=", tags["a"])

	var findings []finding.Finding
	for _, a := range ordered {
		// CNAMEChain (TypeA) is the authoritative NXDOMAIN probe, exactly as the
		// MX/SPF/DMARC/CAA/TLSA/MTA-STS detectors use it.
		_, chainErr := r.CNAMEChain(ctx, a.host)
		if !errors.Is(chainErr, resolver.ErrNXDomain) {
			continue // asset host resolves (healthy) or lookup indeterminate
		}
		findings = append(findings, finding.Finding{
			Subdomain:   target,
			Vector:      finding.VectorBIMI,
			Confidence:  finding.Potential,
			Service:     owner,
			BIMIURIHost: a.host,
			Evidence: "BIMI record at " + owner + " " + strings.Join(a.tags, "/") +
				" asset host " + a.host + " is NXDOMAIN (dangling BIMI asset host — " +
				"reclaimable to serve a forged brand logo/VMC beside DMARC-passing mail)",
		})
	}
	return findings, nil
}

// parseBIMIRecord finds the first valid BIMI TXT record among txts and returns
// its tag=value map. A BIMI record is a sequence of ";"-separated tag=value
// pairs whose first field is "v=BIMI1" (case-insensitive). The bool is false when
// no record qualifies. Tag names are lower-cased; values are trimmed but
// otherwise preserved (URLs must not be altered).
func parseBIMIRecord(txts []string) (map[string]string, bool) {
	for _, txt := range txts {
		fields := strings.Split(txt, ";")
		if len(fields) == 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(fields[0])) != bimiVersionToken {
			continue
		}
		tags := map[string]string{}
		for _, part := range fields {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			if key == "" {
				continue
			}
			tags[key] = strings.TrimSpace(kv[1])
		}
		return tags, true
	}
	return nil, false
}

// bimiURLHost extracts the lower-cased hostname from a BIMI l=/a= URL value. It
// returns "" for an empty value, a value that is not an absolute HTTP(S) URL, or
// a URL with no host — graverobber never probes a host it cannot positively
// identify. The "self" sentinel (some deployments publish a= self) and any
// non-http(s) scheme are likewise ignored.
func bimiURLHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		// "self" (a= self) and relative/opaque values name no remote host to probe.
		return ""
	}
	return strings.ToLower(u.Hostname())
}
