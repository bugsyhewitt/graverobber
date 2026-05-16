package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// knownDNSProviders is the suffix list used to decide whether a deleted hosted
// zone is re-claimable. Sourced from indianajson/can-i-take-over-dns.
var knownDNSProviders = []string{
	"awsdns",                // AWS Route 53
	"googledomains.com",     // Google Cloud DNS
	"azure-dns.com",         // Azure DNS
	"azure-dns.net",         // Azure DNS
	"azure-dns.org",         // Azure DNS
	"digitalocean.com",      // DigitalOcean
	"vultr.com",             // Vultr
	"linode.com",            // Linode
	"nsone.net",             // NS1
	"cloudflare.com",        // Cloudflare
	"dnsimple.com",          // DNSimple
	"dnsmadeeasy.com",       // DNS Made Easy
	"ultradns.net",          // UltraDNS
	"ultradns.com",          // UltraDNS
	"ultradns.org",          // UltraDNS
	"ultradns.biz",          // UltraDNS
	"dynect.net",            // Dyn
	"hurricane.net",         // Hurricane Electric
	"domaincontrol.com",     // GoDaddy
	"registrar-servers.com", // Namecheap
	"name-services.com",     // Enom
}

// NS detects subdomain takeover via a deleted DNS hosted zone.
//
// Algorithm (handoff "Detection vectors / 2. NS takeover detection"):
//  1. Resolve the target's NS records (resolver.NS).
//  2. Query each nameserver directly for the zone SOA
//     (resolver.AuthoritativeSOA).
//  3. If every nameserver answers SERVFAIL/REFUSED, the hosted zone is gone.
//  4. If the NS hostnames belong to a known cloud DNS provider
//     (knownDNSProviders), the zone is re-claimable — emit Confirmed; if the
//     provider is unknown, emit Potential.
func NS(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	nameservers, err := r.NS(ctx, target)
	if err != nil || len(nameservers) == 0 {
		return nil, nil
	}

	// Query each nameserver directly for the zone SOA.
	allDeleted := true
	for _, ns := range nameservers {
		soaErr := r.AuthoritativeSOA(ctx, target, ns)
		if !errors.Is(soaErr, resolver.ErrZoneDeleted) {
			// At least one NS is authoritative — zone is live.
			allDeleted = false
			break
		}
	}
	if !allDeleted {
		return nil, nil
	}

	// All nameservers indicate the zone is deleted. Determine confidence based
	// on whether the provider is known to allow zone re-creation.
	provider := matchNSProvider(nameservers)
	conf := finding.Potential
	if provider != "" {
		conf = finding.Confirmed
	}

	return []finding.Finding{{
		Subdomain:   target,
		Vector:      finding.VectorNS,
		Service:     provider,
		Confidence:  conf,
		Nameservers: nameservers,
		Evidence:    "all nameservers returned SERVFAIL/REFUSED for zone SOA",
	}}, nil
}

// matchNSProvider returns the first knownDNSProvider suffix that any of the
// nameservers matches, or "" if none match.
func matchNSProvider(nameservers []string) string {
	for _, ns := range nameservers {
		ns = strings.ToLower(ns)
		for _, suffix := range knownDNSProviders {
			if strings.HasSuffix(ns, suffix) || strings.Contains(ns, suffix) {
				return suffix
			}
		}
	}
	return ""
}
