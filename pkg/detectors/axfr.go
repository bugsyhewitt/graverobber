package detectors

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
)

// AXFR detects a nameserver misconfigured to allow unauthenticated DNS zone
// transfers. A server that streams the full zone to an arbitrary client leaks
// every record it holds — all subdomains, internal hostnames, mail and
// infrastructure layout — which is both a direct information disclosure and a
// force-multiplier for every other graverobber vector (it hands an attacker the
// complete subdomain list to scan for dangling records).
//
// This is the secure-vs-misconfigured sibling of the NS vector: NS asks "is the
// hosted zone deleted?"; AXFR asks "will the live nameservers hand me the whole
// zone?". Both start from the same delegated NS set.
//
// Algorithm:
//  1. Resolve the target's delegated NS records (resolver.NS).
//  2. Attempt an unauthenticated AXFR against each nameserver
//     (resolver.ZoneTransfer).
//  3. The first nameserver that returns zone data is a confirmed leak — emit a
//     CONFIRMED VectorAXFR finding naming that nameserver and sampling the
//     leaked hostnames. A nameserver that refuses (ErrAXFRRefused) or fails at
//     the transport level is skipped; only an actual transfer is a finding.
func AXFR(ctx context.Context, target string, r *resolver.Resolver) ([]finding.Finding, error) {
	nameservers, err := r.NS(ctx, target)
	if err != nil || len(nameservers) == 0 {
		return nil, nil
	}

	for _, ns := range nameservers {
		res, axErr := r.ZoneTransfer(ctx, target, ns)
		if axErr != nil {
			// ErrAXFRRefused is the secure, expected response; any other error
			// (connection refused, timeout) is transport-level and
			// indeterminate. Neither is a finding — try the next nameserver. A
			// cancelled context stops the whole scan, so propagate it.
			if errors.Is(axErr, context.Canceled) || errors.Is(axErr, context.DeadlineExceeded) {
				return nil, nil
			}
			continue
		}
		if res.RecordCount == 0 {
			continue
		}

		return []finding.Finding{{
			Subdomain:   target,
			Vector:      finding.VectorAXFR,
			Service:     ns,
			Confidence:  finding.Confirmed,
			Nameservers: []string{ns},
			LeakedHosts: res.Hosts,
			Evidence:    axfrEvidence(ns, res.RecordCount, res.Hosts),
		}}, nil
	}

	return nil, nil
}

// axfrEvidence builds a one-line human-readable explanation naming the leaking
// nameserver, the record count, and a sample of the exposed hostnames.
func axfrEvidence(ns string, count int, hosts []string) string {
	if len(hosts) == 0 {
		return fmt.Sprintf("nameserver %s allowed unauthenticated AXFR (%d records leaked)", ns, count)
	}
	return fmt.Sprintf(
		"nameserver %s allowed unauthenticated AXFR (%d records leaked; sample: %s)",
		ns, count, strings.Join(hosts, ", "),
	)
}
