// Package resolver provides the DNS resolution primitives used by the
// detectors.
//
// graverobber deliberately uses github.com/miekg/dns rather than the standard
// library net resolver: takeover detection depends on observing raw response
// codes (NXDOMAIN, SERVFAIL, REFUSED) and complete CNAME chains, which the net
// package abstracts away entirely.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Sentinel errors returned by resolver methods.
var (
	ErrNotImplemented = errors.New("resolver: not implemented (scaffold)")
	// ErrNXDomain is returned by CNAMEChain when the final CNAME target is
	// NXDOMAIN. The chain is still returned so callers can match fingerprints.
	ErrNXDomain = errors.New("resolver: NXDOMAIN")
	// ErrZoneDeleted signals that a nameserver answered SERVFAIL or REFUSED,
	// meaning the hosted zone no longer exists.
	ErrZoneDeleted = errors.New("resolver: zone deleted (SERVFAIL or REFUSED)")
)

// publicFallback is the last-resort resolver set when /etc/resolv.conf is
// unavailable and no custom resolvers are configured.
var publicFallback = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// Resolver performs DNS queries against a configured set of recursive
// resolvers.
type Resolver struct {
	servers []string
	timeout time.Duration
	client  *dns.Client
}

// New returns a Resolver. When servers is empty, the build step should fall
// back to /etc/resolv.conf or a sane public resolver set.
func New(servers []string, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		servers: servers,
		timeout: timeout,
		client:  &dns.Client{Timeout: timeout},
	}
}

// Servers reports the configured recursive resolvers (empty means defaults).
func (r *Resolver) Servers() []string { return r.servers }

// Timeout reports the per-query timeout.
func (r *Resolver) Timeout() time.Duration { return r.timeout }

// effectiveServers returns the resolvers to query: configured servers first,
// then /etc/resolv.conf, finally a hardcoded public set.
func (r *Resolver) effectiveServers() []string {
	if len(r.servers) > 0 {
		out := make([]string, len(r.servers))
		for i, s := range r.servers {
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			out[i] = s
		}
		return out
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		out := make([]string, len(cfg.Servers))
		for i, s := range cfg.Servers {
			out[i] = net.JoinHostPort(s, port)
		}
		return out
	}
	return publicFallback
}

// query sends msg to each effective server in order and returns the first
// successful response.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range r.effectiveServers() {
		resp, _, err := r.client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("resolver: no servers available")
}

// maxCNAMEChain caps the number of CNAME hops extracted from a single DNS
// response. Loop detection is delegated to the recursive resolver (all queries
// go through query() with RecursionDesired=true), but this bound guards against
// pathological responses from a buggy or malicious recursive resolver.
const maxCNAMEChain = 16

// CNAMEChain resolves the ordered chain of CNAME records starting at host. The
// final element is the ultimate canonical target. An empty result with a nil
// error means host has no CNAME.
//
// ErrNXDomain is returned (alongside any partial chain) whenever the queried
// host — or the final CNAME target — does not exist. Callers can use this both
// to match NXDomain fingerprints and to confirm that an SPF include domain is
// unregistered.
//
// Loop safety: CNAMEChain always uses query(), which sets RecursionDesired=true
// and queries the configured recursive resolvers. The recursive resolver is
// responsible for detecting and breaking CNAME loops before the response is
// returned. maxCNAMEChain provides an additional cap on the parsed Answer
// section as defense-in-depth against malformed resolver responses.
func (r *Resolver) CNAMEChain(ctx context.Context, host string) ([]string, error) {
	// Query TypeA: recursive resolvers include all CNAME hops in the Answer
	// section, which gives us the full chain in one round trip.
	resp, err := r.query(ctx, host, dns.TypeA)
	if err != nil {
		return nil, err
	}

	var chain []string
	for _, rr := range resp.Answer {
		if len(chain) >= maxCNAMEChain {
			break // defensive cap; a legitimate chain is never this long
		}
		if c, ok := rr.(*dns.CNAME); ok {
			chain = append(chain, strings.TrimSuffix(c.Target, "."))
		}
	}

	if resp.Rcode == dns.RcodeNameError {
		// Return ErrNXDomain whether or not there is a chain: the CNAME
		// detector skips empty chains, and SPF uses this to confirm a domain is
		// unregistered regardless of whether it has CNAMEs.
		return chain, ErrNXDomain
	}
	return chain, nil
}

// NS returns the NS records delegated for host.
func (r *Resolver) NS(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if n, ok := rr.(*dns.NS); ok {
			out = append(out, strings.TrimSuffix(n.Ns, "."))
		}
	}
	// NS records sometimes appear in the Authority section.
	for _, rr := range resp.Ns {
		if n, ok := rr.(*dns.NS); ok {
			out = append(out, strings.TrimSuffix(n.Ns, "."))
		}
	}
	return out, nil
}

// TXT returns the TXT records for host (used to extract the SPF policy).
func (r *Resolver) TXT(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// soaRetries is the number of UDP attempts before escalating to TCP.
// Transient SERVFAIL and packet loss are common; retrying reduces false
// negatives without risking false positives (a real deletion returns
// ErrZoneDeleted consistently, not intermittently).
const soaRetries = 3

// soaBackoff is the wait between AuthoritativeSOA UDP retry attempts.
// It is a var (not const) so tests in this package can shrink it to keep
// test runtime acceptable without changing production behavior.
var soaBackoff = 150 * time.Millisecond

// AuthoritativeSOA queries nameserver directly for the SOA of zone. An error
// that wraps ErrZoneDeleted means the hosted zone no longer exists.
//
// Retry and TCP escalation policy:
//   - Up to soaRetries UDP attempts, with soaBackoff between each.
//   - If a UDP response is truncated (TC=1), TCP is tried immediately.
//   - If ALL UDP attempts fail with network errors (including timeouts from
//     firewalls that silently drop UDP), TCP is attempted once before giving up.
//     This covers the common case of UDP-blocked resolvers.
func (r *Resolver) AuthoritativeSOA(ctx context.Context, zone, nameserver string) error {
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		nameserver = net.JoinHostPort(nameserver, "53")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	msg.RecursionDesired = false // non-recursive: we want the NS's own answer

	evalRcode := func(resp *dns.Msg) error {
		switch resp.Rcode {
		case dns.RcodeSuccess:
			return nil
		case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNameError:
			return ErrZoneDeleted
		default:
			return fmt.Errorf("resolver: SOA query rcode %d", resp.Rcode)
		}
	}

	tcpFallback := func() error {
		tcpClient := &dns.Client{Net: "tcp", Timeout: r.timeout}
		resp, _, err := tcpClient.ExchangeContext(ctx, msg, nameserver)
		if err != nil {
			return err
		}
		return evalRcode(resp)
	}

	var lastErr error
	for attempt := 0; attempt < soaRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(soaBackoff):
			}
		}

		resp, _, err := r.client.ExchangeContext(ctx, msg, nameserver)
		if err != nil {
			lastErr = err
			continue
		}

		// TCP fallback when the UDP response is truncated (TC=1).
		if resp.Truncated {
			if tcpErr := tcpFallback(); tcpErr == nil || errors.Is(tcpErr, ErrZoneDeleted) {
				return tcpErr
			}
			// TCP also failed; evaluate the truncated UDP response as-is.
		}

		return evalRcode(resp)
	}

	// All UDP attempts exhausted by network errors (timeouts, dropped packets).
	// Escalate to TCP before giving up: firewalls that block UDP DNS are common,
	// and a single TCP attempt costs little compared to the retries already spent.
	if lastErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tcpFallback()
	}
	return lastErr
}

// IsWildcard reports whether domain serves wildcard DNS. Wildcard zones would
// otherwise yield false-positive dangling-record findings and must be
// suppressed.
func (r *Resolver) IsWildcard(ctx context.Context, domain string) (bool, error) {
	probe := fmt.Sprintf("graverobber-%016x.%s", rand.Int63(), domain)
	resp, err := r.query(ctx, probe, dns.TypeA)
	if err != nil {
		return false, err
	}
	return resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0, nil
}
