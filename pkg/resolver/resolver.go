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
	"sort"
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

// RawCNAME returns the single CNAME target published directly at host, or ""
// when host has no CNAME record. Unlike CNAMEChain (which issues a TypeA query
// and reports the recursively-resolved A-record chain), RawCNAME issues a
// TypeCNAME query and reports only the immediate alias.
//
// This distinction matters for the DKIM vector: a DKIM selector is only a
// takeover candidate when it is published as a CNAME (delegating the public key
// to an ESP's infrastructure). A selector published as a TXT record holds the
// key inline and is not delegated, so it is not at risk. RawCNAME lets the
// detector confirm the selector is a CNAME before probing its target.
//
// A NXDOMAIN response for host itself yields ("", ErrNXDomain); callers that
// only care whether a CNAME exists can ignore the error and check the string.
func (r *Resolver) RawCNAME(ctx context.Context, host string) (string, error) {
	resp, err := r.query(ctx, host, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(c.Target, "."), nil
		}
	}
	if resp.Rcode == dns.RcodeNameError {
		return "", ErrNXDomain
	}
	return "", nil
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

// ErrAXFRRefused signals that a nameserver declined a zone-transfer (AXFR)
// request — the correct, secure behaviour. ZoneTransfer returns it (wrapped)
// for a REFUSED/NOTAUTH rcode or a connection that yields no zone data, so the
// detector can distinguish "secure" from a transient transport error.
var ErrAXFRRefused = errors.New("resolver: AXFR refused")

// maxAXFRRecords caps the number of resource records collected from a single
// zone transfer. A successful AXFR against a large zone can stream tens of
// thousands of records; the detector only needs to confirm the leak and sample
// the surface, so the records are bounded to keep memory predictable in a
// 50-worker scan. The cap does not affect the vulnerable/secure verdict, which
// is decided by whether ANY records were transferred.
const maxAXFRRecords = 5000

// ZoneTransferResult reports the outcome of a ZoneTransfer attempt: the total
// number of non-SOA records the nameserver streamed and a deduplicated, sorted
// sample of the owner names (hostnames) those records exposed. The detector
// uses RecordCount for the verdict (>0 means leak) and Hosts for evidence.
type ZoneTransferResult struct {
	// RecordCount is the number of non-SOA resource records transferred (capped
	// at maxAXFRRecords). Zero means the nameserver refused or returned only the
	// bracketing SOAs.
	RecordCount int
	// Hosts is a deduplicated, sorted sample of the distinct owner names seen in
	// the transfer, capped at maxAXFRHostsSampled. It proves the leak and gives
	// the operator a representative view without serialising the whole zone.
	Hosts []string
}

// maxAXFRHostsSampled caps the distinct owner names retained in a
// ZoneTransferResult. The verdict only needs one record; the sample is for the
// operator.
const maxAXFRHostsSampled = 25

// axfrPort is the TCP port ZoneTransfer dials when a nameserver is given without
// an explicit port. It is the standard DNS port in production; it is a var (not
// a const) solely so tests can point the AXFR dial at an ephemeral test server
// without binding privileged port 53 — the same testability pattern used by
// soaBackoff. Production code never reassigns it.
var axfrPort = "53"

// SetAXFRPortForTest overrides the default AXFR TCP port and returns a restore
// function. It exists so cross-package tests (e.g. the detectors package) can
// dial an unprivileged ephemeral AXFR server. It MUST only be called from tests;
// production code never imports it. The returned func restores the prior value.
func SetAXFRPortForTest(port string) (restore func()) {
	prev := axfrPort
	axfrPort = port
	return func() { axfrPort = prev }
}

// ZoneTransfer attempts an unauthenticated AXFR of zone against nameserver. A
// nameserver that allows AXFR to an arbitrary client is misconfigured: it leaks
// every record in the zone (all subdomains, internal hostnames, infrastructure
// layout) to anyone who asks.
//
// On success it returns a ZoneTransferResult whose RecordCount is > 0 (SOA
// records excluded, since an AXFR brackets the zone with two SOAs). A nameserver
// that correctly refuses returns (zero-value result, ErrAXFRRefused). A
// transport-level failure returns (zero-value result, <that error>); callers
// treat a non-nil, non-ErrAXFRRefused error as "indeterminate" and emit no
// finding.
//
// AXFR is TCP-only by protocol. The transfer uses the resolver's timeout for
// dial, read, and write so a hung nameserver cannot stall a worker.
func (r *Resolver) ZoneTransfer(ctx context.Context, zone, nameserver string) (ZoneTransferResult, error) {
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		nameserver = net.JoinHostPort(nameserver, axfrPort)
	}

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(zone))

	tr := &dns.Transfer{
		DialTimeout:  r.timeout,
		ReadTimeout:  r.timeout,
		WriteTimeout: r.timeout,
	}

	envCh, err := tr.In(msg, nameserver)
	if err != nil {
		// Dial/write failure (connection refused, timeout) — indeterminate, not
		// a security verdict.
		return ZoneTransferResult{}, err
	}

	count := 0
	hostSet := make(map[string]struct{})
	for {
		select {
		case <-ctx.Done():
			return ZoneTransferResult{}, ctx.Err()
		case env, ok := <-envCh:
			if !ok {
				// Channel drained cleanly. If the nameserver streamed no records
				// it effectively refused the transfer.
				if count == 0 {
					return ZoneTransferResult{}, ErrAXFRRefused
				}
				return makeZoneTransferResult(count, hostSet), nil
			}
			if env.Error != nil {
				// A REFUSED/NOTAUTH rcode (the secure response) surfaces here as
				// an error after zero records — report it as a clean refusal. A
				// mid-stream error after records were already collected still
				// counts as a leak (the zone data is already out).
				if count > 0 {
					return makeZoneTransferResult(count, hostSet), nil
				}
				return ZoneTransferResult{}, fmt.Errorf("%w: %v", ErrAXFRRefused, env.Error)
			}
			for _, rr := range env.RR {
				// Exclude the bracketing SOA records: an AXFR begins and ends
				// with the zone SOA, so a refused-but-SOA-only response is not a
				// real leak.
				if _, isSOA := rr.(*dns.SOA); isSOA {
					continue
				}
				count++
				if len(hostSet) < maxAXFRHostsSampled {
					hostSet[strings.TrimSuffix(rr.Header().Name, ".")] = struct{}{}
				}
				if count >= maxAXFRRecords {
					return makeZoneTransferResult(count, hostSet), nil
				}
			}
		}
	}
}

// makeZoneTransferResult finalises a result: it sorts the sampled host set for
// stable, deterministic evidence output.
func makeZoneTransferResult(count int, hostSet map[string]struct{}) ZoneTransferResult {
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return ZoneTransferResult{RecordCount: count, Hosts: hosts}
}

// MX returns the mail-exchanger hostnames for host (the right-hand side of each
// MX record, without trailing dot, unsorted).
func (r *Resolver) MX(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if m, ok := rr.(*dns.MX); ok {
			out = append(out, strings.TrimSuffix(m.Mx, "."))
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

// CAARecord is a single CAA (Certification Authority Authorization) resource
// record (RFC 8659). A CAA record set restricts which Certificate Authorities
// may issue certificates for a domain. The fields mirror the wire format:
//
//	Flag  a bit field; bit 0 (value 128) is the "critical" flag.
//	Tag   the property tag, lower-cased: "issue", "issuewild", or "iodef".
//	Value the property value: a CA domain (optionally with parameters) for
//	      issue/issuewild, or a URL for iodef. A bare ";" forbids all issuance.
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// CAA returns the CAA records published at host. An empty slice with a nil error
// means host has no CAA record set (any CA may issue a certificate — the default
// permissive state). Tags are lower-cased so callers can match them directly.
func (r *Resolver) CAA(ctx context.Context, host string) ([]CAARecord, error) {
	resp, err := r.query(ctx, host, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var out []CAARecord
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, CAARecord{
				Flag:  c.Flag,
				Tag:   strings.ToLower(strings.TrimSpace(c.Tag)),
				Value: strings.TrimSpace(c.Value),
			})
		}
	}
	return out, nil
}

// TLSA returns whether a TLSA (DANE, RFC 6698) record set is published at host
// and the count of records found. host is the DANE-prefixed name, e.g.
// "_25._tcp.mx.example.com". An empty/zero result with a nil error means no
// TLSA record set exists at host.
//
// graverobber does not interpret the TLSA RDATA (usage/selector/matching-type or
// the certificate-association payload): the dangling-DANE vector only needs to
// know that a pin EXISTS for a host whose underlying mail exchanger is NXDOMAIN.
// The count is surfaced as evidence.
func (r *Resolver) TLSA(ctx context.Context, host string) (count int, err error) {
	resp, err := r.query(ctx, host, dns.TypeTLSA)
	if err != nil {
		return 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return 0, nil
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.TLSA); ok {
			count++
		}
	}
	return count, nil
}

// DSKeyTags returns the key tags of the DS (Delegation Signer, RFC 4034)
// records published for host in its PARENT zone. A non-empty result means the
// parent has signed a delegation to host: every DNSSEC-validating resolver is
// now committed to building an authenticated chain into host's zone.
//
// An empty slice with a nil error means host has no DS record — it is an
// unsigned (insecure) delegation, the common default, and nothing to orphan. A
// non-nil error means the lookup was indeterminate (transport failure, SERVFAIL
// from the parent) and the caller should emit no finding.
//
// The DS query is answered authoritatively by the parent zone, so it is a plain
// recursive lookup like every other record type; the DO bit is not required to
// ask for DS records themselves. The key tags are surfaced as the actionable
// identifier of the orphaned delegation (they name which parent DS records have
// no matching child key).
func (r *Resolver) DSKeyTags(ctx context.Context, host string) ([]uint16, error) {
	resp, err := r.query(ctx, host, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	// A SERVFAIL on the DS query itself (a broken parent) is indeterminate, not
	// a verdict: do not infer an orphan from it.
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var tags []uint16
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			tags = append(tags, ds.KeyTag)
		}
	}
	return tags, nil
}

// HasDNSKEY reports whether host's own zone publishes any DNSKEY (RFC 4034)
// record — i.e. whether the zone is DNSSEC-signed. A true result means the child
// zone has at least one key with which a DS record at the parent could be
// matched; false means the zone publishes no key at all.
//
// found is false with a nil error when the zone exists but publishes no DNSKEY
// (the orphaned-DS condition when the parent nonetheless has a DS). A non-nil
// error means the lookup was indeterminate and the caller should emit no
// finding: in particular a SERVFAIL — which a validating recursive resolver
// returns for a zone whose DS/DNSKEY chain is already broken — is reported as
// ErrZoneDeleted so the detector can treat it as a positive break signal rather
// than mistake it for "no key".
func (r *Resolver) HasDNSKEY(ctx context.Context, host string) (found bool, err error) {
	resp, err := r.query(ctx, host, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.DNSKEY); ok {
				return true, nil
			}
		}
		return false, nil
	case dns.RcodeServerFailure:
		// A validating recursive resolver returns SERVFAIL for a zone whose
		// DNSSEC chain is already broken (the very orphan we are detecting). Map
		// it to ErrZoneDeleted so the detector treats it as a confirmed break,
		// not an indeterminate transport error.
		return false, ErrZoneDeleted
	default:
		// NXDOMAIN/REFUSED/other: indeterminate for the orphan verdict.
		return false, fmt.Errorf("resolver: DNSKEY query rcode %d", resp.Rcode)
	}
}

// DNSKEYAlgorithm reports the algorithm field of one of a zone's DNSKEY records
// (RFC 4034 §2.1.3). The value is one of the IANA "DNS Security Algorithm
// Numbers" identifiers (e.g. 5 = RSASHA1, 7 = RSASHA1-NSEC3-SHA1, 8 = RSASHA256,
// 13 = ECDSAP256SHA256).
type DNSKEYAlgorithm uint8

// DNSKEYAlgorithms returns the algorithm numbers of every DNSKEY record published
// by host's child zone. The result is in DNS-answer order; callers that need
// determinism must sort and dedupe. An empty slice with a nil error means the
// zone publishes no DNSKEY (it is unsigned, or the orphaned-DS case). A non-nil
// error means the lookup was indeterminate (transport failure, or — as in
// HasDNSKEY — a SERVFAIL mapped to ErrZoneDeleted because a validating resolver
// returned it for an already-broken chain).
//
// Unlike HasDNSKEY this method returns one entry per key — a zone in mid-rollover
// commonly publishes two — so the weak-algorithm check can report every weak key.
func (r *Resolver) DNSKEYAlgorithms(ctx context.Context, host string) ([]DNSKEYAlgorithm, error) {
	resp, err := r.query(ctx, host, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		var algs []DNSKEYAlgorithm
		for _, rr := range resp.Answer {
			if k, ok := rr.(*dns.DNSKEY); ok {
				algs = append(algs, DNSKEYAlgorithm(k.Algorithm))
			}
		}
		return algs, nil
	case dns.RcodeServerFailure:
		return nil, ErrZoneDeleted
	default:
		return nil, fmt.Errorf("resolver: DNSKEY query rcode %d", resp.Rcode)
	}
}

// DSAlgorithm pairs the cryptographic algorithm of the referenced DNSKEY with
// the digest algorithm used to fingerprint that key inside the DS record
// (RFC 4034 §5.1). Both numbers are IANA registry identifiers; both surfaces
// have weak values graverobber flags (e.g. Algorithm 5 = RSASHA1, DigestType 1
// = SHA-1).
type DSAlgorithm struct {
	KeyTag     uint16
	Algorithm  uint8 // DNSSEC algorithm of the referenced key
	DigestType uint8 // hash function used to compute the DS digest
}

// DSAlgorithms returns the algorithm and digest-type fields of every DS record
// published for host by its parent zone. The result mirrors DSKeyTags in
// rcode/error handling: an empty slice with a nil error means the parent
// publishes no DS, and a non-success rcode is treated as indeterminate (no
// finding, no error wrap) so a broken parent never produces a false algorithm
// verdict. The returned slice is in DNS-answer order; callers dedupe as needed.
func (r *Resolver) DSAlgorithms(ctx context.Context, host string) ([]DSAlgorithm, error) {
	resp, err := r.query(ctx, host, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}
	var out []DSAlgorithm
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, DSAlgorithm{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
			})
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
