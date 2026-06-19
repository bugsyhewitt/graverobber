// Package engine implements graverobber's multi-signal takeover detector — the
// precision core that separates graverobber from fingerprint-only scanners
// (subzy, nuclei takeover templates, dnsReaper, the legacy subjack).
//
// Every fingerprint-only tool emits a candidate the moment a provider "unclaimed"
// body string matches. That false-positives constantly: a custom 404 page that
// happens to contain the provider string, or a provider that quietly fixed its
// reclamation policy, both trip a single-fingerprint match while the backend is
// in fact live and owned. graverobber refuses to call a candidate `detected` on a
// fingerprint alone (the false-positive guard, D2): a detection requires the
// fingerprint match PLUS at least one independent unclaimed-backend signal —
// NXDOMAIN on the CNAME target, a TLS-certificate mismatch, or a DNS chain ending
// at a deprovisioned provider edge. "When all align, you likely have a legitimate
// candidate." The aligned-signal evidence is what makes a `detected` finding
// worth confirming and graverobber's `not_vulnerable` disproofs trustworthy.
//
// The engine produces a finding.Finding in the `detected` state with the
// takeover.<service> rule and the multi-signal evidence; the confirmer
// (pkg/confirm) then turns true positives into proven, canary-backed `confirmed`
// findings. The engine is SAFE — it only resolves DNS and issues read-only HTTP
// probes; it never claims anything.
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/fingerprints"
)

// Detector runs multi-signal takeover detection against a host. It composes the
// fingerprint database, a CNAME-chain resolver, a body-fetcher, and a TLS prober.
// All collaborators are injectable so the detector is unit-testable without real
// DNS, HTTP, or TLS.
type Detector struct {
	db       *fingerprints.DB
	resolver cnameResolver
	nxErr    error // the resolver's NXDOMAIN sentinel (resolver.ErrNXDomain)
	fetch    bodyFetcher
	dialTLS  tlsDialer
	now      func() time.Time
}

// bodyFetcher fetches the (bounded) HTTP/HTTPS body of host. It returns the body
// and the winning scheme, or an error. Injectable for tests.
type bodyFetcher func(ctx context.Context, host string) (body []byte, scheme string, err error)

// Option configures a Detector.
type Option func(*Detector)

// WithResolver sets the CNAME-chain resolver and its NXDOMAIN sentinel. The
// production caller passes the real *resolver.Resolver and resolver.ErrNXDomain.
func WithResolver(r cnameResolver, nxErr error) Option {
	return func(d *Detector) {
		if r != nil {
			d.resolver = r
		}
		if nxErr != nil {
			d.nxErr = nxErr
		}
	}
}

// WithBodyFetcher overrides the HTTP body fetcher (tests).
func WithBodyFetcher(f bodyFetcher) Option {
	return func(d *Detector) {
		if f != nil {
			d.fetch = f
		}
	}
}

// WithTLSDialer overrides the TLS prober (tests).
func WithTLSDialer(t tlsDialer) Option {
	return func(d *Detector) {
		if t != nil {
			d.dialTLS = t
		}
	}
}

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option {
	return func(d *Detector) {
		if now != nil {
			d.now = now
		}
	}
}

// NewDetector builds a Detector over db. A resolver MUST be supplied via
// WithResolver before Detect can run; the body fetcher and TLS dialer default to
// real network probes. db may be nil only in tests that also stub the resolver to
// never match a provider.
func NewDetector(db *fingerprints.DB, opts ...Option) *Detector {
	d := &Detector{
		db:      db,
		fetch:   defaultBodyFetcher,
		dialTLS: defaultTLSDialer,
		now:     time.Now,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Detect performs multi-signal analysis of host and reports the aligned Signals
// and whether the candidate is `detected` (D2: fingerprint match AND ≥1
// independent unclaimed-backend signal).
//
// The flow:
//  1. Resolve the CNAME chain (host → CNAME(s) → final edge).
//  2. Match the chain against the fingerprint DB to identify the provider edge.
//  3. Fetch the body and TLS state; set FingerprintMatch from the body (or, for
//     an NXDOMAIN-class provider, from the NXDOMAIN observation).
//  4. Set the independent signals: target NXDOMAIN, TLS mismatch, dangling edge.
//  5. detected = FingerprintMatch && (TargetNXDOMAIN || TLSMismatch ||
//     DanglingEdge).
//
// A fingerprint match with NO independent signal returns (signals, false): a
// low-confidence candidate, NOT a finding (the false-positive guard).
func (d *Detector) Detect(ctx context.Context, host string) (*Signals, bool) {
	host = normalizeHost(host)
	chain := resolveChain(ctx, host, d.resolver, d.nxErr)

	s := &Signals{CNAMETarget: chain.FinalCNAME}

	prov, matched := d.matchProvider(chain)
	if !matched {
		// No provider edge in the chain → nothing to fingerprint. Not detected.
		return s, false
	}
	s.Provider = prov.Service
	s.DanglingEdge = chain.EndsAtEdge(prov.CNAME)

	// Independent signal #1: the final CNAME target is NXDOMAIN. For providers
	// flagged nxdomain in the DB this is also the fingerprint signal.
	if chain.FinalNXDOMAIN {
		s.TargetNXDOMAIN = true
	}

	if prov.NXDomain {
		// NXDOMAIN-class provider: the fingerprint IS the NXDOMAIN observation.
		s.FingerprintMatch = chain.FinalNXDOMAIN
	} else {
		// Body-fingerprinted provider: fetch and match the body. A fetch failure
		// leaves FingerprintMatch false (we will not invent a match).
		if body, scheme, err := d.fetch(ctx, host); err == nil {
			s.FingerprintMatch = prov.MatchBody(body)
			_ = scheme
		}
	}

	// Independent signal #2: TLS mismatch (no TLS / default-provider cert / CN
	// does not cover host). Probed regardless of provider class.
	if state, err := d.dialTLS(ctx, host); err == nil {
		s.TLSMismatch = tlsCertMismatch(state, host)
	} else {
		// A failed TLS handshake against a host whose chain ends at a provider
		// edge is itself an unclaimed signal (a live backend answers TLS).
		s.TLSMismatch = true
	}

	// D2: fingerprint AND at least one independent unclaimed-backend signal.
	detected := s.FingerprintMatch && s.Independent()
	return s, detected
}

// matchProvider returns the first fingerprint-DB provider whose CNAME suffixes
// the chain ends at (or, lacking a chain match, whose edge the final target
// matches). It returns matched=false when no provider edge is found.
func (d *Detector) matchProvider(chain Chain) (fingerprints.Fingerprint, bool) {
	if d.db == nil {
		return fingerprints.Fingerprint{}, false
	}
	// Prefer the most specific: walk hops from the final target backwards so the
	// provider edge (the last hop) wins.
	hops := chain.CNAMEs
	for i := len(hops) - 1; i >= 0; i-- {
		if hits := d.db.MatchCNAME(hops[i]); len(hits) > 0 {
			return hits[0], true
		}
	}
	// Fall back to matching the host itself (a direct provider CNAME with no
	// intermediate hop recorded).
	if chain.FinalCNAME != "" {
		if hits := d.db.MatchCNAME(chain.FinalCNAME); len(hits) > 0 {
			return hits[0], true
		}
	}
	return fingerprints.Fingerprint{}, false
}

// AdapterKeyForService maps a fingerprint service name to its claim_adapter key,
// re-exported via confirm.ServiceToAdapter semantics so the engine and confirmer
// agree on the rule slug without an import cycle. It is the same slug used in the
// finding Rule ("takeover.<slug>").
func adapterSlug(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		case r == '-' || r == ' ' || r == '/' || r == '_' || r == '.':
			if !prevHyphen && b.Len() > 0 {
				b.WriteRune('-')
				prevHyphen = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// Finding builds a `detected` finding.Finding from aligned signals. It is called
// only when Detect returned detected=true. The finding carries the
// takeover.<service> rule, the multi-signal evidence, severity high (content
// takeover — the NS class uses critical via DetectNS), and Confidence reflecting
// the signal strength (NXDOMAIN/confirmed body → CONFIRMED-grade detection;
// otherwise LIKELY) — though State, not Confidence, is the takeover lifecycle.
func (d *Detector) Finding(host string, s *Signals) finding.Finding {
	slug := adapterSlug(s.Provider)
	conf := finding.Likely
	if s.TargetNXDOMAIN {
		conf = finding.Confirmed
	}
	return finding.Finding{
		Subdomain:  normalizeHost(host),
		Vector:     finding.VectorCNAME,
		Service:    s.Provider,
		CNAME:      s.CNAMETarget,
		Rule:       "takeover." + slug,
		State:      finding.StateDetected,
		Severity:   finding.SeverityHigh,
		Confidence: conf,
		Evidence:   SignalEvidence(s),
		Timestamp:  d.now().UTC(),
	}
}

// SignalEvidence renders which signals aligned into a single human-readable
// evidence string, e.g. "signals aligned: [fingerprint:'There isn't a GitHub
// Pages site here.'] [cname-target-nxdomain:assets.github.io] [tls:mismatch]".
// This multi-signal evidence is the credibility that distinguishes a graverobber
// `detected` finding from a fingerprint-only tool's candidate.
func SignalEvidence(s *Signals) string {
	if s == nil {
		return ""
	}
	var parts []string
	if s.FingerprintMatch {
		parts = append(parts, fmt.Sprintf("[fingerprint:%s]", s.Provider))
	}
	if s.TargetNXDOMAIN {
		parts = append(parts, fmt.Sprintf("[cname-target-nxdomain:%s]", s.CNAMETarget))
	}
	if s.TLSMismatch {
		parts = append(parts, "[tls:default-or-mismatched-cert]")
	}
	if s.DanglingEdge {
		parts = append(parts, fmt.Sprintf("[dangling-edge:%s]", s.CNAMETarget))
	}
	if len(parts) == 0 {
		return "no signals aligned"
	}
	return "signals aligned: " + strings.Join(parts, " ")
}

// defaultBodyFetcher is the production HTTP body fetcher: HTTPS first, HTTP
// fallback, bounded body, short timeout, skip-verify (a dangling edge serves a
// mismatched cert but we still want its body). It is intentionally minimal —
// the engine's HTTP needs are a single read-only GET.
func defaultBodyFetcher(ctx context.Context, host string) ([]byte, string, error) {
	return fetchBounded(ctx, host)
}
