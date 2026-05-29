// Package finding defines the core domain types shared across graverobber's
// detection, scanning, and output packages.
//
// It is deliberately a leaf package: it imports only the standard library so
// every other package may depend on it without risk of an import cycle. In
// particular, both pkg/detectors and pkg/scanner need the Finding type, and
// pkg/scanner imports pkg/detectors — placing Finding here breaks that cycle.
package finding

import "time"

// Vector identifies which takeover detection vector produced a Finding.
type Vector string

const (
	// VectorCNAME: a dangling CNAME points at a service whose resource is
	// unclaimed, matched against the fingerprint database.
	VectorCNAME Vector = "cname"
	// VectorNS: the delegated DNS hosted zone has been deleted at the provider
	// and is re-claimable.
	VectorNS Vector = "ns"
	// VectorSPF: an SPF include: directive references a domain that is
	// unregistered and therefore claimable (the SubdoMailing vector).
	VectorSPF Vector = "spf"
	// VectorMX: a dangling MX record points at a mail host that is NXDOMAIN or
	// belongs to a cloud mail provider whose hosted zone has been deleted.
	VectorMX Vector = "mx"
	// VectorDKIM: a DKIM selector (<selector>._domainkey.<domain>) is either
	// published as a CNAME whose target is NXDOMAIN (the ESP resource is gone
	// and an attacker who reclaims it can serve a DKIM key that signs spoofed
	// mail), or published inline with an RSA public key whose modulus is below
	// the RFC 8301 1024-bit floor (an attacker who factors the short key can
	// forge DKIM signatures directly). The DKIMKeyBits field distinguishes the
	// two cases: zero for the dangling-CNAME case, the modulus size for a weak
	// inline key.
	VectorDKIM Vector = "dkim"
	// VectorDMARC: a DMARC policy at _dmarc.<domain> is either weak or dangling.
	// In the dangling sub-case a rua=/ruf= report URI points at an NXDOMAIN
	// domain — an attacker who claims it intercepts every DMARC aggregate/
	// forensic report sent for the target (DMARCURI carries the claimable
	// domain). In the weak-policy sub-case the published policy is p=none
	// (monitor-only: receivers take no action on a failed check, so spoofed mail
	// is delivered unimpeded) — the DMARCPolicy field carries the policy token
	// and DMARCURI is empty. The two sub-cases are distinguished by which of
	// DMARCPolicy / DMARCURI is set.
	VectorDMARC Vector = "dmarc"
	// VectorAXFR: a delegated nameserver allows an unauthenticated DNS zone
	// transfer (AXFR), leaking every record in the zone to any client. It is a
	// direct information disclosure and a force-multiplier for the other vectors.
	VectorAXFR Vector = "axfr"
)

// Confidence is the three-tier certainty model from the v1.0 handoff.
//
//	Confirmed  Fingerprint match on a definitive signal (e.g. S3's "bucket does
//	           not exist"), or a fingerprint match plus active verification.
//	Likely     Fingerprint match only; the signal is not by itself conclusive.
//	Potential  DNS-only signal (NXDOMAIN, SERVFAIL, REFUSED) with no fingerprint
//	           match — a dangling record pointing at an unknown service.
type Confidence string

const (
	Confirmed Confidence = "CONFIRMED"
	Likely    Confidence = "LIKELY"
	Potential Confidence = "POTENTIAL"
)

// rank orders the three confidence tiers from weakest to strongest so they can
// be compared with AtLeast. An unrecognised value ranks 0 (below Potential),
// which keeps a malformed confidence from ever satisfying a threshold.
func (c Confidence) rank() int {
	switch c {
	case Potential:
		return 1
	case Likely:
		return 2
	case Confirmed:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether c is at least as certain as min. It is the predicate
// behind the scanner's --min-confidence filter: Confirmed ≥ Likely ≥ Potential.
// An empty min is treated as "no threshold" and always passes.
func (c Confidence) AtLeast(min Confidence) bool {
	if min == "" {
		return true
	}
	return c.rank() >= min.rank()
}

// ParseConfidence maps a case-insensitive tier name ("confirmed", "likely",
// "potential") to its Confidence value. An empty string yields ("", true),
// meaning "no threshold". An unrecognised name yields ("", false).
func ParseConfidence(s string) (Confidence, bool) {
	switch s {
	case "":
		return "", true
	case "confirmed", "CONFIRMED", "Confirmed":
		return Confirmed, true
	case "likely", "LIKELY", "Likely":
		return Likely, true
	case "potential", "POTENTIAL", "Potential":
		return Potential, true
	default:
		return "", false
	}
}

// Finding is a single takeover candidate emitted by the scanner. It is the unit
// of JSONL output; see pkg/output for serialization. JSON field names match the
// handoff "Output" specification; vector-specific fields use omitempty so a
// CNAME finding serializes to exactly the documented shape.
type Finding struct {
	Subdomain   string     `json:"subdomain"`
	Vector      Vector     `json:"vector"`
	Service     string     `json:"service,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Fingerprint string     `json:"fingerprint,omitempty"`

	// CNAME is set for VectorCNAME findings: the dangling canonical target.
	CNAME string `json:"cname,omitempty"`
	// Nameservers is set for VectorNS findings: the delegated NS hostnames that
	// failed to answer authoritatively.
	Nameservers []string `json:"nameservers,omitempty"`
	// SPFInclude is set for VectorSPF findings: the claimable include: domain.
	SPFInclude string `json:"spf_include,omitempty"`
	// MXHosts is set for VectorMX findings: the dangling mail-exchanger hostnames.
	MXHosts []string `json:"mx_hosts,omitempty"`
	// DKIMSelector is set for VectorDKIM findings: the selector whose
	// _domainkey record is at risk (e.g. "s1" for s1._domainkey.example.com).
	DKIMSelector string `json:"dkim_selector,omitempty"`
	// DKIMKeyBits is set for the weak-key VectorDKIM sub-case: the bit length of
	// the inline RSA public key found at the selector when that length is below
	// the RFC 8301 1024-bit floor. It is zero (omitted) for the dangling-CNAME
	// sub-case, which is identified instead by the CNAME field.
	DKIMKeyBits int `json:"dkim_key_bits,omitempty"`
	// DMARCURI is set for the dangling-report-domain VectorDMARC sub-case: the
	// claimable rua/ruf report domain (the part after "mailto:...@").
	DMARCURI string `json:"dmarc_uri,omitempty"`
	// DMARCPolicy is set for the weak-policy VectorDMARC sub-case: the policy
	// token from the p= tag when it is "none" (monitor-only, no enforcement).
	// It is empty for the dangling-report-domain sub-case, which is identified
	// instead by the DMARCURI field.
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	// LeakedHosts is set for VectorAXFR findings: a deduplicated, sorted sample
	// of the owner names exposed by the zone transfer (capped; the full zone is
	// not serialised). For VectorAXFR, the leaking nameserver is in Service and
	// also the sole entry in Nameservers.
	LeakedHosts []string `json:"leaked_hosts,omitempty"`

	// Scheme records which scheme produced an HTTP-based match: "https" or
	// "http" (see handoff open question #4).
	Scheme string `json:"scheme,omitempty"`
	// Evidence is a short human-readable explanation of the underlying signal.
	Evidence string `json:"evidence,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}
