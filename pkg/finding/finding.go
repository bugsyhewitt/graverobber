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
	// VectorDKIM: a DKIM selector (<selector>._domainkey.<domain>) is published
	// as a CNAME whose target is NXDOMAIN — the ESP resource is gone and an
	// attacker who reclaims it can serve a DKIM key that signs spoofed mail.
	VectorDKIM Vector = "dkim"
	// VectorDMARC: a DMARC policy at _dmarc.<domain> carries a rua=/ruf= report
	// URI whose domain is NXDOMAIN — an attacker who claims it intercepts every
	// DMARC aggregate/forensic report sent for the target.
	VectorDMARC Vector = "dmarc"
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
	// _domainkey CNAME is dangling (e.g. "s1" for s1._domainkey.example.com).
	DKIMSelector string `json:"dkim_selector,omitempty"`
	// DMARCURI is set for VectorDMARC findings: the claimable rua/ruf report
	// domain (the part after "mailto:...@").
	DMARCURI string `json:"dmarc_uri,omitempty"`

	// Scheme records which scheme produced an HTTP-based match: "https" or
	// "http" (see handoff open question #4).
	Scheme string `json:"scheme,omitempty"`
	// Evidence is a short human-readable explanation of the underlying signal.
	Evidence string `json:"evidence,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}
