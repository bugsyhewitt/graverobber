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
	// VectorSPF: an SPF record is dangling, permissive, or exceeds the RFC 7208
	// §4.6.4 DNS-lookup cap. In the dangling sub-case an include:/redirect=/a:/mx:
	// directive references a domain that is unregistered and therefore claimable
	// (the SubdoMailing vector); the SPFInclude field carries the claimable
	// domain. In the permissive sub-case the record's "all" mechanism qualifies
	// as Pass (+all, or a bare "all" which RFC 7208 §4.6.2 treats as +all) —
	// authorising any host on the internet to send mail as the domain, leaving
	// it fully spoofable; the SPFAll field carries the offending mechanism
	// token. In the lookup-limit sub-case the record's DNS-querying mechanisms
	// (include, a, mx, ptr, exists, redirect=) total more than 10 across the
	// recursed evaluation, which RFC 7208 §4.6.4 mandates causes "permerror" at
	// every SPF-checking receiver — the SPF check hard-fails and the domain
	// becomes spoofable by omission as DMARC alignment collapses; the SPFLookups
	// field carries the offending count. The three sub-cases are distinguished
	// by which of SPFInclude / SPFAll / SPFLookups is set.
	VectorSPF Vector = "spf"
	// VectorMX: a dangling MX record points at a mail host that is NXDOMAIN or
	// belongs to a cloud mail provider whose hosted zone has been deleted.
	VectorMX Vector = "mx"
	// VectorDKIM: a DKIM selector (<selector>._domainkey.<domain>) is either
	// published as a CNAME whose target is NXDOMAIN (the ESP resource is gone
	// and an attacker who reclaims it can serve a DKIM key that signs spoofed
	// mail), published inline with an RSA public key whose modulus is below
	// the RFC 8301 1024-bit floor (an attacker who factors the short key can
	// forge DKIM signatures directly), or named with an embedded year that is
	// stale (>= 2 years older than the current year) — a rotation-hint signal
	// that the published key has not been rotated for years, compounding
	// key-compromise risk against the M3AAWG / NIST SP 800-177 annual-rotation
	// recommendation. The DKIMKeyBits / DKIMStaleYear fields distinguish the
	// sub-cases.
	VectorDKIM Vector = "dkim"
	// VectorDMARC: a DMARC policy at _dmarc.<domain> is either weak or dangling.
	// In the dangling sub-case a rua=/ruf= report URI points at an NXDOMAIN host —
	// either a mailto: address domain or an https: collector host (the two report
	// transports RFC 7489 §A.5 registers) — and an attacker who claims it
	// intercepts every DMARC aggregate/forensic report sent for the target
	// (DMARCURI carries the claimable host). In the weak-policy sub-case the
	// published policy is p=none
	// (monitor-only: receivers take no action on a failed check, so spoofed mail
	// is delivered unimpeded) — the DMARCPolicy field carries the policy token
	// and DMARCURI is empty. The two sub-cases are distinguished by which of
	// DMARCPolicy / DMARCURI is set.
	VectorDMARC Vector = "dmarc"
	// VectorAXFR: a delegated nameserver allows an unauthenticated DNS zone
	// transfer (AXFR), leaking every record in the zone to any client. It is a
	// direct information disclosure and a force-multiplier for the other vectors.
	VectorAXFR Vector = "axfr"
	// VectorCAA: a domain's CAA (Certification Authority Authorization, RFC 8659)
	// record set is misconfigured. In the dangling sub-case an issue/issuewild
	// tag names a CA domain that is NXDOMAIN — an attacker who registers that
	// domain controls a CA the policy authorises to issue certificates for the
	// target (the CAAIssuer field carries the claimable domain). In the
	// dangling-iodef sub-case an iodef= tag names a report URL (mailto: or
	// http(s)://) whose host is NXDOMAIN — an attacker who registers it intercepts
	// the CAA violation reports a CA would send (the claimable host is likewise
	// carried in CAAIssuer; the Evidence string names the iodef tag). In the
	// permissive sub-case a CAA record set exists but explicitly authorises ANY
	// CA to issue (an issue/issuewild tag whose value is "*"), defeating the
	// purpose of publishing CAA at all. The CAAIssuer field and the Evidence
	// string together distinguish the sub-cases.
	VectorCAA Vector = "caa"
	// VectorTLSA: a domain publishes a DANE TLSA record (RFC 6698 / RFC 7672)
	// pinning the TLS certificate of a mail exchanger, but the MX host the pin
	// covers is NXDOMAIN — a dangling DANE pin. Because DANE for SMTP mandates
	// DNSSEC, the stale pin is authenticated: an attacker who reclaims the gone
	// mail host can present a certificate that matches the published TLSA
	// association and be trusted by DANE-validating senders, while in the
	// meantime the orphaned pin hard-fails delivery from every DANE sender. The
	// TLSAName field carries the DANE-prefixed owner name (e.g.
	// "_25._tcp.mx.example.com") and MXHosts carries the dangling mail host.
	VectorTLSA Vector = "tlsa"
	// VectorMTASTS: a domain advertises SMTP MTA-STS (RFC 8461) via a TXT policy
	// signal at _mta-sts.<domain> but its policy host mta-sts.<domain> — where the
	// policy file is served over HTTPS — is NXDOMAIN, a dangling MTA-STS host. An
	// attacker who reclaims the gone host can serve a forged policy ("mode: none"
	// to disable TLS enforcement, or an attacker-controlled "mx:" list to steer
	// inbound mail), defeating the downgrade protection MTA-STS exists to provide.
	// The dangling policy host is carried in Service and the claimable CNAME
	// target (or the policy host itself) in CNAME.
	VectorMTASTS Vector = "mtasts"
	// VectorBIMI: a domain advertises BIMI (Brand Indicators for Message
	// Identification) via a TXT record at <selector>._bimi.<domain> whose l= logo
	// URL or a= VMC-certificate URL points at a host that is NXDOMAIN — a dangling
	// BIMI asset host. Mail clients that support BIMI fetch and display the logo
	// (and validate the VMC) next to the authenticated sender; an attacker who
	// reclaims the gone asset host can serve a forged brand logo or VMC, turning
	// BIMI — a trust-signalling feature — into a brand-impersonation surface that
	// makes phishing mail look more legitimate. The dangling asset host is carried
	// in BIMIURIHost and the BIMI owner name (e.g. "default._bimi.example.com") in
	// Service.
	VectorBIMI Vector = "bimi"
	// VectorDNSSEC: a domain's DNSSEC delegation is broken or cryptographically
	// weak. In the orphaned-DS sub-case the PARENT zone publishes a DS
	// (Delegation Signer, RFC 4034) record committing every validating resolver to
	// an authenticated DNSSEC chain into the domain's zone, but the domain itself
	// publishes NO DNSKEY — an orphaned DS; the chain of trust cannot be built,
	// so every DNSSEC-validating resolver (the default at Google Public DNS,
	// Cloudflare 1.1.1.1, Quad9, and most ISPs) returns SERVFAIL for the entire
	// zone (a self-inflicted denial of service, typically caused by disabling
	// DNSSEC at the child or migrating DNS providers without first removing the
	// DS at the registrar). The orphaned DS key tags are carried in DSKeyTags. In
	// the weak-algorithm sub-case the chain is intact but at least one DNSKEY or
	// DS uses an algorithm RFC 8624 forbids ("MUST NOT") or deprecates ("NOT
	// RECOMMENDED") — RSAMD5 (1), DSA/SHA-1 (3), RSASHA1 (5), DSA-NSEC3-SHA1 (6),
	// RSASHA1-NSEC3-SHA1 (7), ECC-GOST (12), or a DS digest type of SHA-1 (1);
	// the cryptography is broken or deprecated enough that a well-resourced
	// attacker can forge a valid-looking chain. The offending algorithm names are
	// carried in DNSSECWeakAlgs. The two sub-cases are distinguished by which of
	// DSKeyTags (orphan) or DNSSECWeakAlgs (weak algorithm) is set; the Evidence
	// string also names the sub-case.
	VectorDNSSEC Vector = "dnssec"
	// VectorTLSRPT: a domain advertises SMTP TLS Reporting (TLSRPT, RFC 8460) via
	// a "v=TLSRPTv1" TXT record at _smtp._tls.<domain> whose rua= report
	// destination — a mailto: address domain or an https: collector host — is
	// NXDOMAIN, a dangling report destination. TLSRPT is the feedback channel that
	// surfaces SMTP TLS-negotiation failures (the failures an attacker mounting a
	// TLS downgrade against the domain's inbound mail causes); an attacker who
	// reclaims the gone destination receives every report sent for the target,
	// gaining delivery-counterparty reconnaissance and a live view of the very
	// downgrade failures that would otherwise alert the domain owner. This is the
	// same dangling-report-destination pattern the DMARC rua/ruf vector covers,
	// applied to the SMTP-TLS reporting plane. The dangling report host is carried
	// in TLSRPTURIHost and the TLSRPT owner name (e.g. "_smtp._tls.example.com") in
	// Service.
	VectorTLSRPT Vector = "tlsrpt"
	// VectorAutodiscover: a domain's mail-client autoconfiguration host —
	// autodiscover.<domain> (Microsoft Exchange/Outlook Autodiscover) or
	// autoconfig.<domain> (Mozilla Thunderbird and the general convention) — is
	// published (commonly as a CNAME to a hosted-mail provider) but resolves to
	// NXDOMAIN, a dangling autoconfiguration host. Mail clients fetch their
	// incoming/outgoing server settings from these hosts automatically during
	// account setup; an attacker who reclaims the gone host serves a forged
	// autoconfiguration payload that points the client at an attacker-controlled
	// IMAP/SMTP server and prompts the user for mailbox credentials — a silent
	// credential-harvesting and mail-interception surface, the same dangling-host
	// pattern the CNAME/MX/MTA-STS/TLSRPT vectors cover, applied to the mail-client
	// autoconfiguration plane. The dangling host is carried in Service and the
	// claimable CNAME target (or the host itself) in CNAME.
	VectorAutodiscover Vector = "autodiscover"
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
	// SPFInclude is set for the dangling VectorSPF sub-case: the claimable
	// include:/redirect=/a:/mx: domain.
	SPFInclude string `json:"spf_include,omitempty"`
	// SPFAll is set for the permissive VectorSPF sub-case: the offending "all"
	// mechanism token ("+all" or a bare "all") whose qualifier is Pass, which
	// authorises any host to send mail as the domain. It is empty for the
	// dangling sub-case, which is identified instead by the SPFInclude field.
	SPFAll string `json:"spf_all,omitempty"`
	// SPFLookups is set for the lookup-limit-exceeded VectorSPF sub-case: the
	// total number of DNS-querying mechanisms and modifiers evaluated across the
	// record and its recursed include:/redirect= policies (include, a, mx, ptr,
	// exists, redirect=, per RFC 7208 §4.6.4). It is reported only when the
	// count exceeds the §4.6.4 cap of 10 — beyond that, every SPF-checking
	// receiver returns "permerror" and the domain's SPF check hard-fails, taking
	// down DMARC alignment and exposing the domain to spoofing-by-omission. The
	// field is zero (omitted) for every other sub-case.
	SPFLookups int `json:"spf_lookups,omitempty"`
	// SPFPtr is set for the deprecated-ptr-mechanism VectorSPF sub-case: the
	// offending SPF token containing a "ptr" mechanism (a bare "ptr" or a
	// "ptr:<domain>" form, with any qualifier prefix preserved, e.g. "+ptr" or
	// "-ptr:example.com"). RFC 7208 §5.5 explicitly discourages use of the ptr
	// mechanism — "SHOULD NOT be published" — because it is slow, unreliable in
	// the face of DNS errors, and places an unfair load on the in-addr.arpa /
	// ip6.arpa name servers. Implementations are RECOMMENDED to ignore it (some
	// SPF receivers already do, returning permerror or treating it as a no-op),
	// which makes the publisher's SPF result effectively undefined on those
	// receivers — a present-but-broken email-auth term, the same disposition
	// class as p=none and the §4.6.4 lookup-limit breach. The field is empty
	// for every other sub-case.
	SPFPtr string `json:"spf_ptr,omitempty"`
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
	// DKIMStaleYear is set for the rotation-hint VectorDKIM sub-case: the
	// 4-digit year graverobber extracted from the selector name (e.g. 2019 for
	// a selector "dkim2019" or "mar2019") when that year is at least
	// staleSelectorYearGap years older than the current year. It is a strong
	// hint that the published key has not been rotated since that year and is
	// stale against the M3AAWG sender BCP / NIST SP 800-177 annual DKIM
	// rotation recommendation; a multi-year-old key compounds any past
	// compromise into a still-live forgery surface. The field is zero
	// (omitted) for every other sub-case, which are distinguished by CNAME
	// (dangling delegation) or DKIMKeyBits (weak inline key).
	DKIMStaleYear int `json:"dkim_stale_year,omitempty"`
	// DMARCURI is set for the dangling-report-host VectorDMARC sub-case: the
	// claimable rua/ruf report host — a mailto: address domain (the part after
	// "mailto:...@") or an https: collector host (the URL authority).
	DMARCURI string `json:"dmarc_uri,omitempty"`
	// DMARCPolicy is set for the weak-policy VectorDMARC sub-case: the policy
	// token from the p= tag when it is "none" (monitor-only, no enforcement).
	// It is empty for the dangling-report-domain sub-case, which is identified
	// instead by the DMARCURI field.
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	// DMARCSubdomainPolicy is set for the weak-subdomain-policy VectorDMARC
	// sub-case: the explicit sp= tag value when it is "none" and the parent
	// policy (p=) is "reject" or "quarantine". RFC 7489 §6.3 defines sp= as
	// the subdomain policy override: when sp=none is present, every subdomain
	// of the target is freely spoofable even if the parent domain has strong
	// enforcement (p=reject/quarantine). This is the "split enforcement"
	// misconfiguration — a domain appears DMARC-protected at the apex while
	// all subdomains remain spoofable (the precondition for subdomain phishing
	// and business-email-compromise from subdomains). The three sub-cases are
	// distinguished by which field is set: DMARCPolicy (p=none on parent),
	// DMARCSubdomainPolicy (sp=none with enforcing parent p=), or DMARCURI
	// (dangling report host).
	DMARCSubdomainPolicy string `json:"dmarc_subdomain_policy,omitempty"`
	// CAAIssuer is set for the two dangling VectorCAA sub-cases: the claimable
	// CA domain named by an issue=/issuewild= tag whose host is NXDOMAIN, or the
	// claimable report host parsed from an iodef= tag's URL (mailto: or http(s)://)
	// whose host is NXDOMAIN. The Evidence string distinguishes the issuer case
	// (certificate mis-issuance) from the iodef case (report interception). It is
	// empty for the permissive-CAA sub-case (a "*" wildcard authorising any CA),
	// which is identified instead by the Evidence string.
	CAAIssuer string `json:"caa_issuer,omitempty"`
	// LeakedHosts is set for VectorAXFR findings: a deduplicated, sorted sample
	// of the owner names exposed by the zone transfer (capped; the full zone is
	// not serialised). For VectorAXFR, the leaking nameserver is in Service and
	// also the sole entry in Nameservers.
	LeakedHosts []string `json:"leaked_hosts,omitempty"`
	// TLSAName is set for VectorTLSA findings: the DANE-prefixed owner name of the
	// dangling TLSA record set (e.g. "_25._tcp.mx.example.com"). The dangling mail
	// host the pin covers is carried in MXHosts.
	TLSAName string `json:"tlsa_name,omitempty"`
	// BIMIURIHost is set for VectorBIMI findings: the hostname parsed out of a
	// BIMI l= (logo) or a= (VMC certificate) URL whose host is NXDOMAIN and
	// therefore reclaimable. The BIMI owner name is carried in Service; the
	// Evidence string names which tag (l= or a=) pointed at the dangling host.
	BIMIURIHost string `json:"bimi_uri_host,omitempty"`
	// DSKeyTags is set for VectorDNSSEC findings: the key tags of the orphaned DS
	// records published by the parent zone for the target. They identify the
	// stale delegation-signer records that must be removed at the registrar (or
	// matched by re-signing the child zone) to repair the broken DNSSEC chain.
	DSKeyTags []uint16 `json:"ds_key_tags,omitempty"`
	// TLSRPTURIHost is set for VectorTLSRPT findings: the hostname parsed out of a
	// TLSRPT rua= report destination (the domain after "@" for a mailto:
	// destination, or the URL host for an https: destination) whose host is
	// NXDOMAIN and therefore reclaimable. The TLSRPT owner name is carried in
	// Service.
	TLSRPTURIHost string `json:"tlsrpt_uri_host,omitempty"`
	// MTASTSMode is set for the weak-policy VectorMTASTS sub-case: the value of
	// the "mode:" field in the MTA-STS policy file at
	// https://mta-sts.<domain>/.well-known/mta-sts.txt when that mode is NOT
	// "enforce". RFC 8461 §3.2 defines three modes:
	//   - "enforce" (active TLS enforcement — the healthy state, not flagged)
	//   - "testing" (monitor-only: TLS failures are reported but mail is delivered
	//     regardless; SMTP senders may apply the policy but MUST NOT fail delivery)
	//   - "none" (completely disabled: senders MUST treat the policy as absent;
	//     this is the "turned off" state)
	// Both "none" and "testing" are the same disposition class as DMARC p=none:
	// TLS enforcement is not active, so the protection MTA-STS exists to provide
	// is absent (for "none") or advisory-only (for "testing"). The field is empty
	// for the dangling-host sub-case, which is identified instead by the CNAME
	// field. The two sub-cases are distinguished by which of MTASTSMode (weak
	// policy) or CNAME (dangling host) is set.
	MTASTSMode string `json:"mtasts_mode,omitempty"`
	// DNSSECWeakAlgs is set for the weak-algorithm VectorDNSSEC sub-case: the
	// human-readable names of the deprecated/forbidden DNSSEC algorithms (or DS
	// digest types) graverobber observed on the target's signed delegation, e.g.
	// "RSAMD5" (Algorithm 1, MUST NOT use), "RSASHA1" (Algorithm 5, NOT
	// RECOMMENDED), or "DS-SHA1" (DS digest type 1, NOT RECOMMENDED). Entries are
	// deduplicated and sorted so the finding is stable across runs regardless of
	// DNS answer ordering. The field is empty for the orphaned-DS sub-case, which
	// is identified instead by DSKeyTags + the absence of any child DNSKEY (the
	// Evidence string also distinguishes the two cases). Per RFC 8624 and the
	// IANA DNSSEC Algorithm Numbers registry these algorithms are
	// cryptographically broken or deprecated; their continued use lets a
	// well-resourced attacker forge a valid DNSSEC chain for the zone, defeating
	// the protection DNSSEC exists to provide.
	DNSSECWeakAlgs []string `json:"dnssec_weak_algs,omitempty"`

	// Scheme records which scheme produced an HTTP-based match: "https" or
	// "http" (see handoff open question #4).
	Scheme string `json:"scheme,omitempty"`
	// Evidence is a short human-readable explanation of the underlying signal.
	Evidence string `json:"evidence,omitempty"`

	// Rule is the stable machine identifier for the takeover class this finding
	// belongs to, used by the active confirmation pipeline and downstream
	// enrichment/reporting. It follows the form "takeover.<service>" for a CNAME
	// content takeover (e.g. "takeover.github-pages") and "takeover.ns.<provider>"
	// for the higher-severity dangling-NS delegation class (e.g.
	// "takeover.ns.route53"). It is set on the active (engine-produced) findings;
	// the legacy per-vector scanner leaves it empty, so it serializes only when
	// present and never alters the v1.0 finding shape.
	Rule string `json:"rule,omitempty"`
	// State is the takeover lifecycle state (detected / confirmed /
	// not_vulnerable). Empty on legacy detection-only findings; set by the engine
	// detector (detected) and advanced by the confirmer.
	State State `json:"state,omitempty"`
	// Severity is the impact class: "high" for a CNAME content takeover,
	// "critical" for a whole-zone dangling-NS takeover. Empty on legacy findings.
	Severity Severity `json:"severity,omitempty"`
	// Confirmation, when non-nil, carries the result of an active safe-claim
	// confirmation attempt: the served-canary evidence (the proof), reproduction,
	// blast radius, and release status. Nil for a detection-only finding.
	Confirmation *Confirmation `json:"confirmation,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}
