package finding

import "time"

// State is the takeover lifecycle state shared across the detect → confirm
// pipeline. It is graverobber's realization of the three-state model the
// takeover class needs once active confirmation exists:
//
//	Detected       A multi-signal detection (a fingerprint match PLUS at least
//	               one independent unclaimed-backend signal — NXDOMAIN on the
//	               CNAME target, a TLS-certificate mismatch, or a DNS chain that
//	               ends at a deprovisioned provider edge). This is a credible
//	               candidate worth confirming, NOT proof. A bare fingerprint
//	               match with no independent signal never reaches Detected (the
//	               false-positive guard).
//	Confirmed      The dangling resource was safely claimed, a unique canary was
//	               served on a hidden path, control was demonstrated by fetching
//	               the FQDN and observing the canary, and the resource was then
//	               released. Only a served-and-reflected canary is proof.
//	NotVulnerable  A confirmation attempt proved the candidate is NOT actually
//	               takeoverable — the resource could not be claimed (the provider
//	               fixed its policy or the name is already owned), or it was
//	               claimed but the FQDN did not route to it / did not reflect the
//	               canary. A real, trustworthy negative — a disproof, not a
//	               silent skip.
//
// State complements Confidence rather than replacing it: Confidence is the
// detection-stage certainty tier (CONFIRMED/LIKELY/POTENTIAL) the v1.0 scanner
// has always emitted, while State tracks where a finding sits in the active
// confirmation lifecycle. A finding may be Confidence==CONFIRMED (a definitive
// fingerprint body string) yet State==Detected (no canary served yet); only a
// served canary advances it to State==Confirmed.
type State string

const (
	// StateDetected is a multi-signal detection: credible, not proven.
	StateDetected State = "detected"
	// StateConfirmed is a claim + served canary + demonstrated control + release.
	StateConfirmed State = "confirmed"
	// StateNotVulnerable is a real negative: a confirmation attempt disproved the
	// candidate (not claimable, or claimed-but-not-routing/not-reflecting).
	StateNotVulnerable State = "not_vulnerable"
)

// Severity is the impact class a confirmed (or detected) takeover carries. It is
// distinct from Confidence (how sure we are) — Severity is how bad it is if real.
//
// The takeover class has two severity tiers that are categorically different:
//
//	SeverityHigh      Content takeover of a single record (a dangling CNAME whose
//	                  provider resource is reclaimable). The attacker controls
//	                  what one subdomain serves.
//	SeverityCritical  Whole-zone takeover (a dangling NS delegation whose managed-
//	                  DNS zone is reclaimable). The attacker controls EVERY record
//	                  under the subdomain — A/AAAA, MX (mail), TXT (SPF), wildcards
//	                  — not just one record's content. This is strictly worse than
//	                  a CNAME content takeover and is tracked as its own class so
//	                  it is never flattened into the high tier.
type Severity string

const (
	// SeverityHigh is content takeover of a single dangling record (CNAME class).
	SeverityHigh Severity = "high"
	// SeverityCritical is whole-zone takeover (dangling-NS delegation class).
	SeverityCritical Severity = "critical"
)

// Confirmation is the result of an active, safe takeover confirmation attached
// to a Finding. It is populated only when graverobber actually ran the confirmer
// against the finding (the active confirm path); a pure detection leaves it nil,
// which is why it is a pointer with omitempty — a detect-only finding serializes
// to exactly the v1.0 shape with no confirmation key.
//
// The fields mirror what a bug-bounty triager needs to pay the report: the
// method used, the evidence (the served canary URL — the proof), a reproduction
// recipe, and the blast radius (what the takeover grants — cookie scope, OAuth
// redirect potential, ACME issuance). The presence of Evidence with a canary URL
// is the difference between a closed "potential" and a paid "confirmed".
type Confirmation struct {
	// State is the lifecycle outcome of the confirmation attempt.
	State State `json:"state"`
	// Method is how control was demonstrated, e.g. "canary_claim".
	Method string `json:"method,omitempty"`
	// Evidence is the proof: the served canary URL and the fact control was
	// demonstrated, plus a note that the claimed resource was released. For a
	// not_vulnerable outcome it records why the candidate was disproved.
	Evidence string `json:"evidence,omitempty"`
	// Reproduction is a short recipe a triager can follow to reproduce the proof.
	Reproduction string `json:"reproduction,omitempty"`
	// BlastRadius characterizes what the takeover grants — content control plus,
	// where applicable, shared-cookie scope (session theft), OAuth redirect_uri
	// candidacy (account takeover), and ACME certificate issuability (valid-TLS
	// phishing). It is what turns "confirmed takeover" into a severity.
	BlastRadius string `json:"blast_radius,omitempty"`
	// Released reports whether the claimed resource was successfully released
	// (deleted) after the proof. A confirmation that claimed a resource MUST
	// release it; a false here means release failed and is a loud incident, not a
	// silent omission.
	Released bool `json:"released"`
	// ConfirmedAt is when the confirmation completed.
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`
}
