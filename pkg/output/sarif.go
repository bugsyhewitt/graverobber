package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// SARIF (Static Analysis Results Interchange Format) 2.1.0 is the OASIS-standard
// JSON schema that GitHub Code Scanning, Azure DevOps, and most security
// platforms ingest natively. A SarifWriter turns a graverobber scan into a
// single SARIF log so findings can be uploaded via github/codeql-action/
// upload-sarif and tracked as deduplicated security alerts in the repository's
// Security tab — making graverobber a CI-native takeover control rather than an
// ad-hoc command.
//
// Unlike JSONLWriter, which streams one object per finding, a SARIF log is a
// single document with a rule catalogue and a results array. SarifWriter
// therefore buffers findings on Write and emits the complete log on Close.
// Buffering is bounded by the number of findings in a scan (already held in
// memory by the emit path) and is safe for the scanner's concurrent Write calls.
const sarifVersion = "2.1.0"

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// toolInfoURI is graverobber's home, surfaced in the SARIF tool metadata so a
// reviewer can trace a result back to the scanner that produced it.
const toolInfoURI = "https://github.com/bugsyhewitt/graverobber"

// SarifWriter accumulates findings and renders a single SARIF 2.1.0 log on Close.
type SarifWriter struct {
	mu       sync.Mutex
	w        io.Writer
	version  string
	findings []finding.Finding
}

// NewSARIF returns a SarifWriter writing to w. version is graverobber's build
// version, recorded in the SARIF tool driver so an uploaded log is attributable
// to a specific release; pass "" when no version is available.
func NewSARIF(w io.Writer, version string) *SarifWriter {
	return &SarifWriter{w: w, version: version}
}

// Write buffers f for inclusion in the SARIF log emitted by Close.
func (s *SarifWriter) Write(f finding.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, f)
	return nil
}

// Close renders the buffered findings as a SARIF 2.1.0 log and writes it to the
// underlying writer. It is idempotent only in the sense that a second call emits
// an empty-results log; callers invoke it exactly once, as the Writer contract
// requires.
func (s *SarifWriter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, ruleIndex := s.buildRules()
	results := make([]sarifResult, 0, len(s.findings))
	for _, f := range s.findings {
		results = append(results, sarifResultFor(f, ruleIndex[string(f.Vector)]))
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "graverobber",
				InformationURI: toolInfoURI,
				Version:        s.version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildRules derives the SARIF rule catalogue from the vectors actually present
// in the buffered findings, returning the rule list and a map from vector name
// to its index in that list (SARIF results reference rules by index). Rules are
// emitted in a stable, sorted order so the log is deterministic.
func (s *SarifWriter) buildRules() ([]sarifRule, map[string]int) {
	seen := map[string]struct{}{}
	for _, f := range s.findings {
		seen[string(f.Vector)] = struct{}{}
	}
	vectors := make([]string, 0, len(seen))
	for v := range seen {
		vectors = append(vectors, v)
	}
	sort.Strings(vectors)

	rules := make([]sarifRule, 0, len(vectors))
	index := make(map[string]int, len(vectors))
	for i, v := range vectors {
		index[v] = i
		rules = append(rules, ruleForVector(finding.Vector(v)))
	}
	return rules, index
}

// vectorRuleText maps each detection vector to its SARIF rule name and the
// short/full descriptions surfaced in the Code Scanning UI.
var vectorRuleText = map[finding.Vector]struct {
	name, short, full string
}{
	finding.VectorCNAME: {
		"Dangling CNAME subdomain takeover",
		"A CNAME points at an unclaimed service resource.",
		"The subdomain's CNAME resolves to a service whose backing resource is unclaimed and re-creatable, allowing an attacker to claim it and serve content from the subdomain.",
	},
	finding.VectorNS: {
		"Dangling NS delegation takeover",
		"A delegated DNS zone has been deleted at the provider.",
		"The subdomain delegates DNS to a provider whose hosted zone has been deleted; an attacker who re-creates the zone controls all records for the subdomain.",
	},
	finding.VectorSPF: {
		"SPF dangling reference or permissive policy",
		"An SPF record references an unregistered domain or authorises any sender.",
		"The domain's SPF record is either dangling — an include:/redirect= directive points at an unregistered (NXDOMAIN) domain, so registering it lets an attacker authorise spoofed mail (the SubdoMailing vector) — or permissive: a Pass-qualified \"all\" mechanism (+all, or a bare \"all\") authorises every host on the internet to send mail as the domain, leaving it fully spoofable.",
	},
	finding.VectorMX: {
		"Dangling MX record takeover",
		"An MX record points at a dead mail host.",
		"The domain's MX record points at a mail host that is NXDOMAIN or whose cloud hosted-zone is deleted; an attacker who claims it receives inbound mail including password resets and 2FA codes.",
	},
	finding.VectorDKIM: {
		"DKIM selector weakness",
		"A DKIM selector is reclaimable (dangling CNAME) or publishes a weak RSA key.",
		"A DKIM selector is either published as a CNAME whose target is NXDOMAIN (an attacker who reclaims the ESP resource can serve a DKIM key that signs spoofed mail) or publishes an inline RSA key below the RFC 8301 1024-bit floor (an attacker who factors the short key can forge DKIM-passing signatures directly). Either way the attacker can sign mail that passes DKIM for the domain.",
	},
	finding.VectorDMARC: {
		"DMARC policy weakness or dangling report domain",
		"A DMARC policy is monitor-only (p=none) or names a claimable report domain.",
		"A DMARC policy is either p=none (monitor-only: receivers take no action on a failed DMARC check, so spoofed mail that fails SPF/DKIM is still delivered — the precondition for business-email-compromise and phishing) or its rua/ruf report URI points at an NXDOMAIN domain (an attacker who claims it intercepts every DMARC aggregate/forensic report sent for the domain).",
	},
	finding.VectorAXFR: {
		"Unauthenticated DNS zone transfer (AXFR)",
		"A nameserver allows unauthenticated AXFR.",
		"A delegated nameserver streams the full zone to any client over AXFR, leaking every subdomain, internal hostname, and infrastructure record — a direct information disclosure and a force-multiplier for the other takeover vectors.",
	},
	finding.VectorCAA: {
		"CAA misconfiguration",
		"A CAA record names a claimable CA domain or authorises any CA.",
		"A CAA (Certification Authority Authorization, RFC 8659) record set is misconfigured: an issue/issuewild tag either names a CA domain that is NXDOMAIN (an attacker who registers it can stand up a CA the policy authorises to issue certificates for the domain) or uses the wildcard \"*\" value that authorises any CA to issue — re-opening the man-in-the-middle TLS exposure CAA exists to close.",
	},
	finding.VectorTLSA: {
		"Dangling DANE TLSA pin",
		"A DANE TLSA record pins a mail host that is NXDOMAIN.",
		"A DANE TLSA record (RFC 6698 / RFC 7672) at _25._tcp.<mxhost> pins the TLS certificate of a mail exchanger that is NXDOMAIN. Because DANE for SMTP mandates DNSSEC the stale pin is authenticated: it hard-fails inbound mail from every DANE-validating sender, and an attacker who reclaims the gone mail host can present a certificate matching the published association to be trusted by DANE senders — a DANE-blessed mail-interception path.",
	},
	finding.VectorMTASTS: {
		"Dangling MTA-STS policy host",
		"An MTA-STS policy is advertised but its policy host is NXDOMAIN.",
		"A domain advertises SMTP MTA-STS (RFC 8461) via a \"v=STSv1\" TXT record at _mta-sts.<domain>, but its policy host mta-sts.<domain> — which serves the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt — is NXDOMAIN. An attacker who reclaims the dangling policy host can serve a forged policy that disables TLS enforcement (mode: none) or authorises an attacker-controlled MX, re-opening the active TLS-downgrade and mail-redirection attacks MTA-STS exists to close.",
	},
}

// ruleForVector builds the SARIF rule descriptor for a vector. Unknown vectors
// (forward compatibility) get a generic descriptor keyed by the vector tag.
func ruleForVector(v finding.Vector) sarifRule {
	text, ok := vectorRuleText[v]
	if !ok {
		return sarifRule{
			ID:                   "graverobber/" + string(v),
			Name:                 string(v),
			ShortDescription:     sarifText{Text: string(v) + " takeover candidate"},
			FullDescription:      sarifText{Text: string(v) + " takeover candidate"},
			DefaultConfiguration: sarifConfig{Level: "warning"},
			HelpURI:              toolInfoURI,
		}
	}
	return sarifRule{
		ID:                   "graverobber/" + string(v),
		Name:                 text.name,
		ShortDescription:     sarifText{Text: text.short},
		FullDescription:      sarifText{Text: text.full},
		DefaultConfiguration: sarifConfig{Level: "error"},
		HelpURI:              toolInfoURI,
	}
}

// sarifResultFor renders a finding as a SARIF result. ruleIndex is the finding
// vector's position in the run's rule catalogue.
func sarifResultFor(f finding.Finding, ruleIndex int) sarifResult {
	return sarifResult{
		RuleID:    "graverobber/" + string(f.Vector),
		RuleIndex: ruleIndex,
		Level:     sarifLevel(f.Confidence),
		Message:   sarifText{Text: sarifMessage(f)},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.Subdomain},
			},
			LogicalLocations: []sarifLogicalLocation{{
				Name: f.Subdomain,
				Kind: "resource",
			}},
		}},
		PartialFingerprints: map[string]string{
			// A stable fingerprint lets Code Scanning deduplicate the same
			// takeover candidate across re-scans instead of opening a new alert
			// each run. It is keyed on the immutable (subdomain, vector) pair.
			"graverobberCandidate/v1": f.Subdomain + "|" + string(f.Vector),
		},
		Properties: sarifResultProps{
			Confidence: string(f.Confidence),
			Vector:     string(f.Vector),
			Service:    f.Service,
		},
	}
}

// sarifLevel maps a graverobber confidence tier to a SARIF result level.
// CONFIRMED is an error (actionable, high-signal); LIKELY and POTENTIAL are
// warnings (worth triage, not yet proven).
func sarifLevel(c finding.Confidence) string {
	if c == finding.Confirmed {
		return "error"
	}
	return "warning"
}

// sarifMessage builds the human-readable result message, leading with the
// confidence tier and vector then appending the vector-specific evidence datum
// so a reviewer sees the dangling target without opening the raw finding.
func sarifMessage(f finding.Finding) string {
	detail := f.Service
	switch f.Vector {
	case finding.VectorCNAME:
		if f.CNAME != "" {
			detail = fmt.Sprintf("CNAME -> %s (%s)", f.CNAME, f.Service)
		}
	case finding.VectorSPF:
		switch {
		case f.SPFInclude != "":
			detail = "SPF include:" + f.SPFInclude
		case f.SPFAll != "":
			detail = "SPF " + f.SPFAll + " (permissive — any host)"
		}
	case finding.VectorNS:
		if len(f.Nameservers) > 0 {
			detail = fmt.Sprintf("NS %v", f.Nameservers)
		}
	case finding.VectorMX:
		if len(f.MXHosts) > 0 {
			detail = fmt.Sprintf("MX %v", f.MXHosts)
		}
	case finding.VectorDKIM:
		switch {
		case f.DKIMKeyBits > 0:
			detail = fmt.Sprintf("DKIM %s._domainkey weak %d-bit RSA key", f.DKIMSelector, f.DKIMKeyBits)
		case f.DKIMSelector != "":
			detail = fmt.Sprintf("DKIM %s._domainkey -> %s", f.DKIMSelector, f.CNAME)
		}
	case finding.VectorDMARC:
		switch {
		case f.DMARCPolicy != "":
			detail = "DMARC policy p=" + f.DMARCPolicy + " (monitor-only)"
		case f.DMARCURI != "":
			detail = "DMARC rua/ruf:" + f.DMARCURI
		}
	case finding.VectorAXFR:
		if f.Service != "" {
			detail = fmt.Sprintf("AXFR %s leaked %d host(s)", f.Service, len(f.LeakedHosts))
		}
	case finding.VectorCAA:
		if f.CAAIssuer != "" {
			detail = "CAA issuer " + f.CAAIssuer + " is NXDOMAIN (claimable)"
		} else {
			detail = "CAA authorises any CA (permissive)"
		}
	case finding.VectorTLSA:
		if len(f.MXHosts) > 0 {
			detail = fmt.Sprintf("DANE TLSA %s pins %s which is NXDOMAIN (dangling pin)", f.TLSAName, f.MXHosts[0])
		} else {
			detail = "DANE TLSA " + f.TLSAName + " dangling pin"
		}
	case finding.VectorMTASTS:
		detail = fmt.Sprintf("MTA-STS policy host %s is NXDOMAIN (dangling — reclaimable target %s)", f.Service, f.CNAME)
	}
	msg := fmt.Sprintf("[%s] %s takeover candidate on %s", f.Confidence, f.Vector, f.Subdomain)
	if detail != "" {
		msg += ": " + detail
	}
	return msg
}

// --- SARIF 2.1.0 document types (minimal subset graverobber emits) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifText   `json:"shortDescription"`
	FullDescription      sarifText   `json:"fullDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
	HelpURI              string      `json:"helpUri,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProps  `json:"properties,omitempty"`
}

type sarifResultProps struct {
	Confidence string `json:"confidence,omitempty"`
	Vector     string `json:"vector,omitempty"`
	Service    string `json:"service,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// compile-time interface check.
var _ Writer = (*SarifWriter)(nil)
