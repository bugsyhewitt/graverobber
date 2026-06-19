package confirm

import "crypto/tls"

// blastTLSConfig returns the TLS configuration used by the read-only
// blast-radius probes. InsecureSkipVerify is deliberate and mirrors
// pkg/detectors' rationale: a dangling or freshly-claimed provider edge
// characteristically serves a certificate that does not match the probed
// hostname, and the blast-radius probe must still observe the HTTP response
// (cookies, status) to characterize impact. This is a recon probe, not a
// trust-sensitive connection — graverobber never sends data the way a real
// client would; it only reads status codes and Set-Cookie scoping.
func blastTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // recon probe; see comment
}
