package fingerprints

// SignatureVerifier validates the integrity and authenticity of a fingerprint
// payload before it is trusted and written to the local cache.
//
// v1.0 ships NoopSignatureVerifier (see handoff open question #3): transport
// integrity is provided by HTTPS to raw.githubusercontent.com, and the
// canonical upstream source is itself unsigned, so there is no upstream
// signature to check. This interface is the integration seam — v1.1 can
// introduce ed25519-signed graverobber fingerprint releases by providing a new
// implementation, with zero changes at any call site.
type SignatureVerifier interface {
	// Verify returns nil if payload is acceptable, or an error describing why
	// the payload must be rejected.
	Verify(payload []byte) error
}

// NoopSignatureVerifier accepts any payload. It is the v1.0 default.
type NoopSignatureVerifier struct{}

// Verify always returns nil.
func (NoopSignatureVerifier) Verify([]byte) error { return nil }

// compile-time interface check.
var _ SignatureVerifier = NoopSignatureVerifier{}
