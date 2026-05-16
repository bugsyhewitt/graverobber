// Package verifier performs active, service-specific confirmation of takeover
// candidates — for example an unauthenticated S3 bucket probe or a GitHub Pages
// repository-existence check.
//
// v1.0 ships only NoopVerifier (see handoff open question #2): findings keep
// the confidence assigned by the fingerprint stage, which is sufficient because
// definitive body strings (e.g. S3's "bucket does not exist") and NXDOMAIN-type
// signals already justify the Confirmed tier without a network round trip.
// Real active verification — and the credential/rate-limit handling it
// requires — is deferred to v1.1. The Verifier interface is the integration
// seam: v1.1 adds concrete implementations without changing pkg/scanner.
package verifier

import (
	"context"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// Verifier optionally upgrades or downgrades a finding's confidence by actively
// probing the suspected service.
type Verifier interface {
	// Verify inspects f and returns the confidence after active checks. It may
	// return f.Confidence unchanged when no active check applies to f.Vector or
	// f.Service.
	Verify(ctx context.Context, f finding.Finding) (finding.Confidence, error)
}

// NoopVerifier returns each finding's confidence unchanged. It is the v1.0
// default wired into pkg/scanner.
type NoopVerifier struct{}

// Verify returns f.Confidence unchanged.
func (NoopVerifier) Verify(_ context.Context, f finding.Finding) (finding.Confidence, error) {
	return f.Confidence, nil
}

// compile-time interface check.
var _ Verifier = NoopVerifier{}
