package confirm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// newConfirmer wires a TakeoverConfirmer for tests: the given adapter under key
// "mock", a canary engine whose reflector consults the mock's in-memory served
// map, an active gate scoped to example.com, and a deterministic blast radius.
func newConfirmer(t *testing.T, m *MockAdapter) *TakeoverConfirmer {
	t.Helper()
	canaries := NewCanaries(WithReflector(m.MockReflector()))
	return NewTakeoverConfirmer(
		WithAdapter("mock", m),
		WithCanaries(canaries),
		WithGate(NewGate(true, []string{"example.com"})),
		WithBlastRadius(func(_ context.Context, fqdn string) string {
			return "content control of " + fqdn + "; ACME cert issuable (valid-TLS phishing surface)"
		}),
	)
}

// detectedFinding builds a detected CNAME finding whose Service maps to the mock
// adapter key.
func detectedFinding(host string) *finding.Finding {
	return &finding.Finding{
		Subdomain: host,
		Vector:    finding.VectorCNAME,
		Service:   "mock",
		Rule:      "takeover.mock",
		State:     finding.StateDetected,
		Severity:  finding.SeverityHigh,
	}
}

// TestConfirm_HappyPath: claim + serve + reflect + release → confirmed, with
// served-canary evidence, reproduction, blast radius, and a clean release.
func TestConfirm_HappyPath(t *testing.T) {
	m := NewMockAdapter()
	c := newConfirmer(t, m)
	f := detectedFinding("assets.example.com")

	r, err := c.Confirm(context.Background(), f)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !r.Confirmed {
		t.Fatalf("expected confirmed, got %+v", r)
	}
	if !strings.Contains(r.Evidence, "served canary") || !strings.Contains(r.Evidence, "/.well-known/nmc-") {
		t.Errorf("evidence should name the served canary URL, got %q", r.Evidence)
	}
	if !strings.Contains(r.Evidence, "released") {
		t.Errorf("evidence should note the resource was released, got %q", r.Evidence)
	}
	if r.Reproduction == "" || r.BlastRadius == "" {
		t.Errorf("confirmed result must carry reproduction and blast radius, got %+v", r)
	}
	if !r.Released {
		t.Errorf("resource must be released on the happy path")
	}
	// Release discipline: claimed once, released once, nothing left claimed.
	if m.ClaimCount() != 1 || m.ReleaseCount() != 1 || m.StillClaimed() != 0 {
		t.Errorf("release discipline: claim=%d release=%d stillClaimed=%d, want 1/1/0",
			m.ClaimCount(), m.ReleaseCount(), m.StillClaimed())
	}
	if len(c.Tracker().Outstanding()) != 0 {
		t.Errorf("no artifacts should be outstanding after a clean release")
	}
}

// TestConfirm_EvidenceInvariant: the Packet-05 D2 invariant carries to the
// takeover layer — a claim that serves but whose canary is NOT reflected must NOT
// be confirmed. No served-and-observed canary, no `confirmed`. (Appendix K's
// TestConfirmEvidenceInvariant.) The resource is still released.
func TestConfirm_EvidenceInvariant(t *testing.T) {
	m := NewMockAdapter()
	m.Reflect = false // serves, but the FQDN does not reflect the canary
	c := newConfirmer(t, m)
	f := detectedFinding("assets.example.com")

	r, err := c.Confirm(context.Background(), f)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if r.Confirmed {
		t.Fatal("D2 VIOLATION: claimed-but-canary-not-reflected must NOT be confirmed")
	}
	if !r.Disproved {
		t.Errorf("a served-but-not-reflected claim is a real negative (disproved), got %+v", r)
	}
	if m.ReleaseCount() != 1 || m.StillClaimed() != 0 {
		t.Errorf("the claimed resource must be released even when not confirmed (release=%d stillClaimed=%d)",
			m.ReleaseCount(), m.StillClaimed())
	}
	if !r.Released {
		t.Errorf("Released should be true after a clean release on the disproved path")
	}
}

// TestConfirm_NotClaimable: a resource that cannot be claimed (provider fixed /
// already owned) is a real disproof, and nothing is released (nothing claimed).
func TestConfirm_NotClaimable(t *testing.T) {
	m := NewMockAdapter()
	m.Claimable = false
	c := newConfirmer(t, m)

	r, err := c.Confirm(context.Background(), detectedFinding("assets.example.com"))
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !r.Disproved || r.Confirmed {
		t.Errorf("not-claimable must be disproved, not confirmed: %+v", r)
	}
	if m.ReleaseCount() != 0 {
		t.Errorf("nothing was claimed, so Release must not be called, got %d", m.ReleaseCount())
	}
	if !strings.Contains(r.Evidence, "not claimable") {
		t.Errorf("evidence should explain the disproof, got %q", r.Evidence)
	}
}

// TestConfirm_ServeFails: a claim that cannot bind the FQDN (DNS not routing) is
// a disproof, and the claimed resource is released.
func TestConfirm_ServeFails(t *testing.T) {
	m := NewMockAdapter()
	m.ServeFail = true
	c := newConfirmer(t, m)

	r, err := c.Confirm(context.Background(), detectedFinding("assets.example.com"))
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !r.Disproved || r.Confirmed {
		t.Errorf("serve-fail must be disproved: %+v", r)
	}
	if m.ClaimCount() != 1 || m.ReleaseCount() != 1 || m.StillClaimed() != 0 {
		t.Errorf("claimed resource must be released after serve failure (claim=%d release=%d stillClaimed=%d)",
			m.ClaimCount(), m.ReleaseCount(), m.StillClaimed())
	}
}

// TestConfirm_ReleaseFailureIsLoud: a release failure returns *ErrReleaseFailed
// so the run fails loudly, the artifact stays tracked (Outstanding), and the
// failure hook fires. (§12 acceptance #7; A2.)
func TestConfirm_ReleaseFailureIsLoud(t *testing.T) {
	m := NewMockAdapter()
	m.ReleaseErr = errors.New("provider API 500")
	tracker := NewArtifactTracker()
	var hookFired bool
	tracker.OnReleaseFailure(func(_ Artifact, _ error) { hookFired = true })

	canaries := NewCanaries(WithReflector(m.MockReflector()))
	c := NewTakeoverConfirmer(
		WithAdapter("mock", m),
		WithCanaries(canaries),
		WithTracker(tracker),
		WithGate(NewGate(true, []string{"example.com"})),
		WithBlastRadius(func(_ context.Context, fqdn string) string { return "x" }),
	)

	r, err := c.Confirm(context.Background(), detectedFinding("assets.example.com"))
	var relErr *ErrReleaseFailed
	if !errors.As(err, &relErr) {
		t.Fatalf("a release failure must return *ErrReleaseFailed, got %v", err)
	}
	if !strings.Contains(relErr.Error(), "manual cleanup required") {
		t.Errorf("the error must demand manual cleanup, got %q", relErr.Error())
	}
	if r.Released {
		t.Errorf("Released must be false on a release failure")
	}
	if !hookFired {
		t.Errorf("the release-failure hook must fire")
	}
	out := tracker.Outstanding()
	if len(out) != 1 {
		t.Fatalf("the un-released artifact must remain tracked, got %d outstanding", len(out))
	}
	if out[0].Handle == "" {
		t.Errorf("the outstanding artifact must carry its handle for manual cleanup")
	}
}

// TestConfirm_ClaimError: a transport/auth error during claim is an error (not a
// false confirm, not a disproof), and nothing is left claimed.
func TestConfirm_ClaimError(t *testing.T) {
	m := NewMockAdapter()
	m.ClaimErr = errors.New("github 401 unauthorized")
	c := newConfirmer(t, m)

	r, err := c.Confirm(context.Background(), detectedFinding("assets.example.com"))
	if err == nil {
		t.Fatal("a claim error must surface as an error")
	}
	if r.Confirmed {
		t.Errorf("a claim error must never be confirmed")
	}
	if m.StillClaimed() != 0 {
		t.Errorf("a failed claim leaves nothing claimed, got %d", m.StillClaimed())
	}
}

// TestConfirm_GateFailClosed: with no gate (or an inactive gate), Confirm refuses
// before touching the adapter.
func TestConfirm_GateFailClosed(t *testing.T) {
	m := NewMockAdapter()
	// No gate supplied → fail-closed.
	c := NewTakeoverConfirmer(WithAdapter("mock", m))

	_, err := c.Confirm(context.Background(), detectedFinding("assets.example.com"))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("missing/inactive gate must fail closed with ErrNotAuthorized, got %v", err)
	}
	if m.ClaimCount() != 0 {
		t.Errorf("the adapter must not be touched when unauthorized, got claim=%d", m.ClaimCount())
	}
}

// TestConfirm_GateOutOfScope: an active gate refuses a target whose apex is not
// allow-listed.
func TestConfirm_GateOutOfScope(t *testing.T) {
	m := NewMockAdapter()
	c := NewTakeoverConfirmer(
		WithAdapter("mock", m),
		WithGate(NewGate(true, []string{"example.com"})),
	)
	_, err := c.Confirm(context.Background(), detectedFinding("assets.NOT-ALLOWED.com"))
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("an out-of-scope target must be refused with ErrOutOfScope, got %v", err)
	}
	if m.ClaimCount() != 0 {
		t.Errorf("the adapter must not be touched for an out-of-scope target")
	}
}

// TestConfirm_NoAdapterLeavesDetected: a finding for a provider with no claim
// adapter is left detected (honest), not confirmed and not an error.
func TestConfirm_NoAdapterLeavesDetected(t *testing.T) {
	c := NewTakeoverConfirmer(
		WithGate(NewGate(true, []string{"example.com"})),
		// no adapters registered
	)
	f := detectedFinding("assets.example.com")
	f.Service = "SomeProviderWithoutAdapter"

	r, err := c.Confirm(context.Background(), f)
	if err != nil {
		t.Fatalf("a missing adapter is not an error, got %v", err)
	}
	if r.Confirmed || r.Disproved {
		t.Errorf("a missing adapter must leave the finding detected (neither confirmed nor disproved): %+v", r)
	}
	if !strings.Contains(r.Evidence, "no claim adapter") {
		t.Errorf("evidence should say there is no adapter, got %q", r.Evidence)
	}

	// Apply should keep it detected.
	c.Apply(f, r)
	if f.State != finding.StateDetected {
		t.Errorf("Apply must leave state detected, got %q", f.State)
	}
}

// TestApply_StateTransitions verifies Apply writes the confirmation block and
// advances finding state/confidence per outcome.
func TestApply_StateTransitions(t *testing.T) {
	c := NewTakeoverConfirmer()

	t.Run("confirmed", func(t *testing.T) {
		f := detectedFinding("a.example.com")
		c.Apply(f, ConfirmResult{Confirmed: true, Method: "canary_claim", Evidence: "served", BlastRadius: "x", Released: true})
		if f.State != finding.StateConfirmed || f.Confidence != finding.Confirmed {
			t.Errorf("confirmed: state=%q conf=%q", f.State, f.Confidence)
		}
		if f.Confirmation == nil || f.Confirmation.State != finding.StateConfirmed || !f.Confirmation.Released {
			t.Errorf("confirmation block not written correctly: %+v", f.Confirmation)
		}
	})

	t.Run("disproved", func(t *testing.T) {
		f := detectedFinding("b.example.com")
		f.Confidence = finding.Confirmed // detection had high confidence
		c.Apply(f, ConfirmResult{Disproved: true, Method: "canary_claim", Evidence: "not claimable", Released: true})
		if f.State != finding.StateNotVulnerable || f.Confidence != finding.Potential {
			t.Errorf("disproved: state=%q conf=%q, want not_vulnerable/POTENTIAL", f.State, f.Confidence)
		}
	})
}

// TestServiceToAdapter covers the service→adapter slug mapping used to dispatch.
func TestServiceToAdapter(t *testing.T) {
	cases := map[string]string{
		"GitHub Pages":    "github-pages",
		"AWS/S3":          "aws-s3",
		"Heroku":          "heroku",
		"Read the Docs":   "read-the-docs",
		"Microsoft Azure": "microsoft-azure",
		"  Fastly  ":      "fastly",
	}
	for in, want := range cases {
		if got := ServiceToAdapter(in); got != want {
			t.Errorf("ServiceToAdapter(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGate_Authorize covers the gate matrix directly.
func TestGate_Authorize(t *testing.T) {
	g := NewGate(true, []string{"example.com", "Example.ORG."})
	cases := []struct {
		fqdn    string
		wantErr error
	}{
		{"assets.example.com", nil},
		{"example.com", nil},
		{"deep.sub.example.org", nil}, // apex normalized + case-insensitive
		{"evil.com", ErrOutOfScope},
	}
	for _, tc := range cases {
		err := g.Authorize(tc.fqdn)
		if tc.wantErr == nil && err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tc.fqdn, err)
		}
		if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("Authorize(%q) = %v, want %v", tc.fqdn, err, tc.wantErr)
		}
	}

	// An inactive gate refuses everything.
	if err := NewGate(false, []string{"example.com"}).Authorize("assets.example.com"); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("inactive gate must refuse, got %v", err)
	}
	// An empty allow-list authorizes nothing even when active.
	if err := NewGate(true, nil).Authorize("assets.example.com"); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("empty allow-list must authorize nothing, got %v", err)
	}
}
