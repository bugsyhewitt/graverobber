package confirm

import (
	"context"
	"errors"
	"sync"
)

// MockAdapter is a fully in-memory ClaimAdapter used to exercise the confirm
// state machine deterministically — in tests and in the safe see-it-work demo
// (cmd/graverobber confirm-demo) — without ever touching a provider. Each knob
// drives one branch of Confirm:
//
//	Claimable=false           → Claim returns claimed=false  → not_vulnerable
//	ClaimErr!=nil             → Claim returns an error       → error
//	ServeFail=true            → ServeCanary returns served=false → not_vulnerable
//	Reflect=false             → the canary is not "served", so ReflectedAt fails
//	                            → not_vulnerable
//	ReleaseErr!=nil           → Release returns an error     → ErrReleaseFailed
//	(all default-happy)       → claim + serve + reflect + release → confirmed
//
// MockAdapter records each lifecycle call so a test can assert, e.g., that
// Release was invoked even when serving failed (the release-discipline invariant)
// and that nothing remains claimed at the end.
type MockAdapter struct {
	NameVal string // adapter key (default "mock")

	Claimable  bool  // whether Claim succeeds (default true via NewMockAdapter)
	ClaimErr   error // if non-nil, Claim returns this error
	ServeFail  bool  // if true, ServeCanary returns served=false
	Reflect    bool  // whether the served canary reflects (default true)
	ReleaseErr error // if non-nil, Release returns this error

	mu          sync.Mutex
	served      map[string]string // url -> token (what is "served")
	claimCount  int
	serveCount  int
	releaseCnt  int
	liveHandles map[string]bool // handle -> still claimed
}

// NewMockAdapter returns a happy-path MockAdapter: claimable, serves, reflects,
// releases cleanly. Tests flip individual knobs to drive the other branches.
func NewMockAdapter() *MockAdapter {
	return &MockAdapter{
		NameVal:     "mock",
		Claimable:   true,
		Reflect:     true,
		served:      map[string]string{},
		liveHandles: map[string]bool{},
	}
}

// Name returns the adapter key.
func (m *MockAdapter) Name() string {
	if m.NameVal == "" {
		return "mock"
	}
	return m.NameVal
}

// Claim simulates claiming the resource.
func (m *MockAdapter) Claim(_ context.Context, fqdn string, c *Canary) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimCount++
	if m.ClaimErr != nil {
		return false, "", m.ClaimErr
	}
	if !m.Claimable {
		return false, "", nil
	}
	handle := m.Name() + ":" + fqdn + ":" + c.ID
	m.liveHandles[handle] = true
	return true, handle, nil
}

// ServeCanary simulates serving the canary at the hidden path. When Reflect is
// true it records the token as observable at the URL so the confirmer's
// ReflectedAt (pointed at MockReflector) returns true.
func (m *MockAdapter) ServeCanary(_ context.Context, fqdn string, c *Canary, path string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serveCount++
	url := "https://" + fqdn + path
	if m.ServeFail {
		return false, url
	}
	if m.Reflect {
		m.served[url] = c.Token
	}
	return true, url
}

// Release simulates releasing (deleting) the claimed resource.
func (m *MockAdapter) Release(_ context.Context, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseCnt++
	if m.ReleaseErr != nil {
		return m.ReleaseErr
	}
	if !m.liveHandles[handle] {
		return errors.New("mock: release of unknown handle " + handle)
	}
	delete(m.liveHandles, handle)
	return nil
}

// MockReflector is the reflector to wire into a Canaries (via WithReflector) so a
// confirmation against this MockAdapter proves through the in-memory "served"
// map instead of real HTTP. It returns true iff ServeCanary recorded the canary
// token at the URL.
func (m *MockAdapter) MockReflector() func(ctx context.Context, url string, c *Canary) bool {
	return func(_ context.Context, url string, c *Canary) bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		tok, ok := m.served[url]
		return ok && tok == c.Token
	}
}

// ClaimCount / ServeCount / ReleaseCount expose the lifecycle call counts so
// tests can assert the release discipline (Release must be called for every
// successful claim, even on a later failure).
func (m *MockAdapter) ClaimCount() int   { m.mu.Lock(); defer m.mu.Unlock(); return m.claimCount }
func (m *MockAdapter) ServeCount() int   { m.mu.Lock(); defer m.mu.Unlock(); return m.serveCount }
func (m *MockAdapter) ReleaseCount() int { m.mu.Lock(); defer m.mu.Unlock(); return m.releaseCnt }

// StillClaimed reports how many handles remain claimed (not released). It must be
// zero after any confirmation that claimed a resource and released cleanly.
func (m *MockAdapter) StillClaimed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.liveHandles)
}

// compile-time interface check.
var _ ClaimAdapter = (*MockAdapter)(nil)
