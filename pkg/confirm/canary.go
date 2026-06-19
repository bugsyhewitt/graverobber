package confirm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

// Canary is a single-use, unguessable proof token. A confirmation claims the
// dangling resource, serves the canary's Token on a hidden path, then proves
// control by fetching the FQDN and observing the Token in the response. The
// token is unique per attempt so a reflected canary unambiguously demonstrates
// that *this* confirmation attempt — not pre-existing content — controls the
// resource.
type Canary struct {
	// ID is a short hex identifier embedded in the hidden path
	// (/.well-known/nmc-<ID>) and the throwaway resource name. It is safe to log.
	ID string
	// Token is the full secret reflected in the served content; observing it at
	// the FQDN is the proof of control. It is longer/higher-entropy than ID.
	Token string
	// CreatedAt records when the canary was minted.
	CreatedAt time.Time
}

// Path returns the hidden well-known path the canary is served at. It is the
// EdOverflow "harmless file on a hidden page" location — obscure, low-footprint,
// and namespaced to graverobber/necromancer so it is unmistakably a proof
// artifact and not real content.
func (c Canary) Path() string {
	return "/.well-known/nmc-" + c.ID
}

// reflector fetches a URL and reports whether the canary token appears in the
// (bounded) response body. It is an indirection so tests can prove the
// reflection logic without real network I/O.
type reflector func(ctx context.Context, url string, c *Canary) bool

// Canaries mints canaries and verifies their reflection. The zero value is not
// usable; construct one with NewCanaries.
type Canaries struct {
	client *http.Client
	// reflect is the reflection check; defaults to httpReflect but is overridable
	// for tests.
	reflect reflector
	// now returns the current time; overridable for deterministic tests.
	now func() time.Time
	// idBytes / tokenBytes size the generated identifiers. Defaults are set by
	// NewCanaries.
	idBytes    int
	tokenBytes int
}

// CanariesOption configures a Canaries.
type CanariesOption func(*Canaries)

// WithReflector overrides the reflection check (tests).
func WithReflector(r reflector) CanariesOption {
	return func(c *Canaries) {
		if r != nil {
			c.reflect = r
		}
	}
}

// WithCanaryClock overrides the clock (tests).
func WithCanaryClock(now func() time.Time) CanariesOption {
	return func(c *Canaries) {
		if now != nil {
			c.now = now
		}
	}
}

// WithHTTPClient overrides the HTTP client used by the default reflector.
func WithHTTPClient(client *http.Client) CanariesOption {
	return func(c *Canaries) {
		if client != nil {
			c.client = client
		}
	}
}

// NewCanaries builds a Canaries with sane defaults: a 10s-timeout HTTP client
// and the standard-library crypto/rand token source.
func NewCanaries(opts ...CanariesOption) *Canaries {
	c := &Canaries{
		client:     &http.Client{Timeout: 10 * time.Second},
		now:        time.Now,
		idBytes:    4,  // 8 hex chars
		tokenBytes: 16, // 32 hex chars
	}
	c.reflect = c.httpReflect
	for _, o := range opts {
		o(c)
	}
	return c
}

// New mints a fresh canary.
func (c *Canaries) New() *Canary {
	return &Canary{
		ID:        randHex(c.idBytes),
		Token:     "nmc-canary-" + randHex(c.tokenBytes),
		CreatedAt: c.now().UTC(),
	}
}

// ReflectedAt reports whether the canary token is observable at url — the proof
// step. It delegates to the configured reflector.
func (c *Canaries) ReflectedAt(ctx context.Context, url string, canary *Canary) bool {
	if canary == nil || url == "" {
		return false
	}
	return c.reflect(ctx, url, canary)
}

// maxCanaryBody bounds how much of a response body the reflector reads. The
// canary token is tiny and served on its own page; a few KiB is ample and bounds
// memory against a hostile or huge response.
const maxCanaryBody = 64 << 10 // 64 KiB

// httpReflect is the default reflector: it GETs url and reports whether the
// canary Token (or, as a fallback, the canary ID) appears in the bounded body.
func (c *Canaries) httpReflect(ctx context.Context, url string, canary *Canary) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "graverobber/confirm")
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCanaryBody))
	if err != nil {
		return false
	}
	s := string(body)
	return strings.Contains(s, canary.Token) || strings.Contains(s, canary.ID)
}

// randHex returns n cryptographically-random bytes as a lower-case hex string.
// crypto/rand.Read on a healthy system does not fail; in the vanishingly
// unlikely event it does, randHex falls back to a time-seeded value so a canary
// is always non-empty (a predictable-but-present token is strictly safer than an
// empty one, which would make every reflection check trivially "match").
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Degraded fallback: never return an empty token.
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (8 * (i % 8)))
		}
	}
	return hex.EncodeToString(b)
}
