// Package confirm implements graverobber's safe, active takeover confirmation:
// the step every other takeover scanner (subzy, nuclei takeover templates,
// dnsReaper, the legacy subjack graverobber resurrects) skips. They stop at a
// fingerprint match and emit "potential takeover" — which a bug-bounty program
// closes as unproven, because a fingerprint match is a strong signal, not proof.
// confirm safely *claims* the dangling resource into the operator's own provider
// account, serves a unique canary token on a hidden path, proves control by
// fetching the FQDN and observing the canary, characterizes the blast radius,
// and then RELEASES (deletes) the claimed resource. Only a served-and-reflected
// canary advances a finding to confirmed; every other branch is a real negative
// (not_vulnerable) or an error — never a false confirmation.
//
// This is the community-sanctioned confirmation method EdOverflow documents:
// "claiming the subdomain discreetly and serving a harmless file on a hidden
// page is usually enough to demonstrate the security vulnerability." confirm
// automates it per provider behind a Gate.
//
// # Safety
//
// Claiming a resource on a real provider tied to a target's DNS is the most
// sensitive action in the suite. The package enforces, by construction:
//
//   - Gated + allow-listed. Confirm refuses unless the run is explicitly
//     authorized (Gate.MustActive) and the target's apex is on the allow-list.
//     Fail-closed: an empty allow-list authorizes nothing.
//   - Benign + canary only. A confirmation serves a unique canary token on a
//     hidden /.well-known path. It never hosts real content, a phishing page, a
//     cookie harvester, or a live OAuth endpoint — those blast-radius
//     consequences are *characterized* (see blast.go), never executed.
//   - Always release. Every claimed resource is tracked and released via a
//     deferred Release; a claimed-but-unreleased resource on a victim's DNS is an
//     incident, so a release failure is loud and fails the confirmation rather
//     than being silently swallowed.
//   - The operator's own accounts. Adapters claim into credentials the operator
//     supplies (config, never hardcoded). The live adapters ship dry-run by
//     default and refuse to perform a real registration unless explicitly armed.
package confirm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// ClaimAdapter performs the provider-specific steps of a safe claim. One
// implementation exists per claimable provider (GitHub Pages, S3, Heroku,
// Netlify, …), keyed by the fingerprint database's claim_adapter field. Claiming
// is provider-specific — creating a Pages repo is nothing like creating an S3
// bucket — so the confirmer dispatches to an adapter rather than special-casing
// providers inline.
//
// The contract is a strict three-step lifecycle:
//
//	Claim       Register the dangling resource (create the Pages repo / S3 bucket
//	            / Heroku app …) into the operator's own account and bind the FQDN.
//	            Returns claimed=false (NOT an error) when the resource is not
//	            actually claimable — the provider fixed its policy, or the name is
//	            already owned — which the confirmer reports as not_vulnerable (a
//	            real disproof). A genuine failure (auth, transport) is an error.
//	ServeCanary Place the canary at the hidden path and return the FQDN URL it
//	            should be observable at. served=false means the claim did not
//	            actually bind the FQDN (DNS is not routing here), → not_vulnerable.
//	Release     Delete the claimed resource. ALWAYS called (via defer) when Claim
//	            returned claimed=true; a non-nil error here is an incident.
//
// Adapters must be safe for concurrent use across distinct findings.
type ClaimAdapter interface {
	// Claim registers the dangling resource for fqdn into the operator's account.
	// handle identifies the created resource for later Release (e.g. "owner/repo"
	// or a bucket name). claimed=false with a nil error means "not claimable"
	// (disproof); a non-nil error means the attempt itself failed.
	Claim(ctx context.Context, fqdn string, canary *Canary) (claimed bool, handle string, err error)
	// ServeCanary places the canary at path within the claimed resource and
	// returns the URL on fqdn at which it should be observable. served=false
	// means the FQDN is not actually routing to the claimed resource.
	ServeCanary(ctx context.Context, fqdn string, canary *Canary, path string) (served bool, url string)
	// Release deletes the claimed resource identified by handle. It is always
	// invoked for a successful claim; a non-nil return is a release failure and
	// is treated as an incident by the confirmer.
	Release(ctx context.Context, handle string) error
	// Name returns the adapter key (matches the fingerprint claim_adapter field),
	// e.g. "github-pages". Used in evidence and reproduction strings.
	Name() string
}

// ConfirmResult is the structured outcome of a confirmation attempt. Exactly one
// of Confirmed / Disproved is true on a non-error return; both false with a nil
// error means "no adapter / could not attempt" (the finding stays detected).
type ConfirmResult struct {
	// Confirmed is true only when a canary was served on the claimed resource and
	// observed at the FQDN — demonstrated control. This is the sole proof.
	Confirmed bool
	// Disproved is true when the attempt proved the candidate is NOT takeoverable
	// (not claimable, or claimed-but-not-routing/not-reflecting). A real negative.
	Disproved bool
	// Method is how control was (attempted to be) demonstrated: "canary_claim".
	Method string
	// Evidence is the human-readable proof or disproof reason. On confirmation it
	// contains the served canary URL and notes the resource was released.
	Evidence string
	// Reproduction is a short recipe to reproduce the proof (confirmation only).
	Reproduction string
	// BlastRadius characterizes what the takeover grants (confirmation only).
	BlastRadius string
	// Released reports whether the claimed resource was successfully released.
	// True when nothing was claimed (nothing to release) or release succeeded;
	// false only when a claim happened and its release failed (an incident).
	Released bool
}

// ErrReleaseFailed wraps an adapter Release failure. It is returned from Confirm
// so the caller fails the run loudly: a claimed-but-unreleased resource sitting
// on a victim's DNS is a real incident, not a warning to swallow. The error
// embeds the resource handle so an operator can release it by hand.
type ErrReleaseFailed struct {
	Adapter string
	Handle  string
	Err     error
}

func (e *ErrReleaseFailed) Error() string {
	return fmt.Sprintf("confirm: RELEASE FAILED for %s resource %q (manual cleanup required): %v",
		e.Adapter, e.Handle, e.Err)
}

func (e *ErrReleaseFailed) Unwrap() error { return e.Err }

// Artifact records a claimed-but-not-yet-released resource. The ArtifactTracker
// holds these so a release failure (or a crash) leaves an auditable record of
// exactly what is still registered on a provider and must be cleaned up.
type Artifact struct {
	Kind     string    // e.g. "takeover-claim"
	Adapter  string    // adapter that created it
	Handle   string    // provider resource handle (owner/repo, bucket, …)
	CanaryID string    // associated canary
	PlacedAt time.Time // when the claim was recorded
}

// ArtifactTracker tracks claimed resources to guarantee the release discipline.
// Every claim is Placed before serving; a successful Release Removes it. Anything
// still Outstanding at the end of a run is litter on a real provider — a loud,
// auditable failure. It is safe for concurrent use.
type ArtifactTracker struct {
	mu        sync.Mutex
	live      map[string]Artifact // keyed by adapter+"\x00"+handle
	now       func() time.Time
	onFailure func(Artifact, error) // optional hook, e.g. structured logging
}

// NewArtifactTracker builds an empty tracker.
func NewArtifactTracker() *ArtifactTracker {
	return &ArtifactTracker{live: map[string]Artifact{}, now: time.Now}
}

// SetClock overrides the clock (tests).
func (t *ArtifactTracker) SetClock(now func() time.Time) {
	if now != nil {
		t.now = now
	}
}

// OnReleaseFailure registers a hook invoked when a tracked artifact fails to
// release. It is the seam for loud logging/alerting; the confirmer still returns
// ErrReleaseFailed regardless.
func (t *ArtifactTracker) OnReleaseFailure(fn func(Artifact, error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onFailure = fn
}

func artifactKey(adapter, handle string) string { return adapter + "\x00" + handle }

// Placed records that a resource has been claimed and is awaiting release.
func (t *ArtifactTracker) Placed(kind, adapter, handle, canaryID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.live[artifactKey(adapter, handle)] = Artifact{
		Kind:     kind,
		Adapter:  adapter,
		Handle:   handle,
		CanaryID: canaryID,
		PlacedAt: t.now().UTC(),
	}
}

// Released records a successful release and stops tracking the resource.
func (t *ArtifactTracker) Released(adapter, handle string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.live, artifactKey(adapter, handle))
}

// Failed records a release failure: it invokes the failure hook (if any) and
// keeps the artifact tracked so it surfaces in Outstanding.
func (t *ArtifactTracker) Failed(adapter, handle string, err error) {
	t.mu.Lock()
	a, ok := t.live[artifactKey(adapter, handle)]
	hook := t.onFailure
	t.mu.Unlock()
	if ok && hook != nil {
		hook(a, err)
	}
}

// Outstanding returns every artifact still tracked (claimed, not released). A
// non-empty result at end-of-run is an incident.
func (t *ArtifactTracker) Outstanding() []Artifact {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Artifact, 0, len(t.live))
	for _, a := range t.live {
		out = append(out, a)
	}
	return out
}

// Gate enforces that confirmation is explicitly authorized and scoped. It is the
// fail-closed boundary in front of every claim: confirmation does not run unless
// the operator armed it (Active) AND the target's apex is on the allow-list.
type Gate struct {
	// Active must be true for any confirmation to proceed (the --authorized /
	// confirm:true switch). Default false: fail-closed.
	Active bool
	// AllowApex is the set of apex domains the operator is authorized to test
	// (lower-cased, no leading dot), e.g. "example.com". A target FQDN passes only
	// if its apex is a key here. An empty map authorizes nothing.
	AllowApex map[string]struct{}
}

// Sentinel gate errors.
var (
	// ErrNotAuthorized means the gate is not Active — confirmation was attempted
	// without the operator explicitly arming it.
	ErrNotAuthorized = errors.New("confirm: not authorized (confirmation is gated; arm it explicitly to claim resources)")
	// ErrOutOfScope means the target's apex is not on the allow-list.
	ErrOutOfScope = errors.New("confirm: target out of scope (apex not on the authorization allow-list)")
)

// NewGate builds a gate from an authorized flag and a list of allowed apex
// domains. Apexes are normalized (lower-cased, trailing dot stripped).
func NewGate(active bool, allowApex []string) *Gate {
	m := make(map[string]struct{}, len(allowApex))
	for _, a := range allowApex {
		if n := normalizeApex(a); n != "" {
			m[n] = struct{}{}
		}
	}
	return &Gate{Active: active, AllowApex: m}
}

// Authorize reports whether fqdn may be confirmed. It returns ErrNotAuthorized
// when the gate is not active, ErrOutOfScope when the apex is not allow-listed,
// and nil only when both checks pass. Fail-closed by construction.
func (g *Gate) Authorize(fqdn string) error {
	if g == nil || !g.Active {
		return ErrNotAuthorized
	}
	apex := apexOf(fqdn)
	if _, ok := g.AllowApex[apex]; !ok {
		return fmt.Errorf("%w: %s (apex %s)", ErrOutOfScope, fqdn, apex)
	}
	return nil
}

// TakeoverConfirmer is graverobber's safe-claim confirmer. It implements the
// detect → confirm contract for the takeover class (rule prefix "takeover.").
type TakeoverConfirmer struct {
	canaries *Canaries
	adapters map[string]ClaimAdapter
	tracker  *ArtifactTracker
	gate     *Gate
	blast    BlastRadiusFunc
	now      func() time.Time
}

// BlastRadiusFunc characterizes what a confirmed takeover of fqdn grants. It is
// an indirection so the (network-touching) default in blast.go can be swapped
// for a deterministic stub in tests.
type BlastRadiusFunc func(ctx context.Context, fqdn string) string

// Option configures a TakeoverConfirmer.
type Option func(*TakeoverConfirmer)

// WithAdapter registers a claim adapter under the given key (the fingerprint
// claim_adapter value). Last write wins for a duplicate key.
func WithAdapter(key string, a ClaimAdapter) Option {
	return func(c *TakeoverConfirmer) {
		if a != nil {
			c.adapters[key] = a
		}
	}
}

// WithCanaries overrides the canary engine (tests / custom HTTP client).
func WithCanaries(cn *Canaries) Option {
	return func(c *TakeoverConfirmer) {
		if cn != nil {
			c.canaries = cn
		}
	}
}

// WithTracker overrides the artifact tracker.
func WithTracker(t *ArtifactTracker) Option {
	return func(c *TakeoverConfirmer) {
		if t != nil {
			c.tracker = t
		}
	}
}

// WithGate sets the authorization gate. Without a gate, confirmation is
// fail-closed (every Confirm returns ErrNotAuthorized).
func WithGate(g *Gate) Option {
	return func(c *TakeoverConfirmer) { c.gate = g }
}

// WithBlastRadius overrides the blast-radius characterizer.
func WithBlastRadius(fn BlastRadiusFunc) Option {
	return func(c *TakeoverConfirmer) {
		if fn != nil {
			c.blast = fn
		}
	}
}

// WithClock overrides the confirmer clock (tests).
func WithClock(now func() time.Time) Option {
	return func(c *TakeoverConfirmer) {
		if now != nil {
			c.now = now
		}
	}
}

// NewTakeoverConfirmer builds a confirmer. By default it has no adapters and a
// fail-closed (nil, inactive) gate, a fresh canary engine and tracker, and the
// real (network) blast-radius characterizer. Supply adapters and a gate via
// options to make it operational.
func NewTakeoverConfirmer(opts ...Option) *TakeoverConfirmer {
	c := &TakeoverConfirmer{
		canaries: NewCanaries(),
		adapters: map[string]ClaimAdapter{},
		tracker:  NewArtifactTracker(),
		gate:     nil,
		blast:    BlastRadius,
		now:      time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// RulePrefix is the finding rule prefix this confirmer handles.
func (c *TakeoverConfirmer) RulePrefix() string { return "takeover." }

// Tracker exposes the artifact tracker so a caller can audit outstanding
// resources at end-of-run.
func (c *TakeoverConfirmer) Tracker() *ArtifactTracker { return c.tracker }

// Adapters reports the registered adapter keys (sorted for stable output).
func (c *TakeoverConfirmer) Adapters() []string {
	out := make([]string, 0, len(c.adapters))
	for k := range c.adapters {
		out = append(out, k)
	}
	return out
}

// Confirm runs the safe-claim confirmation for a detected takeover finding.
//
// Flow (the EdOverflow technique, automated): authorize → select the per-provider
// adapter → CLAIM the dangling resource into the operator's account → record the
// artifact and defer RELEASE → SERVE the canary on a hidden path → PROVE control
// by fetching the FQDN and observing the canary → characterize the BLAST RADIUS →
// return confirmed. Every branch that is not a proven claim returns Disproved (a
// real negative) or an error — never a false confirmed (the evidence invariant).
//
// The Surface argument names the provider/claim_adapter (e.g. "github-pages");
// it is taken from f.Service when surface is empty. A release failure returns an
// *ErrReleaseFailed so the caller fails loudly.
func (c *TakeoverConfirmer) Confirm(ctx context.Context, f *finding.Finding) (result ConfirmResult, retErr error) {
	if f == nil {
		return ConfirmResult{}, errors.New("confirm: nil finding")
	}

	// Gate FIRST: never touch a provider for an unauthorized or out-of-scope
	// target. Fail-closed.
	if err := c.gate.Authorize(f.Subdomain); err != nil {
		return ConfirmResult{}, err
	}

	surface := strings.TrimSpace(adapterKey(f))
	adapter, ok := c.adapters[surface]
	if !ok {
		// No adapter for this provider: we cannot safely confirm. Leave the
		// finding detected — honest, not a false confirm (and not an error).
		return ConfirmResult{
			Method:   "canary_claim",
			Released: true, // nothing claimed → nothing to release
			Evidence: "no claim adapter for provider " + surface + "; left detected (manual validation required)",
		}, nil
	}

	canary := c.canaries.New()

	// 1) CLAIM the dangling resource into the operator's account.
	claimed, handle, err := adapter.Claim(ctx, f.Subdomain, canary)
	if err != nil {
		return ConfirmResult{Method: "canary_claim", Released: true}, fmt.Errorf("confirm: claim %s for %s: %w", surface, f.Subdomain, err)
	}
	if !claimed {
		// Not actually claimable → a real disproof (provider fixed, or owned).
		return ConfirmResult{
			Disproved: true,
			Method:    "canary_claim",
			Released:  true, // nothing was claimed
			Evidence:  "resource not claimable on " + surface + " (provider fixed policy or name already owned)",
		}, nil
	}

	// Record the claim and guarantee release. The deferred release runs on every
	// return path below; because result and retErr are NAMED returns, the defer
	// mutates the actual returned values — setting result.Released and, on a
	// release failure, replacing retErr with a loud *ErrReleaseFailed while
	// keeping the artifact tracked.
	c.tracker.Placed("takeover-claim", surface, handle, canary.ID)
	defer func() {
		if relErr := adapter.Release(ctx, handle); relErr != nil {
			c.tracker.Failed(surface, handle, relErr)
			result.Released = false
			// A release failure dominates: surface it as the returned error so the
			// run fails loudly, regardless of the confirm/disprove outcome.
			retErr = &ErrReleaseFailed{Adapter: surface, Handle: handle, Err: relErr}
			return
		}
		c.tracker.Released(surface, handle)
		result.Released = true
	}()

	// 2) SERVE the canary on a hidden path.
	served, url := adapter.ServeCanary(ctx, f.Subdomain, canary, canary.Path())
	if !served {
		result = ConfirmResult{
			Disproved: true,
			Method:    "canary_claim",
			Evidence:  "claimed " + surface + " resource but could not bind " + f.Subdomain + " (DNS is not routing to the claimed resource)",
		}
		return result, retErr
	}

	// 3) PROVE: fetch the FQDN and confirm our canary is served.
	if !c.canaries.ReflectedAt(ctx, url, canary) {
		result = ConfirmResult{
			Disproved: true,
			Method:    "canary_claim",
			Evidence:  "served canary on " + surface + " but " + f.Subdomain + " did not reflect it",
		}
		return result, retErr
	}

	// CONFIRMED — with mandatory served-canary evidence and blast radius.
	result = ConfirmResult{
		Confirmed:    true,
		Method:       "canary_claim",
		Evidence:     "served canary " + canary.ID + " at " + url + " (control demonstrated); resource released",
		Reproduction: "claim a " + surface + " resource for " + f.Subdomain + " in your own account; serve a file at " + canary.Path(),
		BlastRadius:  c.safeBlast(ctx, f.Subdomain),
	}
	return result, retErr
}

// safeBlast computes the blast radius, tolerating a nil characterizer.
func (c *TakeoverConfirmer) safeBlast(ctx context.Context, fqdn string) string {
	if c.blast == nil {
		return "content control of " + fqdn
	}
	return c.blast(ctx, fqdn)
}

// Apply writes a ConfirmResult back onto a finding as its Confirmation block and
// advances its State. It is the bridge from the confirmer's structured result to
// the serialized finding the pipeline emits.
//
//   - Confirmed → State=confirmed, Confidence raised to CONFIRMED.
//   - Disproved → State=not_vulnerable, Confidence lowered to POTENTIAL (a real
//     negative — the candidate was disproved).
//   - neither (no adapter) → State unchanged (stays detected).
func (c *TakeoverConfirmer) Apply(f *finding.Finding, r ConfirmResult) {
	if f == nil {
		return
	}
	conf := &finding.Confirmation{
		Method:       r.Method,
		Evidence:     r.Evidence,
		Reproduction: r.Reproduction,
		BlastRadius:  r.BlastRadius,
		Released:     r.Released,
		ConfirmedAt:  c.now().UTC(),
	}
	switch {
	case r.Confirmed:
		conf.State = finding.StateConfirmed
		f.State = finding.StateConfirmed
		f.Confidence = finding.Confirmed
	case r.Disproved:
		conf.State = finding.StateNotVulnerable
		f.State = finding.StateNotVulnerable
		f.Confidence = finding.Potential
	default:
		// No adapter / could not attempt: leave the finding detected.
		if f.State == "" {
			f.State = finding.StateDetected
		}
		conf.State = f.State
	}
	f.Confirmation = conf
}

// adapterKey returns the provider/claim_adapter key for a finding: the Service
// field, lower-cased and slugified to the adapter convention (e.g.
// "GitHub Pages" → "github-pages"). A finding that already carries an explicit
// adapter-style Service is used as-is.
func adapterKey(f *finding.Finding) string {
	if f.Service == "" {
		return ""
	}
	return ServiceToAdapter(f.Service)
}

// ServiceToAdapter normalizes a fingerprint-DB service name to a claim_adapter
// key: lower-case, spaces and slashes collapsed to single hyphens. It is the
// default mapping when a fingerprint entry has no explicit claim_adapter.
//
//	"GitHub Pages"  -> "github-pages"
//	"AWS/S3"        -> "aws-s3"
//	"Heroku"        -> "heroku"
func ServiceToAdapter(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		case r == '-' || r == ' ' || r == '/' || r == '_' || r == '.':
			if !prevHyphen && b.Len() > 0 {
				b.WriteRune('-')
				prevHyphen = true
			}
		default:
			// drop other punctuation
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// normalizeApex lower-cases an apex and strips a trailing dot.
func normalizeApex(a string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
}

// apexOf returns the registrable apex of a host using a simple last-two-labels
// heuristic (sufficient for allow-list scoping; the operator controls both the
// allow-list and the targets). For "assets.example.com" it returns
// "example.com"; for "example.com" it returns "example.com".
func apexOf(host string) string {
	h := normalizeApex(host)
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
