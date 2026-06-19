// Package adapters holds graverobber's per-provider claim adapters: the
// provider-specific implementations of confirm.ClaimAdapter that the
// TakeoverConfirmer dispatches to. Each adapter knows how to safely claim a
// dangling resource into the operator's OWN account, serve a canary on a hidden
// path, prove control, and release (delete) the resource.
//
// # Safety posture (read this before arming a live adapter)
//
// Claiming a resource on a real provider whose name is bound to a target's
// dangling DNS is the single most sensitive action in the necromancer suite: a
// successful claim, until released, makes the takeover REAL. graverobber's
// adapters therefore ship DRY-RUN BY DEFAULT. A dry-run adapter exercises the
// full confirm state machine (claim → serve → prove → release) deterministically
// and in-memory, so the precision, evidence-invariant, and release-discipline
// tests all run — without ever touching a provider. Switching an adapter to LIVE
// requires (a) the operator's own provider credentials, supplied explicitly, and
// (b) an explicit Authorized acknowledgement; absent either, the adapter refuses.
// Even when armed, graverobber claims only into the operator's own account,
// serves only a canary on a hidden /.well-known path, and always releases.
package adapters

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/bugsyhewitt/graverobber/pkg/confirm"
)

// GitHubPagesAdapter is the reference claim adapter (Appendix C / D9): the
// template the other providers' adapters follow. It claims a dangling GitHub
// Pages CNAME by creating a throwaway repository in the operator's own account
// with a CNAME file equal to the dangling FQDN and the canary at a hidden path,
// enabling Pages so the dangling CNAME now routes to that repo, proving the FQDN
// reflects the canary, and deleting the repo on release.
//
// In this build the adapter operates in dry-run mode unless explicitly armed with
// live GitHub credentials AND an Authorized acknowledgement. Dry-run mode
// simulates the claim/serve/prove/release lifecycle in-memory and deterministically
// so the confirm state machine is fully exercised by tests and the see-it-work
// demo without registering anything on GitHub.
type GitHubPagesAdapter struct {
	cfg GitHubPagesConfig

	// live holds the injected real GitHub operations when armed. nil in dry-run.
	live GitHubOps

	mu      sync.Mutex
	claimed map[string]dryResource // handle -> simulated resource (dry-run)
}

// GitHubPagesConfig configures a GitHubPagesAdapter.
type GitHubPagesConfig struct {
	// User is the operator's GitHub account/org the repo is created under.
	User string
	// Token is the operator's GitHub credential. Supplied only to arm live mode;
	// never hardcoded. Empty keeps the adapter in dry-run.
	Token string
	// Authorized must be set true to permit a LIVE claim. It is the explicit
	// "I am authorized to register resources for these targets" acknowledgement.
	// Without it, even a token-bearing adapter stays in dry-run.
	Authorized bool
	// Ops, when non-nil, supplies the real GitHub operations (repo create/put
	// file/enable Pages/delete). It is an injection seam: graverobber ships no
	// embedded GitHub client in this build, so a live claim requires the operator
	// to wire a GitHubOps implementation explicitly. When nil and the adapter
	// would otherwise go live, Claim returns ErrLiveAdapterNotWired.
	Ops GitHubOps
}

// GitHubOps is the minimal set of real GitHub operations a live claim needs. It
// is an interface so graverobber does not embed a GitHub SDK by default and so
// the live path is testable. A production operator supplies an implementation
// backed by go-github (per the packet's go.mod sketch) when they arm live mode.
type GitHubOps interface {
	CreateRepo(ctx context.Context, owner, repo string) error
	PutFile(ctx context.Context, owner, repo, path, content string) error
	EnablePages(ctx context.Context, owner, repo string) error
	DeleteRepo(ctx context.Context, owner, repo string) error
}

// Sentinel errors.
var (
	// ErrLiveAdapterNotWired is returned when the adapter is armed (token +
	// Authorized) but no GitHubOps implementation was supplied. graverobber ships
	// no embedded GitHub client in this build, so a real claim requires the
	// operator to wire one — a deliberate guard against an autonomous live claim.
	ErrLiveAdapterNotWired = errors.New(
		"github-pages: live claim requires an explicit GitHubOps implementation (none wired); " +
			"graverobber does not perform real provider registration autonomously — supply Ops to arm")
	// ErrMissingUser is returned when no operator account is configured.
	ErrMissingUser = errors.New("github-pages: no operator GitHub user configured")
)

// dryResource is a simulated claimed repo in dry-run mode.
type dryResource struct {
	owner   string
	repo    string
	fqdn    string
	path    string
	token   string
	pages   bool
	servedT string
}

// NewGitHubPagesAdapter builds the adapter. With an empty token OR Authorized
// false, it runs in dry-run mode. With both set AND cfg.Ops non-nil, it runs
// live against cfg.Ops.
func NewGitHubPagesAdapter(cfg GitHubPagesConfig) *GitHubPagesAdapter {
	a := &GitHubPagesAdapter{
		cfg:     cfg,
		claimed: map[string]dryResource{},
	}
	if a.isArmed() {
		a.live = cfg.Ops // may be nil; Claim returns ErrLiveAdapterNotWired then
	}
	return a
}

// Name returns the adapter key.
func (a *GitHubPagesAdapter) Name() string { return "github-pages" }

// DryRun reports whether the adapter is operating in dry-run (simulated) mode.
func (a *GitHubPagesAdapter) DryRun() bool { return !a.isArmed() || a.live == nil }

// isArmed reports whether the operator explicitly armed live mode (token +
// Authorized). Even when armed, a nil Ops keeps real registration impossible.
func (a *GitHubPagesAdapter) isArmed() bool {
	return a.cfg.Token != "" && a.cfg.Authorized
}

// repoName derives the throwaway repository name from the canary: nmc-<id>. The
// repo lives in the operator's own account and is deleted on release.
func repoName(c *confirm.Canary) string { return "nmc-" + c.ID }

// Claim creates (or simulates creating) the Pages repo for fqdn with the CNAME
// file and the canary, and enables Pages so the dangling CNAME routes to it.
//
// Dry-run: records a simulated resource and returns claimed=true so the state
// machine proceeds; the serve/prove steps then operate on the simulation.
//
// Live: refuses unless GitHubOps was wired (ErrLiveAdapterNotWired) — graverobber
// will not perform a real registration without an explicit, operator-supplied
// client. When wired, it performs the real create/put/enable.
func (a *GitHubPagesAdapter) Claim(ctx context.Context, fqdn string, canary *confirm.Canary) (bool, string, error) {
	owner := strings.TrimSpace(a.cfg.User)
	if owner == "" {
		return false, "", ErrMissingUser
	}
	repo := repoName(canary)
	handle := owner + "/" + repo
	path := canary.Path()

	if a.DryRun() {
		if a.isArmed() && a.live == nil {
			// Armed but not wired: do NOT silently simulate a "real" claim — make
			// the refusal explicit so an operator who thinks they armed live mode
			// is told why nothing was registered.
			return false, "", ErrLiveAdapterNotWired
		}
		a.mu.Lock()
		a.claimed[handle] = dryResource{
			owner: owner, repo: repo, fqdn: normalize(fqdn),
			path: path, token: canary.Token, pages: true,
			servedT: canary.Token,
		}
		a.mu.Unlock()
		return true, handle, nil
	}

	// Live path (requires wired Ops).
	if err := a.live.CreateRepo(ctx, owner, repo); err != nil {
		if isAlreadyExists(err) {
			return false, "", nil // not claimable (name owned) → disproof
		}
		return false, "", err
	}
	if err := a.live.PutFile(ctx, owner, repo, "CNAME", normalize(fqdn)); err != nil {
		return false, "", err
	}
	if err := a.live.PutFile(ctx, owner, repo, strings.TrimPrefix(path, "/"), canary.Token); err != nil {
		return false, "", err
	}
	if err := a.live.EnablePages(ctx, owner, repo); err != nil {
		return false, "", err
	}
	return true, handle, nil
}

// ServeCanary returns the FQDN URL the canary should be observable at. For
// GitHub Pages the file is already served by the repo created in Claim, so this
// just returns the URL. In dry-run it confirms the simulated resource exists.
func (a *GitHubPagesAdapter) ServeCanary(_ context.Context, fqdn string, canary *confirm.Canary, path string) (bool, string) {
	url := "https://" + normalize(fqdn) + path
	if a.DryRun() {
		a.mu.Lock()
		_, ok := a.claimed[a.cfg.User+"/"+repoName(canary)]
		a.mu.Unlock()
		return ok, url
	}
	return true, url
}

// Release deletes (or simulates deleting) the claimed repo. It is always called
// for a successful claim. A non-nil return is a release failure (an incident).
func (a *GitHubPagesAdapter) Release(ctx context.Context, handle string) error {
	if a.DryRun() {
		a.mu.Lock()
		_, ok := a.claimed[handle]
		delete(a.claimed, handle)
		a.mu.Unlock()
		if !ok {
			return errors.New("github-pages: release of unknown handle " + handle)
		}
		return nil
	}
	owner, repo, ok := splitHandle(handle)
	if !ok {
		return errors.New("github-pages: malformed handle " + handle)
	}
	return a.live.DeleteRepo(ctx, owner, repo)
}

// DryReflect reports the canary token a dry-run claim is "serving" at the FQDN,
// so a dry-run confirmation can be wired end-to-end in tests/demo by pointing the
// confirm.Canaries reflector at this adapter. It returns ("", false) for an
// unknown handle or in live mode.
func (a *GitHubPagesAdapter) DryReflect(handle string) (string, bool) {
	if !a.DryRun() {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.claimed[handle]
	if !ok {
		return "", false
	}
	return r.servedT, true
}

// compile-time interface check.
var _ confirm.ClaimAdapter = (*GitHubPagesAdapter)(nil)

func normalize(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func splitHandle(handle string) (owner, repo string, ok bool) {
	parts := strings.SplitN(handle, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "name already") ||
		strings.Contains(s, "422")
}
