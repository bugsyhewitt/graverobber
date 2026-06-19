package adapters

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bugsyhewitt/graverobber/pkg/confirm"
	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// TestGitHubPages_DryRunByDefault: with no token, the adapter is in dry-run and
// the full claim → serve → release lifecycle is simulated in-memory. This is the
// default safe posture — graverobber does not register anything on GitHub.
func TestGitHubPages_DryRunByDefault(t *testing.T) {
	a := NewGitHubPagesAdapter(GitHubPagesConfig{User: "operator"})
	if !a.DryRun() {
		t.Fatal("an adapter with no token MUST be in dry-run mode")
	}
	canary := confirm.NewCanaries().New()

	claimed, handle, err := a.Claim(context.Background(), "assets.example.com", canary)
	if err != nil || !claimed {
		t.Fatalf("dry-run claim should succeed: claimed=%v err=%v", claimed, err)
	}
	if handle != "operator/nmc-"+canary.ID {
		t.Errorf("handle = %q, want operator/nmc-%s", handle, canary.ID)
	}

	served, url := a.ServeCanary(context.Background(), "assets.example.com", canary, canary.Path())
	if !served {
		t.Fatal("dry-run serve should succeed")
	}
	if url != "https://assets.example.com"+canary.Path() {
		t.Errorf("url = %q", url)
	}
	// The dry-run "serves" the token, so a dry confirmation can prove through it.
	if tok, ok := a.DryReflect(handle); !ok || tok != canary.Token {
		t.Errorf("DryReflect = (%q,%v), want the canary token", tok, ok)
	}

	if err := a.Release(context.Background(), handle); err != nil {
		t.Fatalf("dry-run release should succeed: %v", err)
	}
	// After release the handle is gone.
	if _, ok := a.DryReflect(handle); ok {
		t.Error("released handle should no longer reflect")
	}
}

// TestGitHubPages_DryRunEndToEndViaConfirmer wires the dry-run adapter into the
// real TakeoverConfirmer and proves a full confirmed→released cycle with NO
// network and NO provider registration — the safe see-it-work path.
func TestGitHubPages_DryRunEndToEndViaConfirmer(t *testing.T) {
	a := NewGitHubPagesAdapter(GitHubPagesConfig{User: "operator"})

	// The canary engine's reflector consults the adapter's dry-run served token.
	canaries := confirm.NewCanaries(confirm.WithReflector(func(_ context.Context, url string, c *confirm.Canary) bool {
		// In dry-run the served URL embeds the canary path; the adapter "serves"
		// the token, so reflect iff the URL is the expected canary URL.
		return strings.HasSuffix(url, c.Path())
	}))

	c := confirm.NewTakeoverConfirmer(
		confirm.WithAdapter("github-pages", a),
		confirm.WithCanaries(canaries),
		confirm.WithGate(confirm.NewGate(true, []string{"example.com"})),
		confirm.WithBlastRadius(func(_ context.Context, fqdn string) string { return "content control of " + fqdn }),
	)

	f := &finding.Finding{
		Subdomain: "assets.example.com",
		Vector:    finding.VectorCNAME,
		Service:   "github-pages",
		Rule:      "takeover.github-pages",
		State:     finding.StateDetected,
		Severity:  finding.SeverityHigh,
	}
	r, err := c.Confirm(context.Background(), f)
	if err != nil {
		t.Fatalf("dry-run confirm: %v", err)
	}
	if !r.Confirmed {
		t.Fatalf("dry-run end-to-end should confirm, got %+v", r)
	}
	if !r.Released {
		t.Errorf("dry-run resource should be released")
	}
	if len(c.Tracker().Outstanding()) != 0 {
		t.Errorf("nothing should be left claimed after a dry-run cycle")
	}
}

// TestGitHubPages_ArmedButNotWiredRefuses: setting a token + Authorized but NOT
// supplying a GitHubOps implementation must REFUSE to claim — graverobber does
// not perform a real registration without an explicit, operator-supplied client.
func TestGitHubPages_ArmedButNotWiredRefuses(t *testing.T) {
	a := NewGitHubPagesAdapter(GitHubPagesConfig{
		User:       "operator",
		Token:      "ghp_secret",
		Authorized: true,
		// Ops intentionally nil
	})
	canary := confirm.NewCanaries().New()
	_, _, err := a.Claim(context.Background(), "assets.example.com", canary)
	if !errors.Is(err, ErrLiveAdapterNotWired) {
		t.Fatalf("armed-but-unwired must refuse with ErrLiveAdapterNotWired, got %v", err)
	}
}

// fakeOps is an in-memory GitHubOps for exercising the live code path without
// touching GitHub.
type fakeOps struct {
	created   map[string]bool
	files     map[string]string
	pages     map[string]bool
	deleted   map[string]bool
	createErr error
}

func newFakeOps() *fakeOps {
	return &fakeOps{created: map[string]bool{}, files: map[string]string{}, pages: map[string]bool{}, deleted: map[string]bool{}}
}

func (o *fakeOps) CreateRepo(_ context.Context, owner, repo string) error {
	if o.createErr != nil {
		return o.createErr
	}
	o.created[owner+"/"+repo] = true
	return nil
}
func (o *fakeOps) PutFile(_ context.Context, owner, repo, path, content string) error {
	o.files[owner+"/"+repo+"/"+path] = content
	return nil
}
func (o *fakeOps) EnablePages(_ context.Context, owner, repo string) error {
	o.pages[owner+"/"+repo] = true
	return nil
}
func (o *fakeOps) DeleteRepo(_ context.Context, owner, repo string) error {
	o.deleted[owner+"/"+repo] = true
	return nil
}

// TestGitHubPages_LivePathViaFakeOps exercises the live claim/serve/release path
// against a fake GitHubOps: the repo is created with a CNAME file and the canary,
// Pages is enabled, and Release deletes the repo. (No real GitHub I/O.)
func TestGitHubPages_LivePathViaFakeOps(t *testing.T) {
	ops := newFakeOps()
	a := NewGitHubPagesAdapter(GitHubPagesConfig{
		User: "operator", Token: "ghp_secret", Authorized: true, Ops: ops,
	})
	if a.DryRun() {
		t.Fatal("a fully-armed adapter (token+authorized+ops) must NOT be in dry-run")
	}
	canary := confirm.NewCanaries().New()

	claimed, handle, err := a.Claim(context.Background(), "assets.example.com", canary)
	if err != nil || !claimed {
		t.Fatalf("live claim via fake ops should succeed: claimed=%v err=%v", claimed, err)
	}
	repo := "operator/nmc-" + canary.ID
	if !ops.created[repo] {
		t.Errorf("repo %s should have been created", repo)
	}
	if ops.files[repo+"/CNAME"] != "assets.example.com" {
		t.Errorf("CNAME file should be the dangling FQDN, got %q", ops.files[repo+"/CNAME"])
	}
	if ops.files[repo+"/"+strings.TrimPrefix(canary.Path(), "/")] != canary.Token {
		t.Errorf("canary file should hold the token")
	}
	if !ops.pages[repo] {
		t.Errorf("pages should be enabled")
	}

	if err := a.Release(context.Background(), handle); err != nil {
		t.Fatalf("live release should succeed: %v", err)
	}
	if !ops.deleted[repo] {
		t.Errorf("repo should be deleted on release")
	}
}

// TestGitHubPages_LiveNotClaimable: a CreateRepo failure that means "name already
// exists" is a disproof (claimed=false, nil error), not an error.
func TestGitHubPages_LiveNotClaimable(t *testing.T) {
	ops := newFakeOps()
	ops.createErr = errors.New("422 Repository creation failed: name already exists on this account")
	a := NewGitHubPagesAdapter(GitHubPagesConfig{User: "operator", Token: "t", Authorized: true, Ops: ops})
	canary := confirm.NewCanaries().New()
	claimed, _, err := a.Claim(context.Background(), "assets.example.com", canary)
	if err != nil {
		t.Fatalf("a name-exists failure is a disproof, not an error: %v", err)
	}
	if claimed {
		t.Error("name-already-exists must yield claimed=false (disproof)")
	}
}

// TestGitHubPages_MissingUser: no operator account → error.
func TestGitHubPages_MissingUser(t *testing.T) {
	a := NewGitHubPagesAdapter(GitHubPagesConfig{})
	_, _, err := a.Claim(context.Background(), "assets.example.com", confirm.NewCanaries().New())
	if !errors.Is(err, ErrMissingUser) {
		t.Fatalf("missing user must error with ErrMissingUser, got %v", err)
	}
}
