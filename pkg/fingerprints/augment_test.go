package fingerprints

import (
	"testing"
)

// TestApplyAugment_SetsClaimAdapter: the embedded augment.json assigns a
// claim_adapter to the seed services (GitHub Pages → github-pages, AWS/S3 → s3),
// and Apply stamps it onto the matching DB entries.
func TestApplyAugment_SetsClaimAdapter(t *testing.T) {
	db, err := Embedded()
	if err != nil {
		t.Fatalf("load embedded DB: %v", err)
	}
	if err := ApplyAugment(db); err != nil {
		t.Fatalf("ApplyAugment: %v", err)
	}

	want := map[string]string{
		"GitHub Pages": "github-pages",
		"AWS/S3":       "s3",
	}
	got := map[string]string{}
	for _, e := range db.Entries() {
		if e.ClaimAdapter != "" {
			got[e.Service] = e.ClaimAdapter
		}
	}
	for svc, adapter := range want {
		if got[svc] != adapter {
			t.Errorf("service %q claim_adapter = %q, want %q", svc, got[svc], adapter)
		}
	}
}

// TestAugment_PreservedAcrossReload is the D1 invariant: a sync that re-Loads the
// upstream fingerprints (which carry NO claim_adapter) must NOT lose graverobber's
// augmentations — they live in the side-file and are re-applied. This simulates
// `make fpdb-sync`: parse fresh upstream JSON (no claim_adapter), then re-apply
// the augment side-file, and confirm the adapter is back.
func TestAugment_PreservedAcrossReload(t *testing.T) {
	// Fresh "upstream" payload: the canonical schema, explicitly WITHOUT any
	// claim_adapter field (as the real upstream fingerprints.json is).
	upstream := []byte(`[
		{"service":"GitHub Pages","cname":["github.io"],"fingerprint":"There isn't a GitHub Pages site here.","nxdomain":false,"status":"Vulnerable"},
		{"service":"AWS/S3","cname":["s3.amazonaws.com"],"fingerprint":"The specified bucket does not exist","nxdomain":false,"status":"Vulnerable"}
	]`)
	fresh, err := Load(upstream)
	if err != nil {
		t.Fatalf("load fresh upstream: %v", err)
	}
	// Before re-applying augmentations the synced entries have no adapter.
	for _, e := range fresh.Entries() {
		if e.ClaimAdapter != "" {
			t.Fatalf("a freshly-synced upstream entry should have NO claim_adapter, %q had %q", e.Service, e.ClaimAdapter)
		}
	}
	// Re-apply the augmentation side-file (the D1 sync step).
	if err := ApplyAugment(fresh); err != nil {
		t.Fatalf("re-apply augment: %v", err)
	}
	got := map[string]string{}
	for _, e := range fresh.Entries() {
		got[e.Service] = e.ClaimAdapter
	}
	if got["GitHub Pages"] != "github-pages" || got["AWS/S3"] != "s3" {
		t.Errorf("augmentations not preserved across reload: %v", got)
	}
}

// TestAugment_NXDomainOverride: an augmentation may override the upstream
// nxdomain flag (A5 — the DB lags reality). Apply applies the override.
func TestAugment_NXDomainOverride(t *testing.T) {
	db, err := Load([]byte(`[{"service":"Example","cname":["example.test"],"fingerprint":"x","nxdomain":false,"status":"Vulnerable"}]`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tru := true
	set := &AugmentSet{byService: map[string]Augment{
		"example": {Service: "Example", ClaimAdapter: "example-adapter", NXDomain: &tru},
	}}
	set.Apply(db)
	e := db.Entries()[0]
	if e.ClaimAdapter != "example-adapter" {
		t.Errorf("claim_adapter = %q, want example-adapter", e.ClaimAdapter)
	}
	if !e.NXDomain {
		t.Errorf("nxdomain override should have set NXDomain=true")
	}
}

// TestClaimable lists the services that have an adapter assigned.
func TestClaimable(t *testing.T) {
	db, err := Embedded()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := ApplyAugment(db); err != nil {
		t.Fatalf("ApplyAugment: %v", err)
	}
	claimable := db.Claimable()
	if len(claimable) == 0 {
		t.Fatal("expected at least the GitHub Pages / S3 services to be claimable")
	}
	found := map[string]bool{}
	for _, sa := range claimable {
		found[sa.Service] = true
	}
	for _, svc := range []string{"GitHub Pages", "AWS/S3"} {
		if !found[svc] {
			t.Errorf("expected %q in the claimable set", svc)
		}
	}
}

// TestEmbeddedAugment_Parses guards the vendored augment.json against a malformed
// edit (it must always parse — a broken side-file silently drops every adapter).
func TestEmbeddedAugment_Parses(t *testing.T) {
	set, err := EmbeddedAugment()
	if err != nil {
		t.Fatalf("embedded augment.json must parse: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("embedded augment.json should not be empty")
	}
	// The reference adapter must be present.
	if aug, ok := set.For("GitHub Pages"); !ok || aug.ClaimAdapter != "github-pages" {
		t.Errorf("GitHub Pages augmentation missing or wrong: %+v ok=%v", aug, ok)
	}
}
