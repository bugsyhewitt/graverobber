package nsproviders

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleREADME mirrors the real indianajson/can-i-take-over-dns README table
// layout (` | `-separated cells, <br>-joined nameserver fingerprints, escaped
// wildcards, <sub>/<sup> annotations, and a trailing Private DNS section that
// must be ignored).
const sampleREADME = "# Can I Take Over DNS?\n" +
	"\n" +
	"## DNS Providers\n" +
	"\n" +
	"Provider | Status | Fingerprint | Takeover Instructions\n" +
	"--------- | ------ | ----------- | -------------\n" +
	"[AWS Route 53](https://aws.amazon.com/) | **Not Vulnerable** | ns-\\*\\*\\*\\*.awsdns-\\*\\*.org<br>ns-\\*\\*\\*.awsdns-\\*\\*.com | [Issue #1](x)\n" +
	"[Azure (Microsoft)](https://azure.microsoft.com/) | **Edge Case** | ns1-\\*\\*.azure-dns.com<br>ns2-\\*\\*.azure-dns.net | [Issue #5](x)\n" +
	"[Digital Ocean](https://digitalocean.com/) | **Vulnerable** | ns1.digitalocean.com<br>ns2.digitalocean.com | [Issue #22](x)\n" +
	"[DNSimple](https://dnsimple.com/) | **Vulnerable** | ns1.dnsimple.com<br>ns2.dnsimple.com | [Issue #16](x)\n" +
	"[Domain.com](https://domain.com/)| **Vulnerable <sub><sup>(w/ purchase)</sub></sup>** | ns1.domain.com<br>ns2.domain.com | [Issue #17](x)\n" +
	"[Cloudflare](https://cloudflare.com/) | **Not Vulnerable** | \\*.ns.cloudflare.com | [Issue #10](x)\n" +
	"[NS1](https://nsone.net/) | **Registration Closed** | dns1.p\\*\\*.nsone.net<br>dns2.p\\*\\*.nsone.net | [Issue #7](x)\n" +
	"\n" +
	"## Private DNS\n" +
	"\n" +
	"Owner | Status | Fingerprint |\n" +
	"----- | ------ | ----------- |\n" +
	"[Apple](https://apple.com/) | **Not Vulnerable** | a.ns.apple.com<br>b.ns.apple.com |\n"

func TestParseREADME_VulnerableClassification(t *testing.T) {
	l, err := ParseREADME([]byte(sampleREADME))
	if err != nil {
		t.Fatalf("ParseREADME: %v", err)
	}

	// digitalocean and dnsimple are plainly Vulnerable; domain.com is
	// Vulnerable with an annotation.
	wantVuln := map[string]bool{
		"digitalocean.com": true,
		"dnsimple.com":     true,
		"domain.com":       true,
	}
	// AWS (Not Vulnerable), Azure (Edge Case), Cloudflare (Not Vulnerable),
	// NS1 (Registration Closed) must NOT be vulnerable.
	wantNotVuln := []string{"awsdns-", "azure-dns.com", "cloudflare.com", "nsone.net"}

	gotVuln := make(map[string]bool)
	for _, s := range l.VulnerableSuffixes() {
		gotVuln[s] = true
	}
	for suffix := range wantVuln {
		if !gotVuln[suffix] {
			t.Errorf("expected %q to be vulnerable; vulnerable set=%v", suffix, l.VulnerableSuffixes())
		}
	}
	for _, suffix := range wantNotVuln {
		for _, v := range l.VulnerableSuffixes() {
			if v == suffix {
				t.Errorf("provider %q should not be vulnerable", suffix)
			}
		}
	}
}

func TestParseREADME_IgnoresPrivateDNS(t *testing.T) {
	l, err := ParseREADME([]byte(sampleREADME))
	if err != nil {
		t.Fatalf("ParseREADME: %v", err)
	}
	for _, p := range l.Providers() {
		if strings.Contains(p.Suffix, "apple.com") {
			t.Errorf("Private DNS entry apple.com must not appear in parsed list")
		}
	}
}

func TestParseREADME_Empty(t *testing.T) {
	_, err := ParseREADME([]byte("# No table here\n\nNothing to parse.\n"))
	if err == nil {
		t.Fatal("expected error parsing README with no provider table")
	}
}

func TestMatch_VulnerableOnly(t *testing.T) {
	l, err := ParseREADME([]byte(sampleREADME))
	if err != nil {
		t.Fatalf("ParseREADME: %v", err)
	}

	// A DigitalOcean nameserver (vulnerable) must match.
	if got := l.Match("ns1.digitalocean.com"); got == "" {
		t.Error("expected DigitalOcean nameserver to match a vulnerable provider")
	}
	// An Azure nameserver (Edge Case → not vulnerable) must NOT match.
	if got := l.Match("ns1-04.azure-dns.com"); got != "" {
		t.Errorf("Azure nameserver should not match (edge case), got %q", got)
	}
	// A Cloudflare nameserver (Not Vulnerable) must NOT match.
	if got := l.Match("kim.ns.cloudflare.com"); got != "" {
		t.Errorf("Cloudflare nameserver should not match, got %q", got)
	}
}

func TestSuffixFromHost(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"ns-****.awsdns-**.org", "awsdns.org"},
		{"ns1.digitalocean.com", "digitalocean.com"},
		{"*.ns.cloudflare.com", "cloudflare.com"},
		{"a.dns.gandi.net", "gandi.net"},
		{"ns-****.awsdns-**.co.uk", "awsdns.co.uk"},
		{"justonelabel", ""},
	}
	for _, c := range cases {
		got := suffixFromHost(c.host)
		if got != c.want {
			t.Errorf("suffixFromHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestIsVulnerableStatus(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"**Vulnerable**", true},
		{"**Vulnerable <sub><sup>(w/ purchase)</sub></sup>**", true},
		{"**Not Vulnerable**", false},
		{"**Not Vulnerable</sup>**", false},
		{"**Edge Case**", false},
		{"**Registration Closed**", false},
	}
	for _, c := range cases {
		if got := isVulnerableStatus(c.status); got != c.want {
			t.Errorf("isVulnerableStatus(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}

func TestDefault_AllVulnerable(t *testing.T) {
	d := Default()
	if d.Len() == 0 {
		t.Fatal("default provider list is empty")
	}
	if len(d.VulnerableSuffixes()) != d.Len() {
		t.Errorf("expected all %d default providers to be vulnerable, got %d",
			d.Len(), len(d.VulnerableSuffixes()))
	}
	// Spot-check a couple of historically-known providers.
	if d.Match("ns-100.awsdns-12.org") == "" {
		t.Error("default list should match an AWS Route 53 nameserver")
	}
	if d.Match("ns1.linode.com") == "" {
		t.Error("default list should match a Linode nameserver")
	}
}

func TestLoadMarshalRoundTrip(t *testing.T) {
	orig, err := ParseREADME([]byte(sampleREADME))
	if err != nil {
		t.Fatalf("ParseREADME: %v", err)
	}
	data, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reloaded, err := Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Len() != orig.Len() {
		t.Errorf("round-trip length mismatch: got %d want %d", reloaded.Len(), orig.Len())
	}
	if len(reloaded.VulnerableSuffixes()) != len(orig.VulnerableSuffixes()) {
		t.Errorf("round-trip vulnerable-count mismatch")
	}
}

func TestLoad_CorruptIsError(t *testing.T) {
	if _, err := Load([]byte("not json")); err == nil {
		t.Error("expected error loading non-JSON payload")
	}
	if _, err := Load([]byte("[]")); err == nil {
		t.Error("expected error loading empty provider array")
	}
}

func TestLoadCachedOrDefault_FallsBackToDefault(t *testing.T) {
	// Point UserConfigDir at an empty temp dir so no cache exists; the function
	// must degrade to the compiled-in default rather than panic or return nil.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp) // belt-and-suspenders for non-XDG platforms

	l := LoadCachedOrDefault()
	if l == nil || l.Len() == 0 {
		t.Fatal("LoadCachedOrDefault returned an empty list with no cache present")
	}
}

func TestLoadCachedOrDefault_PrefersCache(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	path, err := CachePath()
	if err != nil {
		t.Fatalf("CachePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A minimal cache with a single, distinctive provider not in the default.
	cache := `[{"suffix":"example-only-cache.test","label":"Cache Only","vulnerable":true}]`
	if err := os.WriteFile(path, []byte(cache), 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	l := LoadCachedOrDefault()
	if l.Match("ns1.example-only-cache.test") == "" {
		t.Error("LoadCachedOrDefault did not prefer the on-disk cache")
	}
	// And it should NOT contain a default-only provider, proving the cache
	// replaced (not merged with) the default.
	if l.Match("ns1.linode.com") != "" {
		t.Error("cache load unexpectedly included a default-only provider")
	}
}

func TestDiffVulnerable(t *testing.T) {
	prev := newList([]Provider{
		{Suffix: "a.com", Vulnerable: true},
		{Suffix: "b.com", Vulnerable: true},
		{Suffix: "c.com", Vulnerable: false},
	})
	fresh := newList([]Provider{
		{Suffix: "b.com", Vulnerable: true}, // unchanged
		{Suffix: "c.com", Vulnerable: true}, // newly vulnerable -> added
		{Suffix: "d.com", Vulnerable: true}, // new -> added
		// a.com dropped from vulnerable set -> removed
	})
	added, removed := diffVulnerable(prev, fresh)
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
}
