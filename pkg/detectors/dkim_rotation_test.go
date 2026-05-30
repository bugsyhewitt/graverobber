package detectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
	"github.com/bugsyhewitt/graverobber/pkg/resolver"
	"github.com/miekg/dns"
)

// TestStaleSelectorYear_BoundaryAndExtraction exercises the pure-string
// extraction rule across the cases that drove its design: standalone years,
// years adjacent to letters/dashes/dots, embedded-in-longer-numeric noise,
// and the staleness-gap boundary itself.
func TestStaleSelectorYear_BoundaryAndExtraction(t *testing.T) {
	now := time.Date(2026, time.May, 30, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		selector string
		wantYear int
		wantOK   bool
	}{
		// Stale years embedded with various boundary characters.
		{"prefix-letters", "dkim2019", 2019, true},
		{"month-prefix", "mar2019", 2019, true},
		{"suffix-dash", "2019-key", 2019, true},
		{"middle-dashes", "key-2019-rot", 2019, true},
		{"prefix-letter-stale", "k2018", 2018, true},

		// Inside-window (< staleSelectorYearGap) years must not fire.
		{"current-year", "key2026", 0, false},
		{"one-year-old", "dkim2025", 0, false},

		// Years before the registry low bound must not fire (DKIM RFC 4871
		// is 2007; sub-2000 4-digit substrings are almost always not years).
		{"below-low-bound", "key1999", 0, false},

		// 4-digit substrings inside longer numeric runs must NOT match
		// (vendor account ids are the dominant false-positive source).
		{"vendor-account-id", "u20191234", 0, false},
		{"long-numeric", "1234567890", 0, false},

		// Selectors with no 4-digit substring at all.
		{"plain-default", "default", 0, false},
		{"plain-sendgrid", "s1", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotYear, gotOK := staleSelectorYear(tc.selector, now)
			if gotOK != tc.wantOK {
				t.Fatalf("staleSelectorYear(%q): ok=%v want=%v (year=%d)",
					tc.selector, gotOK, tc.wantOK, gotYear)
			}
			if gotYear != tc.wantYear {
				t.Errorf("staleSelectorYear(%q): year=%d want=%d", tc.selector, gotYear, tc.wantYear)
			}
		})
	}
}

// chunkTXT splits a long string into fixed-size pieces so it survives the
// 255-byte per-<character-string> limit on TXT records.
func chunkTXT(s string, size int) []string {
	var out []string
	for len(s) > size {
		out = append(out, s[:size])
		s = s[size:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// rsaKeyTXT builds a DKIM TXT record string carrying an RSA public key of the
// requested modulus size. It returns a single TXT value, ready to be served
// by a test DNS server. Used to drive the rotation-hint detector against a
// realistic (non-empty, well-formed) inline-key selector.
func rsaKeyTXT(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// dkimRotationDNSServer answers a single selector with an inline DKIM TXT key
// (modelling the "selector still publishes a live key" branch). It also serves
// a configurable CNAME-with-live-target case used by the CNAME-delegation
// rotation test. Every other query is NOERROR/empty.
func dkimRotationDNSServer(t *testing.T, inlineFQDN, inlineTXT, cnameFQDN, cnameTarget string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req := new(dns.Msg)
			if pErr := req.Unpack(buf[:n]); pErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			name := q.Name

			switch {
			case q.Qtype == dns.TypeTXT && name == dns.Fqdn(inlineFQDN):
				// DNS TXT strings cap at 255 bytes; a 2048-bit RSA public key
				// in base64 exceeds that, so chunk the value the way real
				// resolvers do (RFC 1035 §3.3.14 — multiple <character-string>s
				// concatenated by the application).
				resp.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: chunkTXT(inlineTXT, 200),
				}}
			case q.Qtype == dns.TypeCNAME && name == dns.Fqdn(cnameFQDN):
				resp.Answer = []dns.RR{&dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dns.Fqdn(cnameTarget),
				}}
			case q.Qtype == dns.TypeA && name == dns.Fqdn(cnameTarget):
				// The CNAME target resolves (live ESP delegation), so the chain
				// walk returns NOERROR rather than NXDOMAIN — exercises the
				// rotation-hint-on-live-CNAME branch (not the dangling branch).
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(127, 0, 0, 2),
				}}
			default:
				// NOERROR, no answer — nothing else is at risk.
			}

			packed, _ := resp.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()
	return pc.LocalAddr().String(), func() { pc.Close() }
}

// TestDKIM_RotationHint_InlineKey verifies that a selector whose name embeds a
// stale year and which publishes a live inline RSA key (modern bit length, so
// the weak-key check does NOT fire) produces exactly one POTENTIAL
// rotation-hint finding carrying the extracted year.
func TestDKIM_RotationHint_InlineKey(t *testing.T) {
	const target = "example.com"
	const selector = "dkim2019"
	inlineFQDN := selector + "._domainkey." + target

	// 2048-bit key — well above the RFC 8301 floor; weak-key check stays silent.
	addr, cleanup := dkimRotationDNSServer(t, inlineFQDN, rsaKeyTXT(t, 2048), "unused.invalid", "unused.invalid")
	defer cleanup()

	// Pin "now" to a deterministic year so the threshold doesn't drift with the
	// real calendar.
	origNow := nowFn
	t.Cleanup(func() { nowFn = origNow })
	nowFn = func() time.Time { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) }

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{selector})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 rotation-hint finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Vector != finding.VectorDKIM {
		t.Errorf("vector: got %q, want dkim", f.Vector)
	}
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.DKIMStaleYear != 2019 {
		t.Errorf("DKIMStaleYear: got %d, want 2019", f.DKIMStaleYear)
	}
	if f.DKIMSelector != selector {
		t.Errorf("selector: got %q, want %q", f.DKIMSelector, selector)
	}
	if f.DKIMKeyBits != 0 {
		t.Errorf("DKIMKeyBits should be zero for the rotation-hint sub-case, got %d", f.DKIMKeyBits)
	}
	if f.Subdomain != inlineFQDN {
		t.Errorf("subdomain: got %q, want %q", f.Subdomain, inlineFQDN)
	}
}

// TestDKIM_RotationHint_LiveCNAME verifies the rotation-hint also fires when
// the stale-named selector publishes its key via a CNAME whose target still
// resolves (the live-ESP-delegation branch).
func TestDKIM_RotationHint_LiveCNAME(t *testing.T) {
	const target = "example.com"
	const selector = "mar2019"
	cnameFQDN := selector + "._domainkey." + target
	cnameTarget := "mar2019.dkim.esp.invalid"

	addr, cleanup := dkimRotationDNSServer(t, "unused-inline._domainkey.example.com", "", cnameFQDN, cnameTarget)
	defer cleanup()

	origNow := nowFn
	t.Cleanup(func() { nowFn = origNow })
	nowFn = func() time.Time { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) }

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{selector})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 rotation-hint finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != finding.Potential {
		t.Errorf("confidence: got %q, want POTENTIAL", f.Confidence)
	}
	if f.DKIMStaleYear != 2019 {
		t.Errorf("DKIMStaleYear: got %d, want 2019", f.DKIMStaleYear)
	}
	if f.CNAME != "" {
		// Rotation-hint findings are about the key, not a dangling CNAME — the
		// CNAME field is reserved for the Confirmed dangling sub-case.
		t.Errorf("CNAME should be empty on a rotation-hint finding, got %q", f.CNAME)
	}
}

// TestDKIM_RotationHint_NotFiredForFreshSelector verifies that a selector whose
// embedded year is within the staleness window produces no rotation-hint
// finding even when it publishes a live inline key.
func TestDKIM_RotationHint_NotFiredForFreshSelector(t *testing.T) {
	const target = "example.com"
	const selector = "key2025" // one year old at the pinned now of 2026
	inlineFQDN := selector + "._domainkey." + target

	addr, cleanup := dkimRotationDNSServer(t, inlineFQDN, rsaKeyTXT(t, 2048), "unused.invalid", "unused.invalid")
	defer cleanup()

	origNow := nowFn
	t.Cleanup(func() { nowFn = origNow })
	nowFn = func() time.Time { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) }

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{selector})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for a 1-year-old selector, got %d: %+v", len(findings), findings)
	}
}

// TestDKIM_RotationHint_DanglingTakesPrecedence verifies that a stale-named
// selector whose CNAME target is NXDOMAIN produces only the CONFIRMED dangling
// finding — not a duplicate rotation-hint — because there is no live key to
// flag as stale when the selector itself is gone.
func TestDKIM_RotationHint_DanglingTakesPrecedence(t *testing.T) {
	const target = "example.com"
	const selector = "dkim2019"
	danglingFQDN := selector + "._domainkey." + target
	danglingTarget := "dkim2019.deleted-esp.invalid"

	addr, cleanup := dkimDNSServer(t, danglingFQDN, danglingTarget)
	defer cleanup()

	origNow := nowFn
	t.Cleanup(func() { nowFn = origNow })
	nowFn = func() time.Time { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) }

	r := resolver.New([]string{addr}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := DKIM(ctx, target, r, []string{selector})
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 dangling finding (rotation-hint must not fire on a NXDOMAIN selector), got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != finding.Confirmed {
		t.Errorf("confidence: got %q, want CONFIRMED", findings[0].Confidence)
	}
	if findings[0].DKIMStaleYear != 0 {
		t.Errorf("dangling finding must not carry DKIMStaleYear, got %d", findings[0].DKIMStaleYear)
	}
}
