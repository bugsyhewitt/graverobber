package finding

import "testing"

// TestConfidence_AtLeast exercises the threshold predicate behind the scanner's
// --min-confidence filter across the full tier lattice, including the
// no-threshold (empty min) and malformed-value edge cases.
func TestConfidence_AtLeast(t *testing.T) {
	cases := []struct {
		conf Confidence
		min  Confidence
		want bool
		desc string
	}{
		{Confirmed, Confirmed, true, "confirmed meets confirmed"},
		{Confirmed, Likely, true, "confirmed meets likely"},
		{Confirmed, Potential, true, "confirmed meets potential"},
		{Likely, Confirmed, false, "likely below confirmed"},
		{Likely, Likely, true, "likely meets likely"},
		{Likely, Potential, true, "likely meets potential"},
		{Potential, Confirmed, false, "potential below confirmed"},
		{Potential, Likely, false, "potential below likely"},
		{Potential, Potential, true, "potential meets potential"},
		{Potential, "", true, "empty min passes anything (no threshold)"},
		{Confirmed, "", true, "empty min passes confirmed"},
		{"", Potential, false, "malformed confidence never meets a threshold"},
		{"bogus", Confirmed, false, "unrecognised confidence ranks below potential"},
	}
	for _, tc := range cases {
		if got := tc.conf.AtLeast(tc.min); got != tc.want {
			t.Errorf("%s: %q.AtLeast(%q) = %v, want %v", tc.desc, tc.conf, tc.min, got, tc.want)
		}
	}
}

// TestParseConfidence verifies tier-name parsing is case-insensitive, treats the
// empty string as "no threshold", and rejects unknown names.
func TestParseConfidence(t *testing.T) {
	cases := []struct {
		in     string
		want   Confidence
		wantOK bool
	}{
		{"", "", true},
		{"confirmed", Confirmed, true},
		{"CONFIRMED", Confirmed, true},
		{"Confirmed", Confirmed, true},
		{"likely", Likely, true},
		{"LIKELY", Likely, true},
		{"potential", Potential, true},
		{"POTENTIAL", Potential, true},
		{"high", "", false},
		{"none", "", false},
		{"confirm", "", false},
	}
	for _, tc := range cases {
		got, ok := ParseConfidence(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("ParseConfidence(%q) = (%q, %v), want (%q, %v)",
				tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
