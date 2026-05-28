package main

import (
	"reflect"
	"testing"
)

// TestParseSelectors verifies the --selectors comma-list parser: trimming,
// lower-casing, blank-dropping, and the empty-input → nil (use defaults) case.
func TestParseSelectors(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"s1", []string{"s1"}},
		{"s1,s2", []string{"s1", "s2"}},
		{" S1 , Selector2 ", []string{"s1", "selector2"}},
		{"k1,,k2,", []string{"k1", "k2"}},
	}
	for _, c := range cases {
		got := parseSelectors(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseSelectors(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
