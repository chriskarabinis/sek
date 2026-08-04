package cmd

import "testing"

// TestSelectLookups covers the -t value to section mapping. AAAA is the case
// that regressed: the command's own help offered it, but only the "A" spelling
// selected the section that answers for both address families, so asking for
// the v6 records by name failed with "unknown record type".
func TestSelectLookups(t *testing.T) {
	titles := func(indices []int) []string {
		var out []string
		for _, i := range indices {
			out = append(out, dnsLookups[i].title)
		}
		return out
	}

	tests := []struct {
		name   string
		wanted string
		want   []string
	}{
		{"empty selects everything", "", nil},
		{"A", "A", []string{"A / AAAA"}},
		{"AAAA is an alias for the A section", "AAAA", []string{"A / AAAA"}},
		{"MX", "MX", []string{"MX"}},
		{"EMAIL", "EMAIL", []string{"Email Security (SPF / DMARC / DKIM)"}},
		{"unknown selects nothing", "PTR", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectLookups(tt.wanted)

			if tt.wanted == "" {
				if len(got) != len(dnsLookups) {
					t.Fatalf("selectLookups(%q) picked %d sections, want all %d",
						tt.wanted, len(got), len(dnsLookups))
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("selectLookups(%q) = %v, want %v", tt.wanted, titles(got), tt.want)
			}
			for i, want := range tt.want {
				if dnsLookups[got[i]].title != want {
					t.Errorf("selectLookups(%q)[%d] = %q, want %q",
						tt.wanted, i, dnsLookups[got[i]].title, want)
				}
			}
		})
	}
}

// Every alias must be upper-case: the command folds -t before matching but
// leaves the table alone, so a lower-case alias could never be selected.
func TestLookupKeysAreUppercase(t *testing.T) {
	for _, l := range dnsLookups {
		for _, key := range append([]string{l.key}, l.aliases...) {
			for _, r := range key {
				if r >= 'a' && r <= 'z' {
					t.Errorf("%s: key %q is not upper-case", l.title, key)
					break
				}
			}
		}
	}
}
