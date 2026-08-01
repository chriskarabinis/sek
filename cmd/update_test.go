package cmd

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"patch bump", "0.1.6", "0.1.7", true},
		{"minor bump", "0.1.6", "0.2.0", true},
		{"major bump", "0.1.6", "1.0.0", true},
		{"identical", "0.1.6", "0.1.6", false},
		{"older patch", "0.1.7", "0.1.6", false},
		{"older minor", "0.2.0", "0.1.9", false},
		{"older major", "1.0.0", "0.9.9", false},
		{"double-digit patch is not lexical", "0.1.9", "0.1.10", true},
		{"double-digit minor is not lexical", "0.9.0", "0.10.0", true},
		{"major beats minor", "0.9.9", "1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewer(tt.current, tt.latest); got != tt.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestResolveVersion(t *testing.T) {
	previous := version
	defer func() { version = previous }()

	// A value stamped in by -ldflags must win over anything else.
	version = "9.9.9"
	if got := resolveVersion(); got != "9.9.9" {
		t.Errorf("resolveVersion() = %q, want the linker-provided 9.9.9", got)
	}

	// Left at the fallback, it must report the fallback rather than a
	// pseudo-version synthesised from a dirty work tree.
	version = fallbackVersion
	got := resolveVersion()
	if got != fallbackVersion && !releaseTag.MatchString("v"+got) {
		t.Errorf("resolveVersion() = %q, want %q or a clean release tag", got, fallbackVersion)
	}
}

// TestReleaseTagRejectsPseudoVersions guards the check that keeps `go build`
// from reporting something like 0.0.0-20260725164926-23e2cfa54d6e+dirty.
func TestReleaseTagRejectsPseudoVersions(t *testing.T) {
	accepted := []string{"v0.1.6", "v1.0.0", "v10.20.30"}
	rejected := []string{
		"(devel)",
		"",
		"v0.0.0-20260725164926-23e2cfa54d6e",
		"v0.0.0-20260725164926-23e2cfa54d6e+dirty",
		"v0.1.7-rc1",
		"0.1.6",
	}

	for _, v := range accepted {
		if !releaseTag.MatchString(v) {
			t.Errorf("releaseTag rejected %q, want it accepted", v)
		}
	}
	for _, v := range rejected {
		if releaseTag.MatchString(v) {
			t.Errorf("releaseTag accepted %q, want it rejected", v)
		}
	}
}

// TestTruncate covers shortening a header value for the table. The previous
// implementation sliced s[:max-3] unguarded, so any max below 3 panicked, and
// it counted bytes, which could cut a multi-byte character in half.
func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"shorter than max", "abc", 10, "abc"},
		{"exactly max", "abcde", 5, "abcde"},
		{"longer than max", "abcdefghij", 8, "abcde..."},
		{"max equals ellipsis", "abcdef", 3, "abc"},
		{"max below ellipsis", "abcdef", 2, "ab"},
		{"zero max", "abcdef", 0, ""},
		{"negative max", "abcdef", -1, ""},
		{"multi-byte is not split", "ααααααααββ", 8, "ααααα..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncate(tt.in, tt.max); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}
