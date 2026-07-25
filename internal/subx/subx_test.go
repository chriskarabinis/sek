package subx

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsWildcardHit covers the filter that makes brute force meaningful on a
// domain with a wildcard record. Without it every word in the list resolves and
// is reported as a real subdomain.
func TestIsWildcardHit(t *testing.T) {
	tests := []struct {
		name     string
		ips      []string
		wildcard []string
		want     bool
	}{
		{
			name:     "no wildcard means nothing is filtered",
			ips:      []string{"1.2.3.4"},
			wildcard: nil,
			want:     false,
		},
		{
			name:     "resolves only to the wildcard address",
			ips:      []string{"1.2.3.4"},
			wildcard: []string{"1.2.3.4"},
			want:     true,
		},
		{
			name:     "every address is a wildcard address",
			ips:      []string{"1.2.3.4", "5.6.7.8"},
			wildcard: []string{"1.2.3.4", "5.6.7.8"},
			want:     true,
		},
		{
			name:     "one address outside the set makes it a real host",
			ips:      []string{"1.2.3.4", "9.9.9.9"},
			wildcard: []string{"1.2.3.4", "5.6.7.8"},
			want:     false,
		},
		{
			name:     "entirely different address",
			ips:      []string{"9.9.9.9"},
			wildcard: []string{"1.2.3.4"},
			want:     false,
		},
		{
			name:     "subset of the wildcard set still counts",
			ips:      []string{"1.2.3.4"},
			wildcard: []string{"1.2.3.4", "5.6.7.8"},
			want:     true,
		},
		{
			name:     "host that did not resolve",
			ips:      nil,
			wildcard: []string{"1.2.3.4"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWildcardHit(tt.ips, tt.wildcard); got != tt.want {
				t.Errorf("isWildcardHit(%v, %v) = %v, want %v", tt.ips, tt.wildcard, got, tt.want)
			}
		})
	}
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")

	content := `# a comment
www
api

   admin
# another comment
dev
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write fixture: %v", err)
	}

	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("LoadWordlist returned error: %v", err)
	}

	want := []string{"www", "api", "admin", "dev"}
	if len(words) != len(want) {
		t.Fatalf("LoadWordlist() = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Errorf("word %d = %q, want %q", i, words[i], want[i])
		}
	}
}

func TestLoadWordlistRejects(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadWordlist(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
			t.Error("LoadWordlist on a missing file returned no error")
		}
	})

	t.Run("no usable entries", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.txt")
		if err := os.WriteFile(path, []byte("# only comments\n\n   \n"), 0o644); err != nil {
			t.Fatalf("cannot write fixture: %v", err)
		}
		if _, err := LoadWordlist(path); err == nil {
			t.Error("LoadWordlist on a comment-only file returned no error")
		}
	})
}

func TestDefaultWordlistIsUsable(t *testing.T) {
	if len(DefaultWordlist) == 0 {
		t.Fatal("DefaultWordlist is empty")
	}
	seen := make(map[string]bool)
	for _, w := range DefaultWordlist {
		if w == "" {
			t.Error("DefaultWordlist contains an empty entry")
		}
		if seen[w] {
			t.Errorf("DefaultWordlist contains %q more than once", w)
		}
		seen[w] = true
	}
}

func TestSortedKeys(t *testing.T) {
	got := sortedKeys(map[string]bool{"c": true, "a": true, "b": true})
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedKeys() = %v, want %v", got, want)
		}
	}
}
