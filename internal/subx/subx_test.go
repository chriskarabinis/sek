package subx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestResolveAllPreservesOrder covers the concurrent resolution of certificate
// transparency hits. Order must match the input so output stays deterministic,
// and every host must get an entry even when it does not resolve.
func TestResolveAllPreservesOrder(t *testing.T) {
	// .invalid is reserved by RFC 2606 and never resolves, so this exercises the
	// ordering and tagging without depending on the network.
	hosts := []string{
		"a.example.invalid",
		"b.example.invalid",
		"c.example.invalid",
		"d.example.invalid",
	}

	got := ResolveAll(context.Background(), hosts, SourceCertLog, 3)

	if len(got) != len(hosts) {
		t.Fatalf("ResolveAll() returned %d findings, want %d", len(got), len(hosts))
	}
	for i, f := range got {
		if f.Host != hosts[i] {
			t.Errorf("finding %d = %q, want %q — order must follow the input", i, f.Host, hosts[i])
		}
		if f.Source != SourceCertLog {
			t.Errorf("finding %d source = %q, want %q", i, f.Source, SourceCertLog)
		}
	}
}

// TestResolveAllEmpty covers the degenerate input that would otherwise start a
// pool of zero workers and deadlock.
func TestResolveAllEmpty(t *testing.T) {
	if got := ResolveAll(context.Background(), nil, SourceCertLog, 10); len(got) != 0 {
		t.Errorf("ResolveAll(nil) = %v, want no findings", got)
	}
}

// TestResolveAllStopsOnCancel checks that a cancelled context ends dispatch
// rather than leaving the caller blocked.
func TestResolveAllStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hosts := make([]string, 200)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.invalid", i)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ResolveAll(ctx, hosts, SourceBruteForce, 4)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ResolveAll did not return after its context was cancelled")
	}
}
