package subx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
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

// TestResolveAllCancelsInFlightLookups covers what actually changed about
// cancellation: the run's context now reaches the resolver.
//
// Dispatch already stopped queueing new work on cancel, so the queue was never
// the problem. The lookups themselves were: net.LookupHost takes no context, so
// each one already running had to time out on its own before Ctrl+C could take
// effect. Threading the context through is what makes them abort.
func TestResolveAllCancelsInFlightLookups(t *testing.T) {
	observed := make(chan context.Context, 1)
	release := make(chan struct{})

	restore := stubResolver(t, func(ctx context.Context, _ string) ([]string, error) {
		select {
		case observed <- ctx:
		default:
		}
		<-release
		return nil, ctx.Err()
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := make([]string, 64)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.invalid", i)
	}

	done := make(chan int, 1)
	go func() { done <- len(ResolveAll(ctx, hosts, SourceCertLog, 4)) }()

	lookupCtx := <-observed // a lookup is running
	cancel()

	// The context handed to the resolver must observe the cancellation; that is
	// what lets a real DNS call abort instead of running to its timeout.
	select {
	case <-lookupCtx.Done():
	case <-time.After(5 * time.Second):
		t.Error("the context passed to the resolver was not cancelled with the run")
	}

	close(release)
	select {
	case n := <-done:
		if n != len(hosts) {
			t.Errorf("ResolveAll() returned %d findings, want %d", n, len(hosts))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ResolveAll did not return after its context was cancelled")
	}
}

// TestResolveAllDoesNoWorkWhenCancelled documents the guarantee for a context
// that is already cancelled on entry: not a single lookup is started.
//
// This holds without the explicit guard too, since dispatch normally exits
// before any worker parks on the channel. It pins the contract so a future
// rewrite of the pool cannot quietly lose it.
func TestResolveAllDoesNoWorkWhenCancelled(t *testing.T) {
	var lookups atomic.Int64
	restore := stubResolver(t, func(context.Context, string) ([]string, error) {
		lookups.Add(1)
		return []string{"192.0.2.1"}, nil
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hosts := make([]string, 64)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.invalid", i)
	}

	got := ResolveAll(ctx, hosts, SourceBruteForce, 8)

	if n := lookups.Load(); n != 0 {
		t.Errorf("ResolveAll started %d lookups on an already-cancelled context, want 0", n)
	}
	if len(got) != len(hosts) {
		t.Fatalf("ResolveAll() returned %d findings, want %d", len(got), len(hosts))
	}
	for i, f := range got {
		if f.Host != hosts[i] || f.Source != SourceBruteForce {
			t.Errorf("finding %d = %+v, want host %q tagged %q", i, f, hosts[i], SourceBruteForce)
		}
	}
}

// TestDetectWildcardIPs covers the two answers that matter: a domain that
// resolves every random name has a wildcard, and one that does not resolve them
// has none — a partial answer must not be reported as a wildcard, or real
// findings would be filtered away.
func TestDetectWildcardIPs(t *testing.T) {
	t.Run("wildcard", func(t *testing.T) {
		restore := stubResolver(t, func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.2", "192.0.2.1"}, nil
		})
		defer restore()

		got := DetectWildcardIPs(context.Background(), "example.invalid")
		if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "192.0.2.2" {
			t.Errorf("DetectWildcardIPs() = %v, want the probe addresses, sorted", got)
		}
	})

	t.Run("no wildcard", func(t *testing.T) {
		restore := stubResolver(t, func(context.Context, string) ([]string, error) {
			return nil, errors.New("NXDOMAIN")
		})
		defer restore()

		if got := DetectWildcardIPs(context.Background(), "example.invalid"); got != nil {
			t.Errorf("DetectWildcardIPs() = %v, want nil", got)
		}
	})
}

// TestDetectWildcardIPsHonoursContext is the regression test for the probes
// running through net.LookupHost, which takes no context: interrupting `sek sub`
// during wildcard detection meant waiting out three full DNS timeouts.
func TestDetectWildcardIPsHonoursContext(t *testing.T) {
	var cancelled atomic.Int64
	restore := stubResolver(t, func(ctx context.Context, _ string) ([]string, error) {
		if ctx.Err() != nil {
			cancelled.Add(1)
			return nil, ctx.Err()
		}
		return []string{"192.0.2.1"}, nil
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := DetectWildcardIPs(ctx, "example.invalid"); got != nil {
		t.Errorf("DetectWildcardIPs() = %v on a cancelled context, want nil", got)
	}
	if cancelled.Load() == 0 {
		t.Error("wildcard probes did not receive the cancelled context")
	}
}

// stubResolver swaps the package DNS entry point for the duration of a test.
func stubResolver(t *testing.T, fn func(context.Context, string) ([]string, error)) func() {
	t.Helper()
	prev := resolveHost
	resolveHost = fn
	return func() { resolveHost = prev }
}

// TestResolveAllStopsMidRun covers cancellation arriving after dispatch has
// begun: the call must still return every host, resolved or not.
func TestResolveAllStopsMidRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	hosts := make([]string, 200)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.invalid", i)
	}

	go cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := ResolveAll(ctx, hosts, SourceBruteForce, 4); len(got) != len(hosts) {
			t.Errorf("ResolveAll() returned %d findings, want %d", len(got), len(hosts))
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ResolveAll did not return after its context was cancelled")
	}
}
