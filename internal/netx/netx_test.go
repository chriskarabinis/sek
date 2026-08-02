package netx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResolveIP(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    string
		wantErr bool
	}{
		{"ipv4 passes through", "8.8.8.8", "8.8.8.8", false},
		{"ipv6 passes through", "2001:4860:4860::8888", "2001:4860:4860::8888", false},
		{"loopback name", "localhost", "127.0.0.1", false},
		{"unresolvable", "this-host-does-not-exist.invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveIP(context.Background(), tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ResolveIP(%q) = %q, want an error", tt.target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveIP(%q) returned error: %v", tt.target, err)
			}
			if got != tt.want {
				t.Errorf("ResolveIP(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

// TestResolveIPHonoursCancellation is the point of taking a context: a name
// that needs a real lookup must fail fast once the caller has given up, rather
// than sitting out the resolver's own timeout.
func TestResolveIPHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := ResolveIP(ctx, "example.com")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ResolveIP with a cancelled context returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ResolveIP ignored the cancelled context")
	}
}

// A literal address needs no lookup at all, so cancellation must not turn it
// into a failure.
func TestResolveIPSkipsLookupForLiterals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ResolveIP(ctx, "192.0.2.1")
	if err != nil {
		t.Fatalf("ResolveIP returned error for a literal: %v", err)
	}
	if got != "192.0.2.1" {
		t.Errorf("ResolveIP = %q, want the literal back", got)
	}
	if errors.Is(err, context.Canceled) {
		t.Error("a literal address must not consult the resolver")
	}
}
