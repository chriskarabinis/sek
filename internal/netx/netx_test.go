package netx

import (
	"context"
	"testing"
)

func TestResolvePreferIPv4(t *testing.T) {
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
			got, err := ResolvePreferIPv4(context.Background(), tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ResolvePreferIPv4(%q) = %q, want an error", tt.target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolvePreferIPv4(%q) returned error: %v", tt.target, err)
			}
			if got != tt.want {
				t.Errorf("ResolvePreferIPv4(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

// TestResolvePreferIPv4HonoursContext is the regression test for the lookup
// running through net.LookupHost, which takes no context: a cancelled command
// had to sit through the full DNS timeout before it could return.
func TestResolvePreferIPv4HonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := ResolvePreferIPv4(ctx, "example.invalid"); err == nil {
		t.Error("ResolvePreferIPv4 with a cancelled context returned no error")
	}

	// An IP literal needs no lookup at all, so cancellation must not affect it.
	if got, err := ResolvePreferIPv4(ctx, "9.9.9.9"); err != nil || got != "9.9.9.9" {
		t.Errorf("ResolvePreferIPv4(cancelled, IP) = %q, %v; want the address unchanged", got, err)
	}
}
