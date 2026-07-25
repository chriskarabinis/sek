package dnsx

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestRootDomain covers the Public Suffix List lookup. Taking the last two
// labels collapsed shop.example.co.uk to co.uk, so platform detection then ran
// against the TLD instead of the site.
func TestRootDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"plain", "example.com", "example.com"},
		{"subdomain", "www.example.com", "example.com"},
		{"deep subdomain", "a.b.c.example.com", "example.com"},
		{"multi-label suffix", "example.co.uk", "example.co.uk"},
		{"subdomain of multi-label suffix", "shop.example.co.uk", "example.co.uk"},
		{"greek commercial", "example.com.gr", "example.com.gr"},
		{"subdomain of greek commercial", "www.example.com.gr", "example.com.gr"},
		{"greek", "example.gr", "example.gr"},
		{"trailing dot", "example.com.", "example.com"},
		{"uppercase", "WWW.EXAMPLE.COM", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RootDomain(tt.domain); got != tt.want {
				t.Errorf("RootDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestRcodeError(t *testing.T) {
	tests := []struct {
		rcode int
		want  string
	}{
		{dns.RcodeNameError, "NXDOMAIN"},
		{dns.RcodeServerFailure, "SERVFAIL"},
		{dns.RcodeRefused, "REFUSED"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			err := &RcodeError{Rcode: tt.rcode}
			if got := err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}

	// An unmapped code must still render rather than come out blank.
	if got := (&RcodeError{Rcode: 4095}).Error(); got == "" {
		t.Error("Error() for an unknown rcode returned an empty string")
	}
}

func TestIsNameError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nxdomain", &RcodeError{Rcode: dns.RcodeNameError}, true},
		{"servfail", &RcodeError{Rcode: dns.RcodeServerFailure}, false},
		{"wrapped nxdomain", fmt.Errorf("probe: %w", &RcodeError{Rcode: dns.RcodeNameError}), true},
		{"unrelated", errors.New("timeout"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNameError(tt.err); got != tt.want {
				t.Errorf("IsNameError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestMailbox(t *testing.T) {
	tests := []struct {
		mbox string
		want string
	}{
		{"admin.example.com.", "admin@example.com"},
		{"hostmaster.example.co.uk.", "hostmaster@example.co.uk"},
		{"noreply.example.com", "noreply@example.com"},
		{"nodots", "nodots"},
	}
	for _, tt := range tests {
		t.Run(tt.mbox, func(t *testing.T) {
			if got := mailbox(tt.mbox); got != tt.want {
				t.Errorf("mailbox(%q) = %q, want %q", tt.mbox, got, tt.want)
			}
		})
	}
}

func TestServerAddress(t *testing.T) {
	tests := []struct {
		name   string
		custom string
		want   string
	}{
		{"bare ipv4 gets default port", "8.8.8.8", "8.8.8.8:53"},
		{"explicit port kept", "8.8.8.8:5353", "8.8.8.8:5353"},
		{"bracketed ipv6 with port kept", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serverAddress(tt.custom); got != tt.want {
				t.Errorf("serverAddress(%q) = %q, want %q", tt.custom, got, tt.want)
			}
		})
	}

	// With no override it must still produce something dialable.
	if got := serverAddress(""); !strings.Contains(got, ":") {
		t.Errorf("serverAddress(\"\") = %q, want host:port", got)
	}
}

func TestMatchProvider(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"ns1.cloudflare.com", "Cloudflare"},
		{"NS-1234.AWSDNS-56.ORG", "Amazon Route 53 (AWS)"},
		{"ns1.papaki.gr", "Papaki (GR)"},
		{"ns1.some-unknown-host.net", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := matchProvider(tt.host); got != tt.want {
				t.Errorf("matchProvider(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestRandomLabelIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		label := RandomLabel()
		if seen[label] {
			t.Fatalf("RandomLabel() repeated %q within 100 calls", label)
		}
		seen[label] = true
		if strings.ContainsAny(label, ".") {
			t.Errorf("RandomLabel() = %q, must be a single label", label)
		}
	}
}
