package dnsx

import (
	"context"
	"strings"
	"testing"
	"time"

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
		{"bare ipv6 gets brackets and default port", "2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
		// Bracketed with no port fails SplitHostPort for the same reason a bare
		// literal does, and JoinHostPort would bracket the brackets: the result
		// was "[[::1]]:53", which fails every query it is handed.
		{"bracketed ipv6 without port", "[::1]", "[::1]:53"},
		// net.ParseIP rejects a zone identifier, so a scoped literal has to be
		// recognised by its brackets rather than by parsing it — otherwise it
		// takes the same doubling path "[::1]" used to.
		{"bracketed scoped ipv6 without port", "[fe80::1%eth0]", "[fe80::1%eth0]:53"},
		{"bracketed scoped ipv6 with port kept", "[fe80::1%eth0]:5353", "[fe80::1%eth0]:5353"},
		{"bare scoped ipv6 gets brackets", "fe80::1%eth0", "[fe80::1%eth0]:53"},
		{"surrounding space trimmed", "  8.8.8.8  ", "8.8.8.8:53"},
		{"hostname gets default port", "resolver.example.com", "resolver.example.com:53"},
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

// TestProviderForIP covers matching an address against the published operator
// ranges. Matching on leading digits missed whole blocks: 104.16.0.0/13 runs to
// 104.23.255.255, but only 104.16-104.21 were listed, so a Cloudflare site on
// 104.22.x reported no platform at all.
func TestProviderForIP(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"104.16.0.1", "Cloudflare"},
		{"104.21.55.9", "Cloudflare"},
		{"104.22.10.1", "Cloudflare"},
		{"104.23.255.254", "Cloudflare"},
		{"104.27.1.1", "Cloudflare"},
		{"131.0.72.5", "Cloudflare"},
		{"172.67.200.1", "Cloudflare"},
		{"198.41.200.1", "Cloudflare"},
		{"2606:4700::1111", "Cloudflare"},
		// Outside every listed range.
		{"104.28.0.1", ""},
		{"8.8.8.8", ""},
		{"1.1.1.1", ""},
		{"2001:4860:4860::8888", ""},
		// A string-prefix match would have claimed these; a CIDR match must not.
		{"104.160.0.1", ""},
		{"172.640.0.1", ""},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := providerForIP(tt.ip); got != tt.want {
				t.Errorf("providerForIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// TestMatchAny covers picking a provider out of a set of records.
func TestMatchAny(t *testing.T) {
	records := []Record{
		{Type: "NS", Value: "ns1.example.com"},
		{Type: "NS", Value: "kate.ns.cloudflare.com"},
	}
	if got := matchAny(records); got != "Cloudflare" {
		t.Errorf("matchAny() = %q, want Cloudflare", got)
	}
	if got := matchAny([]Record{{Type: "NS", Value: "ns1.example.com"}}); got != "" {
		t.Errorf("matchAny() = %q, want empty for an unrecognised nameserver", got)
	}
	if got := matchAny(nil); got != "" {
		t.Errorf("matchAny(nil) = %q, want empty", got)
	}
}

// TestKnownRecordsAvoidLookups checks that supplying records skips the query.
// A resolver pointed at an unroutable address would fail every lookup, so a
// result at all proves the cached records were used.
func TestKnownRecordsAvoidLookups(t *testing.T) {
	r := &Resolver{Server: "127.0.0.1:1", Timeout: time.Millisecond}

	got := r.records(context.Background(), []Record{{Type: "NS", Value: "kate.ns.cloudflare.com"}},
		"example.com", (*Resolver).NS)
	if len(got) != 1 || got[0].Value != "kate.ns.cloudflare.com" {
		t.Fatalf("records() = %v, want the supplied record", got)
	}

	// A nil slice means "not fetched", so the lookup runs and fails harmlessly.
	if got := r.records(context.Background(), nil, "example.com", (*Resolver).NS); len(got) != 0 {
		t.Errorf("records(nil) = %v, want no records from a dead resolver", got)
	}
}

// TestPickServer covers choosing a nameserver out of a resolv.conf list. The
// link-local skip was case-sensitive, and a non-address entry was returned
// unchecked — either one produced a resolver address that fails every query
// rather than falling through to the next entry.
func TestPickServer(t *testing.T) {
	tests := []struct {
		name    string
		servers []string
		port    string
		want    string
	}{
		{"first usable wins", []string{"1.1.1.1", "8.8.8.8"}, "53", "1.1.1.1:53"},
		{"non-default port kept", []string{"1.1.1.1"}, "5353", "1.1.1.1:5353"},
		{"empty port defaults to 53", []string{"1.1.1.1"}, "", "1.1.1.1:53"},
		{"lower-case link-local skipped", []string{"fe80::1", "1.1.1.1"}, "53", "1.1.1.1:53"},
		{"upper-case link-local skipped", []string{"FE80::1", "1.1.1.1"}, "53", "1.1.1.1:53"},
		{"mixed-case link-local skipped", []string{"Fe80::1", "1.1.1.1"}, "53", "1.1.1.1:53"},
		{"non-address skipped", []string{"not-an-address", "1.1.1.1"}, "53", "1.1.1.1:53"},
		{"routable ipv6 kept", []string{"2606:4700:4700::1111"}, "53", "[2606:4700:4700::1111]:53"},
		{"nothing usable", []string{"fe80::1", "garbage"}, "53", ""},
		{"empty list", nil, "53", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pickServer(tt.servers, tt.port); got != tt.want {
				t.Errorf("pickServer(%v, %q) = %q, want %q", tt.servers, tt.port, got, tt.want)
			}
		})
	}
}
