package whoisx

import (
	"strings"
	"testing"
)

func TestTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "com"},
		{"www.example.com", "com"},
		{"example.co.uk", "co.uk"},
		{"shop.example.co.uk", "co.uk"},
		{"example.gr", "gr"},
		{"example.com.gr", "com.gr"},
		{"EXAMPLE.COM", "com"},
		{"example.com.", "com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := TLD(tt.domain); got != tt.want {
				t.Errorf("TLD(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// TestMatchKeyIsExact is the regression test for prefix matching. Looking up
// "Registrar" also matched "Registrar URL" and "Registrar WHOIS Server", so the
// reported registrar could be whichever of those lines appeared first.
func TestMatchKeyIsExact(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		key       string
		wantValue string
		wantOK    bool
	}{
		{"exact", "Registrar: MarkMonitor Inc.", "Registrar", "MarkMonitor Inc.", true},
		{"case insensitive", "registrar: Example", "Registrar", "Example", true},
		{"leading space", "   Registrar: Example", "Registrar", "Example", true},
		{"longer key must not match", "Registrar URL: http://example.com", "Registrar", "", false},
		{"whois server must not match", "Registrar WHOIS Server: whois.example.com", "Registrar", "", false},
		{"no colon", "Registrar MarkMonitor", "Registrar", "", false},
		{"value keeps inner colons", "Registrar URL: https://a.example", "Registrar URL", "https://a.example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := matchKey(tt.line, tt.key)
			if ok != tt.wantOK || val != tt.wantValue {
				t.Errorf("matchKey(%q, %q) = (%q, %v), want (%q, %v)",
					tt.line, tt.key, val, ok, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestFieldPicksTheRightLine(t *testing.T) {
	lines := strings.Split(`Domain Name: EXAMPLE.COM
Registrar WHOIS Server: whois.example-registrar.com
Registrar URL: http://www.example-registrar.com
Registrar: Example Registrar, Inc.
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-14T04:00:00Z`, "\n")

	tests := []struct {
		name string
		keys []string
		want string
	}{
		{"registrar not the URL", []string{"Registrar"}, "Example Registrar, Inc."},
		{"whois server", []string{"Registrar WHOIS Server"}, "whois.example-registrar.com"},
		{"creation date", []string{"Creation Date"}, "1997-09-15T04:00:00Z"},
		{"expiry via alternate key", []string{"Registry Expiry Date", "Expiry Date"}, "2028-09-14T04:00:00Z"},
		{"absent key", []string{"Nonexistent"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := field(lines, tt.keys...); got != tt.want {
				t.Errorf("field(%v) = %q, want %q", tt.keys, got, tt.want)
			}
		})
	}
}

func TestAllFieldsDeduplicates(t *testing.T) {
	lines := strings.Split(`Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Name Server: NS1.EXAMPLE.COM`, "\n")

	got := allFields(lines, "Name Server")
	want := []string{"NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"}

	if len(got) != len(want) {
		t.Fatalf("allFields() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allFields()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseExtractsDomainInfo(t *testing.T) {
	raw := `Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Registrar URL: http://www.example-registrar.com
Creation Date: 1997-09-15T04:00:00Z
Updated Date: 2024-08-14T07:01:31Z
Registry Expiry Date: 2028-09-14T04:00:00Z
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: signedDelegation`

	var res Result
	parse(&res, raw)

	if res.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", res.Registrar)
	}
	if res.Created != "1997-09-15T04:00:00Z" {
		t.Errorf("Created = %q", res.Created)
	}
	if res.Expires != "2028-09-14T04:00:00Z" {
		t.Errorf("Expires = %q", res.Expires)
	}
	// The explanatory URL ICANN appends must be dropped.
	if res.Status != "clientDeleteProhibited" {
		t.Errorf("Status = %q, want the bare status code", res.Status)
	}
	if res.DNSSEC != "signedDelegation" {
		t.Errorf("DNSSEC = %q", res.DNSSEC)
	}
	if len(res.NameServers) != 2 || res.NameServers[0] != "ns1.example.com" {
		t.Errorf("NameServers = %v, want two lowercased entries", res.NameServers)
	}
}

// TestMergeFillsGapsOnly covers the referral follow-up: values already recovered
// from the registry must survive, and only blanks get filled from the registrar.
func TestMergeFillsGapsOnly(t *testing.T) {
	res := &Result{
		Registrar: "Registry-reported Registrar",
		Created:   "1997-09-15T04:00:00Z",
	}

	merge(res, `Registrar: Registrar-reported Name
Registrant Name: Example Org
Creation Date: 2020-01-01T00:00:00Z
Name Server: NS1.EXAMPLE.COM`)

	if res.Registrar != "Registry-reported Registrar" {
		t.Errorf("Registrar = %q, an existing value must not be overwritten", res.Registrar)
	}
	if res.Created != "1997-09-15T04:00:00Z" {
		t.Errorf("Created = %q, an existing value must not be overwritten", res.Created)
	}
	if res.Registrant != "Example Org" {
		t.Errorf("Registrant = %q, an empty field should be filled", res.Registrant)
	}
	if len(res.NameServers) != 1 {
		t.Errorf("NameServers = %v, want the referral's entry", res.NameServers)
	}
}

// TestRegistryKey covers reducing a public suffix to the registry that serves
// it. Cutting at the first dot rather than the last left "edu.au" for
// "act.edu.au", which matches no registry at all.
func TestRegistryKey(t *testing.T) {
	tests := []struct {
		tld  string
		want string
	}{
		{"com", "com"},
		{"co.uk", "uk"},
		{"act.edu.au", "au"},
		{"nsw.gov.au", "au"},
		{"com.gr", "gr"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := registryKey(tt.tld); got != tt.want {
				t.Errorf("registryKey(%q) = %q, want %q", tt.tld, got, tt.want)
			}
		})
	}
}

// TestRegistryKeyResolvesToKnownServer ties the key back to the table: the
// three-label Australian suffixes must reach the .au registry.
func TestRegistryKeyResolvesToKnownServer(t *testing.T) {
	for _, tld := range []string{"au", "com.au", "act.edu.au"} {
		if server := whoisServers[registryKey(tld)]; server != "whois.auda.org.au" {
			t.Errorf("%s resolved to %q, want whois.auda.org.au", tld, server)
		}
	}
}
