// Package whoisx queries WHOIS servers over port 43 and extracts the fields
// worth showing from their free-form output.
package whoisx

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Result is a parsed WHOIS response.
type Result struct {
	Domain      string   `json:"domain"`
	Server      string   `json:"server"`
	Registrar   string   `json:"registrar,omitempty"`
	Registrant  string   `json:"registrant,omitempty"`
	Created     string   `json:"created,omitempty"`
	Updated     string   `json:"updated,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Status      string   `json:"status,omitempty"`
	DNSSEC      string   `json:"dnssec,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
	Raw         string   `json:"raw,omitempty"`

	// Registered is false when the registry reports no such domain.
	Registered bool `json:"registered"`
	// DomainLevel is false when only registry-level (TLD) data came back,
	// which happens for TLDs with no public port-43 service.
	DomainLevel bool `json:"domain_level"`
	// WebLookup points at a browser-based service when there is no port-43 one.
	WebLookup string `json:"web_lookup,omitempty"`

	// TLD holds registry-level fields, used when DomainLevel is false.
	TLD *TLDInfo `json:"tld,omitempty"`
}

// TLDInfo is the registry-level data IANA returns for a TLD.
type TLDInfo struct {
	Name         string   `json:"name"`
	Organisation string   `json:"organisation,omitempty"`
	Status       string   `json:"status,omitempty"`
	Created      string   `json:"created,omitempty"`
	Changed      string   `json:"changed,omitempty"`
	NameServers  []string `json:"name_servers,omitempty"`
}

// tldWebRegistries maps TLDs with no public port-43 WHOIS to their web lookup.
var tldWebRegistries = map[string]string{
	"gr": "https://grweb.ics.forth.gr/",
}

// whoisServers maps common TLDs to their WHOIS servers, avoiding an IANA
// round-trip for the ones that come up most.
var whoisServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"de":   "whois.denic.de",
	"uk":   "whois.nic.uk",
	"fr":   "whois.nic.fr",
	"eu":   "whois.eu",
	"nl":   "whois.domain-registry.nl",
	"info": "whois.afilias.net",
	"biz":  "whois.biz",
	"app":  "whois.nic.google",
	"dev":  "whois.nic.google",
	"ai":   "whois.nic.ai",
	"me":   "whois.nic.me",
	"us":   "whois.nic.us",
	"ca":   "whois.cira.ca",
	"au":   "whois.auda.org.au",
}

// notFoundPhrases are how registries say a domain is unregistered.
var notFoundPhrases = []string{
	"no match for", "not found", "no data found",
	"no entries found", "object does not exist", "status: free",
}

// TLD returns the public suffix of a domain, so example.co.uk yields "co.uk"
// rather than "uk".
func TLD(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	suffix, _ := publicsuffix.PublicSuffix(d)
	return suffix
}

// Query sends a request to a WHOIS server and returns the raw response.
func Query(ctx context.Context, query, server string) (string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(20 * time.Second))
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}

	var out strings.Builder
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		out.WriteString(scanner.Text())
		out.WriteString("\n")
	}
	return out.String(), scanner.Err()
}

// registryKey reduces a public suffix to the registry that serves it, which is
// its last label.
//
// Cutting at the first dot instead turned "act.edu.au" into "edu.au", a string
// that is in neither the built-in table nor IANA's registry, so every
// three-label suffix fell through to whois.iana.org and came back useless.
func registryKey(tld string) string {
	if i := strings.LastIndex(tld, "."); i >= 0 {
		return tld[i+1:]
	}
	return tld
}

// ServerFor returns the WHOIS server for a TLD, asking IANA when it is not in
// the built-in table.
func ServerFor(ctx context.Context, tld string) string {
	key := registryKey(tld)
	if server, ok := whoisServers[key]; ok {
		return server
	}

	resp, err := Query(ctx, key, "whois.iana.org")
	if err != nil {
		return "whois.iana.org"
	}
	if refer := field(strings.Split(resp, "\n"), "refer"); refer != "" {
		return refer
	}
	return "whois.iana.org"
}

// Lookup queries the registry for a domain and parses the response. For thin
// registries such as .com, the registry only points at the registrar, so the
// registrar's own server is queried as well to recover the detail fields.
func Lookup(ctx context.Context, domain string) (*Result, error) {
	tld := TLD(domain)
	server := ServerFor(ctx, tld)

	raw, err := Query(ctx, domain, server)
	if err != nil {
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("no WHOIS data returned")
	}

	res := &Result{Domain: domain, Server: server, Raw: raw, Registered: true, DomainLevel: true}

	lower := strings.ToLower(raw)
	for _, phrase := range notFoundPhrases {
		if strings.Contains(lower, phrase) {
			res.Registered = false
			return res, nil
		}
	}

	// A response that never mentions the domain is registry-level data about
	// the TLD, not an answer about this name.
	if !strings.Contains(lower, strings.ToLower(domain)) {
		res.DomainLevel = false
		res.WebLookup = tldWebRegistries[tld]
		res.TLD = parseTLD(tld, raw)
		return res, nil
	}

	parse(res, raw)

	// Thin registries answer with a referral rather than the registrant
	// details; follow it so the fields are not reported as missing.
	if referral := field(strings.Split(raw, "\n"), "Registrar WHOIS Server"); referral != "" && referral != server {
		if extra, err := Query(ctx, domain, referral); err == nil && strings.TrimSpace(extra) != "" {
			merge(res, extra)
			res.Raw = raw + "\n" + extra
		}
	}
	return res, nil
}

func parse(res *Result, raw string) {
	lines := strings.Split(raw, "\n")

	res.Registrar = field(lines, "Registrar", "Registrar Name", "Sponsoring Registrar")
	res.Registrant = field(lines, "Registrant Name", "Registrant Organization", "registrant")
	res.Created = field(lines, "Creation Date", "Created Date", "created", "Registration Time", "Domain Registration Date")
	res.Updated = field(lines, "Updated Date", "Last Updated", "last-modified", "Last Modified")
	res.Expires = field(lines, "Registry Expiry Date", "Expiry Date", "Expiration Date", "paid-till", "Domain Expiration Date")
	res.DNSSEC = field(lines, "DNSSEC", "dnssec")

	// ICANN appends an explanatory URL after the status code; keep the code.
	if status := field(lines, "Domain Status", "Status", "state"); status != "" {
		res.Status = strings.Fields(status)[0]
	}

	res.NameServers = lowerAll(allFields(lines, "Name Server", "nserver", "Nameserver", "nameserver"))
}

// merge fills in fields the registry response left empty.
func merge(res *Result, raw string) {
	var extra Result
	parse(&extra, raw)

	for _, f := range []struct {
		dst *string
		src string
	}{
		{&res.Registrar, extra.Registrar},
		{&res.Registrant, extra.Registrant},
		{&res.Created, extra.Created},
		{&res.Updated, extra.Updated},
		{&res.Expires, extra.Expires},
		{&res.Status, extra.Status},
		{&res.DNSSEC, extra.DNSSEC},
	} {
		if *f.dst == "" {
			*f.dst = f.src
		}
	}
	if len(res.NameServers) == 0 {
		res.NameServers = extra.NameServers
	}
}

func parseTLD(tld, raw string) *TLDInfo {
	lines := strings.Split(raw, "\n")
	return &TLDInfo{
		Name:         tld,
		Organisation: field(lines, "organisation", "org"),
		Status:       field(lines, "status"),
		Created:      field(lines, "created"),
		Changed:      field(lines, "changed"),
		NameServers:  lowerAll(allFields(lines, "nserver")),
	}
}

// field returns the first non-empty value for any of the given keys.
func field(lines []string, keys ...string) string {
	for _, line := range lines {
		for _, key := range keys {
			if val, ok := matchKey(line, key); ok && val != "" {
				return val
			}
		}
	}
	return ""
}

// allFields returns every distinct value for the given keys, in order.
func allFields(lines []string, keys ...string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, line := range lines {
		for _, key := range keys {
			val, ok := matchKey(line, key)
			if !ok || val == "" || seen[val] {
				continue
			}
			seen[val] = true
			out = append(out, val)
		}
	}
	return out
}

// matchKey splits a "Key: value" line when the key matches, case-insensitively.
func matchKey(line, key string) (string, bool) {
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(name), key) {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}
