package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"golang.org/x/net/publicsuffix"
)

// rcodeError reports a DNS response code other than NOERROR, so callers can
// tell "this name does not exist" apart from "this name has no such records".
type rcodeError struct{ rcode int }

func (e *rcodeError) Error() string {
	if s, ok := dns.RcodeToString[e.rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE %d", e.rcode)
}

// isNameError reports whether err is NXDOMAIN. Probe lookups (DKIM selectors,
// wildcard tests) expect it and treat it as a plain negative, not a failure.
func isNameError(err error) bool {
	var re *rcodeError
	return errors.As(err, &re) && re.rcode == dns.RcodeNameError
}

// flags
var dnsDomain string
var dnsType string
var dnsServer string
var dnsReverse string

// dnsRecord holds a single DNS record with its TTL
type dnsRecord struct {
	recordType string
	value      string
	ttl        uint32
}

// knownProviders maps hostname keywords to provider names
var knownProviders = []struct {
	keyword  string
	provider string
}{
	// Global CDN / Security
	{"cloudflare", "Cloudflare"},
	{"awsdns", "Amazon Route 53 (AWS)"},
	{"cloudfront.net", "Amazon CloudFront (AWS)"},
	{"azure-dns", "Azure DNS (Microsoft)"},
	{"googledomains", "Google Cloud DNS"},
	{"google", "Google Cloud DNS"},
	{"sucuri", "Sucuri WAF"},
	{"incapsula", "Imperva Incapsula"},
	{"akamai", "Akamai"},
	{"fastly", "Fastly CDN"},
	{"stackpath", "StackPath CDN"},
	{"cdn77", "CDN77"},
	{"ovh", "OVH"},
	{"hetzner", "Hetzner"},
	{"digitalocean", "DigitalOcean"},
	// Greek / Cyprus providers
	{"fastpath", "Fastpath (GR)"},
	{"papaki", "Papaki (GR)"},
	{"tophost", "Top.Host (GR)"},
	{"top.host", "Top.Host (GR)"},
	{"forthnet", "Forthnet (GR)"},
	{"otenet", "OTEnet / Cosmote (GR)"},
	{"cosmote", "Cosmote (GR)"},
	{"hol.gr", "Hol (GR)"},
	{"wind.gr", "Wind Hellas (GR)"},
	{"cyta", "Cyta (CY)"},
	{"cytanet", "Cyta (CY)"},
	{"hosting.gr", "Hosting.gr (GR)"},
}

// ipProviders maps known IP prefixes to provider names (verified/official ranges only)
var ipProviders = []struct {
	prefix   string
	provider string
}{
	// Cloudflare — official ranges from cloudflare.com/ips
	{"103.21.244.", "Cloudflare"}, {"103.22.200.", "Cloudflare"}, {"103.31.4.", "Cloudflare"},
	{"104.16.", "Cloudflare"}, {"104.17.", "Cloudflare"}, {"104.18.", "Cloudflare"},
	{"104.19.", "Cloudflare"}, {"104.20.", "Cloudflare"}, {"104.21.", "Cloudflare"},
	{"104.24.", "Cloudflare"}, {"104.25.", "Cloudflare"}, {"104.26.", "Cloudflare"},
	{"108.162.", "Cloudflare"}, {"141.101.", "Cloudflare"},
	{"162.158.", "Cloudflare"}, {"162.159.", "Cloudflare"},
	{"172.64.", "Cloudflare"}, {"172.65.", "Cloudflare"},
	{"172.66.", "Cloudflare"}, {"172.67.", "Cloudflare"},
	{"173.245.", "Cloudflare"}, {"188.114.", "Cloudflare"},
	{"190.93.", "Cloudflare"}, {"197.234.", "Cloudflare"}, {"198.41.", "Cloudflare"},
}

// getServer returns the DNS server to use
func getServer(custom string) string {
	if custom != "" {
		if !strings.Contains(custom, ":") {
			return custom + ":53"
		}
		return custom
	}
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		for _, srv := range config.Servers {
			// Skip IPv6 link-local addresses (fe80::) — not handled by miekg/dns
			if strings.HasPrefix(srv, "fe80") {
				continue
			}
			return srv + ":" + config.Port
		}
	}
	return "8.8.8.8:53"
}

// dnsQuery sends a DNS query, retrying with TCP if the UDP response is truncated
func dnsQuery(domain, server string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	// Large responses get truncated over UDP — retry with TCP
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.Exchange(m, server)
		if err != nil {
			return nil, err
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, &rcodeError{rcode: r.Rcode}
	}
	return r.Answer, nil
}

// lookupTyped runs one query and maps each answer through fn, which reports
// false for records of a type it does not handle.
func lookupTyped(domain, server string, qtype uint16, fn func(dns.RR) (dnsRecord, bool)) ([]dnsRecord, error) {
	rrs, err := dnsQuery(domain, server, qtype)
	if err != nil {
		return nil, err
	}
	var records []dnsRecord
	for _, rr := range rrs {
		if rec, ok := fn(rr); ok {
			records = append(records, rec)
		}
	}
	return records, nil
}

func lookupA(domain, server string) ([]dnsRecord, error) {
	v4, errA := lookupTyped(domain, server, dns.TypeA, func(rr dns.RR) (dnsRecord, bool) {
		a, ok := rr.(*dns.A)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{"A", a.A.String(), a.Hdr.Ttl}, true
	})
	v6, errAAAA := lookupTyped(domain, server, dns.TypeAAAA, func(rr dns.RR) (dnsRecord, bool) {
		aaaa, ok := rr.(*dns.AAAA)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{"AAAA", aaaa.AAAA.String(), aaaa.Hdr.Ttl}, true
	})

	records := append(v4, v6...)
	// A host with only one address family is normal, so report a failure
	// only when neither query produced anything.
	if len(records) == 0 {
		if errA != nil {
			return nil, errA
		}
		if errAAAA != nil {
			return nil, errAAAA
		}
	}
	return records, nil
}

func lookupMX(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeMX, func(rr dns.RR) (dnsRecord, bool) {
		mx, ok := rr.(*dns.MX)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{
			"MX",
			fmt.Sprintf("%s (priority: %d)", strings.TrimSuffix(mx.Mx, "."), mx.Preference),
			mx.Hdr.Ttl,
		}, true
	})
}

func lookupNS(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeNS, func(rr dns.RR) (dnsRecord, bool) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{"NS", strings.TrimSuffix(ns.Ns, "."), ns.Hdr.Ttl}, true
	})
}

func lookupTXT(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeTXT, func(rr dns.RR) (dnsRecord, bool) {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{"TXT", strings.Join(txt.Txt, ""), txt.Hdr.Ttl}, true
	})
}

func lookupCNAME(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeCNAME, func(rr dns.RR) (dnsRecord, bool) {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{"CNAME", strings.TrimSuffix(cname.Target, "."), cname.Hdr.Ttl}, true
	})
}

func lookupSOA(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeSOA, func(rr dns.RR) (dnsRecord, bool) {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			return dnsRecord{}, false
		}
		mbox := strings.TrimSuffix(soa.Mbox, ".")
		parts := strings.SplitN(mbox, ".", 2)
		email := mbox
		if len(parts) == 2 {
			email = parts[0] + "@" + parts[1]
		}
		value := fmt.Sprintf("primary: %s | admin: %s | serial: %d | refresh: %ds",
			strings.TrimSuffix(soa.Ns, "."), email, soa.Serial, soa.Refresh)
		return dnsRecord{"SOA", value, soa.Hdr.Ttl}, true
	})
}

func lookupCAA(domain, server string) ([]dnsRecord, error) {
	return lookupTyped(domain, server, dns.TypeCAA, func(rr dns.RR) (dnsRecord, bool) {
		caa, ok := rr.(*dns.CAA)
		if !ok {
			return dnsRecord{}, false
		}
		return dnsRecord{
			"CAA",
			fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value),
			caa.Hdr.Ttl,
		}, true
	})
}

// lookupEmailSecurity checks SPF, DMARC, and common DKIM selectors. It always
// reports success: every lookup here is a probe whose absence is a valid answer.
func lookupEmailSecurity(domain, server string) ([]dnsRecord, error) {
	var records []dnsRecord

	spf, _ := lookupTXT(domain, server)
	for _, txt := range spf {
		if strings.HasPrefix(txt.value, "v=spf1") {
			records = append(records, dnsRecord{"SPF", txt.value, txt.ttl})
		}
	}

	dmarc, _ := lookupTXT("_dmarc."+domain, server)
	for _, txt := range dmarc {
		if strings.HasPrefix(txt.value, "v=DMARC1") {
			records = append(records, dnsRecord{"DMARC", txt.value, txt.ttl})
		}
	}

	// Selectors are guessed, so NXDOMAIN is the common case and errors are
	// deliberately ignored here — a miss just means "no key at that name".
	selectors := []string{"google", "default", "mail", "k1", "s1", "s2", "selector1", "selector2", "dkim", "smtp"}
	for _, sel := range selectors {
		keys, _ := lookupTXT(sel+"._domainkey."+domain, server)
		for _, txt := range keys {
			if strings.Contains(txt.value, "v=DKIM1") {
				records = append(records, dnsRecord{"DKIM", fmt.Sprintf("[%s] %s", sel, txt.value), txt.ttl})
			}
		}
	}

	return records, nil
}

// lookupReverse does a reverse DNS lookup (IP → hostname)
func lookupReverse(ip string) []dnsRecord {
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, h := range hostnames {
		records = append(records, dnsRecord{"PTR", strings.TrimSuffix(h, "."), 0})
	}
	return records
}

// detectWildcard checks if the domain has a wildcard DNS record. NXDOMAIN is
// the expected answer when there is none, so errors are not surfaced.
func detectWildcard(domain, server string) string {
	rrs, err := dnsQuery(randomLabel()+"."+domain, server, dns.TypeA)
	if err != nil {
		return ""
	}
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func printDNSRecords(records []dnsRecord) {
	for _, r := range records {
		ttlStr := ""
		if r.ttl > 0 {
			ttlStr = fmt.Sprintf("  TTL: %ds", r.ttl)
		}
		plain := fmt.Sprintf("  %-6s  %-50s%s", r.recordType, r.value, ttlStr)
		WriteLineColored(yellow+plain+reset, plain)
	}
}

// printSection renders one record type. A failed query is reported as such
// rather than as "no records" — NXDOMAIN, SERVFAIL and an unreachable resolver
// used to be indistinguishable from a domain that simply has no such records.
func printSection(title string, records []dnsRecord, err error) {
	WriteLine(fmt.Sprintf("[*] %s", title))
	switch {
	case err != nil:
		WriteLine(fmt.Sprintf("  Query failed: %s", err))
	case len(records) == 0:
		WriteLine("  No records found.")
	default:
		printDNSRecords(records)
	}
	WriteLine("")
}

// --- Platform detection ---

// getRootDomain returns the registrable domain, using the Public Suffix List
// so multi-label suffixes resolve correctly: shop.example.co.uk yields
// example.co.uk, not co.uk. Also covers .com.gr, .edu.gr and friends.
func getRootDomain(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return root
}

func checkNS(domain, server string) string {
	ns, _ := lookupNS(domain, server)
	for _, r := range ns {
		host := strings.ToLower(r.value)
		for _, p := range knownProviders {
			if strings.Contains(host, p.keyword) {
				return p.provider
			}
		}
	}
	return ""
}

func detectPlatform(domain, server string) string {
	if p := checkNS(domain, server); p != "" {
		return p
	}
	root := getRootDomain(domain)
	if root != domain {
		if p := checkNS(root, server); p != "" {
			return p
		}
	}
	cnames, _ := lookupCNAME(domain, server)
	for _, r := range cnames {
		cname := strings.ToLower(r.value)
		for _, p := range knownProviders {
			if strings.Contains(cname, p.keyword) {
				return p.provider
			}
		}
	}
	addrs, _ := lookupA(domain, server)
	for _, r := range addrs {
		for _, p := range ipProviders {
			if strings.HasPrefix(r.value, p.prefix) {
				return p.provider
			}
		}
	}
	return ""
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS record lookup",
	Long:  `Query DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and email security (SPF, DMARC, DKIM).`,
	Run: func(cmd *cobra.Command, args []string) {
		InitOutput()
		defer CloseOutput()

		server := getServer(dnsServer)

		// Reverse DNS mode
		if dnsReverse != "" {
			plain := fmt.Sprintf("\n[*] Reverse DNS for: %s\n", dnsReverse)
			WriteLineColored(yellow+plain+reset, plain)
			records := lookupReverse(dnsReverse)
			if len(records) == 0 {
				WriteLine("  No PTR records found.")
			} else {
				printDNSRecords(records)
			}
			WriteLine("")
			return
		}

		if dnsDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		header := fmt.Sprintf("\n[*] DNS lookup for: %s\n", dnsDomain)
		WriteLineColored(yellow+header+reset, header)

		recordType := strings.ToUpper(dnsType)

		section := func(title string, lookup func(domain, server string) ([]dnsRecord, error)) {
			records, err := lookup(dnsDomain, server)
			printSection(title, records, err)
		}
		const emailTitle = "Email Security (SPF / DMARC / DKIM)"

		switch recordType {
		case "A":
			section("A / AAAA", lookupA)
		case "MX":
			section("MX", lookupMX)
		case "NS":
			section("NS", lookupNS)
		case "TXT":
			section("TXT", lookupTXT)
		case "CNAME":
			section("CNAME", lookupCNAME)
		case "SOA":
			section("SOA", lookupSOA)
		case "CAA":
			section("CAA", lookupCAA)
		case "EMAIL":
			section(emailTitle, lookupEmailSecurity)
		default:
			section("A / AAAA", lookupA)
			section("MX", lookupMX)
			section("NS", lookupNS)
			section("TXT", lookupTXT)
			section("CNAME", lookupCNAME)
			section("SOA", lookupSOA)
			section("CAA", lookupCAA)
			section(emailTitle, lookupEmailSecurity)

			// Wildcard detection
			WriteLine("[*] Wildcard DNS")
			if ip := detectWildcard(dnsDomain, server); ip != "" {
				plain := fmt.Sprintf("  *.%s  ->  %s  (wildcard detected)", dnsDomain, ip)
				WriteLineColored(yellow+plain+reset, plain)
			} else {
				WriteLine("  No wildcard DNS detected.")
			}
			WriteLine("")
		}

		// Platform detection
		platform := detectPlatform(dnsDomain, server)
		if platform == "" {
			platform = "Custom / Unknown"
		}
		plain := fmt.Sprintf("[*] Platform detected: %s\n", platform)
		WriteLineColored(yellow+plain+reset, plain)
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	dnsCmd.Flags().StringVarP(&dnsType, "type", "t", "", "Record type: A, MX, NS, TXT, CNAME, SOA, CAA, EMAIL (default: all)")
	dnsCmd.Flags().StringVarP(&dnsServer, "server", "s", "", "DNS server to use (e.g. 8.8.8.8)")
	dnsCmd.Flags().StringVarP(&dnsReverse, "reverse", "r", "", "Reverse DNS lookup for an IP address")
	rootCmd.AddCommand(dnsCmd)
}
