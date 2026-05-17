package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// flags
var dnsDomain  string
var dnsType    string
var dnsServer  string
var dnsReverse string

// dnsRecord holds a single DNS record result
type dnsRecord struct {
	recordType string
	value      string
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

// ipProviders maps known IP prefixes to provider names
// Only providers that officially publish their IP ranges
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

// getServer returns the DNS server to use — custom or system default
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
			// Skip IPv6 link-local addresses (fe80::) — not supported by miekg/dns
			if strings.HasPrefix(srv, "fe80") {
				continue
			}
			return srv + ":" + config.Port
		}
	}
	return "8.8.8.8:53"
}

// dnsQuery sends a DNS query for the given record type to the specified server
// Falls back to TCP if the UDP response is truncated
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
		return nil, nil
	}
	return r.Answer, nil
}

func lookupA(domain, server string) []dnsRecord {
	var records []dnsRecord
	if rrs, _ := dnsQuery(domain, server, dns.TypeA); rrs != nil {
		for _, rr := range rrs {
			if a, ok := rr.(*dns.A); ok {
				records = append(records, dnsRecord{"A", a.A.String()})
			}
		}
	}
	if rrs, _ := dnsQuery(domain, server, dns.TypeAAAA); rrs != nil {
		for _, rr := range rrs {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				records = append(records, dnsRecord{"AAAA", aaaa.AAAA.String()})
			}
		}
	}
	return records
}

func lookupMX(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeMX)
	var records []dnsRecord
	for _, rr := range rrs {
		if mx, ok := rr.(*dns.MX); ok {
			records = append(records, dnsRecord{
				"MX",
				fmt.Sprintf("%s (priority: %d)", strings.TrimSuffix(mx.Mx, "."), mx.Preference),
			})
		}
	}
	return records
}

func lookupNS(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeNS)
	var records []dnsRecord
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			records = append(records, dnsRecord{"NS", strings.TrimSuffix(ns.Ns, ".")})
		}
	}
	return records
}

func lookupTXT(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeTXT)
	var records []dnsRecord
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, dnsRecord{"TXT", strings.Join(txt.Txt, "")})
		}
	}
	return records
}

func lookupCNAME(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeCNAME)
	var records []dnsRecord
	for _, rr := range rrs {
		if cname, ok := rr.(*dns.CNAME); ok {
			records = append(records, dnsRecord{"CNAME", strings.TrimSuffix(cname.Target, ".")})
		}
	}
	return records
}

func lookupSOA(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeSOA)
	var records []dnsRecord
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			// Convert DNS mbox format (admin.example.com) to email (admin@example.com)
			mbox := strings.TrimSuffix(soa.Mbox, ".")
			parts := strings.SplitN(mbox, ".", 2)
			email := mbox
			if len(parts) == 2 {
				email = parts[0] + "@" + parts[1]
			}
			value := fmt.Sprintf("primary: %s | admin: %s | serial: %d | refresh: %ds",
				strings.TrimSuffix(soa.Ns, "."),
				email,
				soa.Serial,
				soa.Refresh,
			)
			records = append(records, dnsRecord{"SOA", value})
		}
	}
	return records
}

func lookupCAA(domain, server string) []dnsRecord {
	rrs, _ := dnsQuery(domain, server, dns.TypeCAA)
	var records []dnsRecord
	for _, rr := range rrs {
		if caa, ok := rr.(*dns.CAA); ok {
			records = append(records, dnsRecord{
				"CAA",
				fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value),
			})
		}
	}
	return records
}

// lookupEmailSecurity checks SPF, DMARC, and common DKIM selectors
func lookupEmailSecurity(domain, server string) []dnsRecord {
	var records []dnsRecord

	// SPF — lives in TXT records of the root domain
	for _, txt := range lookupTXT(domain, server) {
		if strings.HasPrefix(txt.value, "v=spf1") {
			records = append(records, dnsRecord{"SPF", txt.value})
		}
	}

	// DMARC — TXT record at _dmarc.<domain>
	for _, txt := range lookupTXT("_dmarc."+domain, server) {
		if strings.HasPrefix(txt.value, "v=DMARC1") {
			records = append(records, dnsRecord{"DMARC", txt.value})
		}
	}

	// DKIM — try common selectors
	selectors := []string{"google", "default", "mail", "k1", "s1", "s2", "selector1", "selector2", "dkim", "smtp"}
	for _, sel := range selectors {
		for _, txt := range lookupTXT(sel+"._domainkey."+domain, server) {
			if strings.Contains(txt.value, "v=DKIM1") {
				records = append(records, dnsRecord{"DKIM", fmt.Sprintf("[%s] %s", sel, txt.value)})
			}
		}
	}

	return records
}

// lookupReverse does a reverse DNS lookup (IP → hostname)
func lookupReverse(ip string) []dnsRecord {
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, h := range hostnames {
		records = append(records, dnsRecord{"PTR", strings.TrimSuffix(h, ".")})
	}
	return records
}

func printDNSRecords(records []dnsRecord) {
	for _, r := range records {
		line := fmt.Sprintf("  %-6s  %s", r.recordType, r.value)
		fmt.Println(yellow + line + reset)
	}
}

func printSection(title string, records []dnsRecord) {
	fmt.Printf("[*] %s\n", title)
	if len(records) == 0 {
		fmt.Println("  No records found.")
	} else {
		printDNSRecords(records)
	}
	fmt.Println()
}

// --- Platform detection ---

func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func checkNS(domain, server string) string {
	for _, r := range lookupNS(domain, server) {
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
	for _, r := range lookupCNAME(domain, server) {
		cname := strings.ToLower(r.value)
		for _, p := range knownProviders {
			if strings.Contains(cname, p.keyword) {
				return p.provider
			}
		}
	}
	for _, r := range lookupA(domain, server) {
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
		server := getServer(dnsServer)

		// Reverse DNS mode
		if dnsReverse != "" {
			fmt.Printf("\n%s[*] Reverse DNS for: %s%s\n\n", yellow, dnsReverse, reset)
			records := lookupReverse(dnsReverse)
			if len(records) == 0 {
				fmt.Println("  No PTR records found.")
			} else {
				printDNSRecords(records)
			}
			fmt.Println()
			return
		}

		if dnsDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		fmt.Printf("\n%s[*] DNS lookup for: %s%s\n\n", yellow, dnsDomain, reset)

		recordType := strings.ToUpper(dnsType)

		switch recordType {
		case "A":
			printSection("A / AAAA", lookupA(dnsDomain, server))
		case "MX":
			printSection("MX", lookupMX(dnsDomain, server))
		case "NS":
			printSection("NS", lookupNS(dnsDomain, server))
		case "TXT":
			printSection("TXT", lookupTXT(dnsDomain, server))
		case "CNAME":
			printSection("CNAME", lookupCNAME(dnsDomain, server))
		case "SOA":
			printSection("SOA", lookupSOA(dnsDomain, server))
		case "CAA":
			printSection("CAA", lookupCAA(dnsDomain, server))
		case "EMAIL":
			printSection("Email Security (SPF / DMARC / DKIM)", lookupEmailSecurity(dnsDomain, server))
		default:
			// Show all records
			printSection("A / AAAA", lookupA(dnsDomain, server))
			printSection("MX", lookupMX(dnsDomain, server))
			printSection("NS", lookupNS(dnsDomain, server))
			printSection("TXT", lookupTXT(dnsDomain, server))
			printSection("CNAME", lookupCNAME(dnsDomain, server))
			printSection("SOA", lookupSOA(dnsDomain, server))
			printSection("CAA", lookupCAA(dnsDomain, server))
			printSection("Email Security (SPF / DMARC / DKIM)", lookupEmailSecurity(dnsDomain, server))
		}

		// Platform detection
		platform := detectPlatform(dnsDomain, server)
		if platform == "" {
			platform = "Custom / Unknown"
		}
		fmt.Printf("%s[*] Platform detected: %s%s\n\n", yellow, platform, reset)
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	dnsCmd.Flags().StringVarP(&dnsType, "type", "t", "", "Record type: A, MX, NS, TXT, CNAME, SOA, CAA, EMAIL (default: all)")
	dnsCmd.Flags().StringVarP(&dnsServer, "server", "s", "", "DNS server to use (e.g. 8.8.8.8)")
	dnsCmd.Flags().StringVarP(&dnsReverse, "reverse", "r", "", "Reverse DNS lookup for an IP address")
	rootCmd.AddCommand(dnsCmd)
}
