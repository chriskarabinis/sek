package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// flags
var dnsDomain string
var dnsType   string

// knownProviders maps hostname keywords to provider names (checked against NS/CNAME records)
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
	{"netim", "Netim (GR)"},
}

// ipProviders maps known IP prefixes to provider names
// Only include providers that officially publish their IP ranges
var ipProviders = []struct {
	prefix   string
	provider string
}{
	// Cloudflare — official ranges from cloudflare.com/ips
	{"103.21.244.", "Cloudflare"},
	{"103.22.200.", "Cloudflare"},
	{"103.31.4.", "Cloudflare"},
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

// getRootDomain extracts the root domain from a subdomain (e.g. dash.frenzy.gr → frenzy.gr)
func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// checkNS looks up NS records for the given domain and returns a matching provider name
func checkNS(domain string) string {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return ""
	}
	for _, ns := range nss {
		host := strings.ToLower(ns.Host)
		for _, p := range knownProviders {
			if strings.Contains(host, p.keyword) {
				return p.provider
			}
		}
	}
	return ""
}

// detectPlatform checks NS records, CNAME, and IPs to identify the hosting/CDN provider
func detectPlatform(domain string) string {
	// Check NS on the exact domain
	if p := checkNS(domain); p != "" {
		return p
	}

	// If it's a subdomain, also check NS on the root domain
	root := getRootDomain(domain)
	if root != domain {
		if p := checkNS(root); p != "" {
			return p
		}
	}

	// Check CNAME
	if cname, err := net.LookupCNAME(domain); err == nil {
		cname = strings.ToLower(cname)
		for _, p := range knownProviders {
			if strings.Contains(cname, p.keyword) {
				return p.provider
			}
		}
	}

	// Check IPs against known provider ranges
	if ips, err := net.LookupHost(domain); err == nil {
		for _, ip := range ips {
			for _, p := range ipProviders {
				if strings.HasPrefix(ip, p.prefix) {
					return p.provider
				}
			}
		}
	}

	return ""
}

// dnsRecord holds a single DNS record result
type dnsRecord struct {
	recordType string
	value      string
}

func lookupA(domain string) []dnsRecord {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, ip := range ips {
		// Distinguish IPv4 (A) from IPv6 (AAAA) by checking for ":"
		rtype := "A"
		if strings.Contains(ip, ":") {
			rtype = "AAAA"
		}
		records = append(records, dnsRecord{recordType: rtype, value: ip})
	}
	return records
}

func lookupMX(domain string) []dnsRecord {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, mx := range mxs {
		records = append(records, dnsRecord{
			recordType: "MX",
			value:      fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref),
		})
	}
	return records
}

func lookupNS(domain string) []dnsRecord {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, ns := range nss {
		records = append(records, dnsRecord{recordType: "NS", value: ns.Host})
	}
	return records
}

func lookupTXT(domain string) []dnsRecord {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	var records []dnsRecord
	for _, txt := range txts {
		records = append(records, dnsRecord{recordType: "TXT", value: txt})
	}
	return records
}

func lookupCNAME(domain string) []dnsRecord {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return nil
	}
	// LookupCNAME always returns something (the domain itself if no CNAME exists)
	// so only return if it's actually different from the input
	cname = strings.TrimSuffix(cname, ".")
	if cname == domain {
		return nil
	}
	return []dnsRecord{{recordType: "CNAME", value: cname}}
}

func printRecords(records []dnsRecord) {
	for _, r := range records {
		line := fmt.Sprintf("  %-6s  %s", r.recordType, r.value)
		fmt.Println(yellow + line + reset)
	}
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS record lookup",
	Long:  `Query DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME.`,
	Run: func(cmd *cobra.Command, args []string) {
		if dnsDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		fmt.Printf("\n%s[*] DNS lookup for: %s%s\n\n", yellow, dnsDomain, reset)

		recordType := strings.ToUpper(dnsType)

		// Run the requested lookup(s)
		switch recordType {
		case "A":
			records := lookupA(dnsDomain)
			if len(records) == 0 {
				fmt.Println("  No A/AAAA records found.")
			} else {
				printRecords(records)
			}
		case "MX":
			records := lookupMX(dnsDomain)
			if len(records) == 0 {
				fmt.Println("  No MX records found.")
			} else {
				printRecords(records)
			}
		case "NS":
			records := lookupNS(dnsDomain)
			if len(records) == 0 {
				fmt.Println("  No NS records found.")
			} else {
				printRecords(records)
			}
		case "TXT":
			records := lookupTXT(dnsDomain)
			if len(records) == 0 {
				fmt.Println("  No TXT records found.")
			} else {
				printRecords(records)
			}
		case "CNAME":
			records := lookupCNAME(dnsDomain)
			if len(records) == 0 {
				fmt.Println("  No CNAME records found.")
			} else {
				printRecords(records)
			}
		default:
			// No type specified — show everything
			sections := []struct {
				name    string
				records []dnsRecord
			}{
				{"A / AAAA", lookupA(dnsDomain)},
				{"MX", lookupMX(dnsDomain)},
				{"NS", lookupNS(dnsDomain)},
				{"TXT", lookupTXT(dnsDomain)},
				{"CNAME", lookupCNAME(dnsDomain)},
			}

			for _, section := range sections {
				fmt.Printf("[*] %s\n", section.name)
				if len(section.records) == 0 {
					fmt.Println("  No records found.")
				} else {
					printRecords(section.records)
				}
				fmt.Println()
			}
		}

		// Platform detection
		platform := detectPlatform(dnsDomain)
		if platform == "" {
			platform = "Custom / Unknown"
		}
		fmt.Printf("%s[*] Platform detected: %s%s\n\n", yellow, platform, reset)
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	dnsCmd.Flags().StringVarP(&dnsType, "type", "t", "", "Record type: A, MX, NS, TXT, CNAME (default: all)")
	rootCmd.AddCommand(dnsCmd)
}
