package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// flags
var whoisDomain string
var whoisRaw    bool

// tldWebRegistries maps TLDs that have no public port-43 WHOIS to their web lookup URLs
var tldWebRegistries = map[string]string{
	"gr": "https://grweb.ics.forth.gr/",
}

// whoisServers maps common TLDs to their WHOIS servers
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

// getTLD extracts the TLD from a domain (e.g. "google.com" → "com")
func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	return parts[len(parts)-1]
}

// queryWhois connects to a WHOIS server and returns the raw response
func queryWhois(query, server string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", query)

	var result strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		result.WriteString(scanner.Text() + "\n")
	}
	return result.String(), nil
}

// getWhoisServer returns the correct WHOIS server for a TLD
// If unknown, queries IANA to find the referral server
func getWhoisServer(tld string) string {
	if server, ok := whoisServers[tld]; ok {
		return server
	}
	// Ask IANA for the correct server
	resp, err := queryWhois(tld, "whois.iana.org")
	if err != nil {
		return "whois.iana.org"
	}
	for _, line := range strings.Split(resp, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "whois.iana.org"
}

// extractField searches WHOIS lines for a value matching any of the given keys
func extractField(lines []string, keys ...string) string {
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, key := range keys {
			prefix := strings.ToLower(key) + ":"
			if strings.HasPrefix(lower, prefix) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val != "" {
						return val
					}
				}
			}
		}
	}
	return "N/A"
}

// extractAll returns all values for a given key (e.g. multiple Name Servers)
func extractAll(lines []string, keys ...string) []string {
	var results []string
	seen := make(map[string]bool)
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, key := range keys {
			prefix := strings.ToLower(key) + ":"
			if strings.HasPrefix(lower, prefix) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val != "" && !seen[val] {
						seen[val] = true
						results = append(results, val)
					}
				}
			}
		}
	}
	return results
}

var whoisCmd = &cobra.Command{
	Use:   "whois",
	Short: "WHOIS domain lookup",
	Long:  `Query WHOIS information for a domain — registrar, dates, nameservers, and status.`,
	Run: func(cmd *cobra.Command, args []string) {
		if whoisDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		header := fmt.Sprintf("\n[*] WHOIS lookup for: %s\n", whoisDomain)
		WriteLineColored(yellow+header+reset, header)

		tld := getTLD(whoisDomain)
		server := getWhoisServer(tld)

		WriteLine(fmt.Sprintf("[*] Querying: %s\n", server))

		raw, err := queryWhois(whoisDomain, server)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] WHOIS query failed: %s\n", err))
			os.Exit(1)
		}

		if strings.TrimSpace(raw) == "" {
			WriteLine("[!] No WHOIS data returned.\n")
			os.Exit(1)
		}

		// Show raw output if requested
		if whoisRaw {
			WriteLine(raw)
			return
		}

		// Check if the domain is not registered
		rawLower := strings.ToLower(raw)
		notFound := []string{"no match for", "not found", "no data found", "no entries found", "object does not exist"}
		for _, phrase := range notFound {
			if strings.Contains(rawLower, phrase) {
				WriteLine(fmt.Sprintf("[!] Domain not registered: %s\n", whoisDomain))
				os.Exit(0)
			}
		}

		// Check if the response is about the queried domain or just the TLD
		if !strings.Contains(strings.ToLower(raw), strings.ToLower(whoisDomain)) {
			WriteLine(fmt.Sprintf("[!] No domain-level WHOIS available for .%s — the registry has no public port-43 server.\n", tld))

			if webURL, ok := tldWebRegistries[tld]; ok {
				plain := fmt.Sprintf("[*] Domain lookup: %s\n", webURL)
				WriteLineColored(yellow+plain+reset, plain)
			}

			// Show the TLD-level registry info that IANA did return
			tldLines := strings.Split(raw, "\n")
			tldFields := []struct {
				label string
				keys  []string
			}{
				{"Organisation", []string{"organisation", "org"}},
				{"Status", []string{"status"}},
				{"Created", []string{"created"}},
				{"Changed", []string{"changed"}},
			}
			WriteLine("[*] TLD Registry Info (from IANA)")
			for _, f := range tldFields {
				val := extractField(tldLines, f.keys...)
				if val != "N/A" {
					plain := fmt.Sprintf("  %-14s  %s", f.label, val)
					WriteLineColored(yellow+plain+reset, plain)
				}
			}
			WriteLine("")

			nservers := extractAll(tldLines, "nserver")
			if len(nservers) > 0 {
				WriteLine("[*] TLD Name Servers")
				for _, ns := range nservers {
					plain := fmt.Sprintf("  %s", strings.ToLower(ns))
					WriteLineColored(yellow+plain+reset, plain)
				}
				WriteLine("")
			}
			return
		}

		lines := strings.Split(raw, "\n")

		// Extract key fields — try multiple common key names across registrars
		fields := []struct {
			label string
			keys  []string
		}{
			{"Registrar", []string{"Registrar", "registrar", "Registrar Name"}},
			{"Registrant", []string{"Registrant Name", "Registrant Organization", "registrant"}},
			{"Created", []string{"Creation Date", "Created Date", "created", "Registration Time", "Domain Registration Date"}},
			{"Updated", []string{"Updated Date", "Last Updated", "last-modified", "Last Modified"}},
			{"Expires", []string{"Registry Expiry Date", "Expiry Date", "Expiration Date", "paid-till", "Domain Expiration Date"}},
			{"Status", []string{"Domain Status", "Status", "state"}},
			{"DNSSEC", []string{"DNSSEC", "dnssec"}},
		}

		WriteLine("[*] Domain Info")
		for _, f := range fields {
			val := extractField(lines, f.keys...)
			// Trim URLs from status fields (ICANN adds URLs after status codes)
			if f.label == "Status" && strings.Contains(val, " ") {
				val = strings.Fields(val)[0]
			}
			plain := fmt.Sprintf("  %-12s  %s", f.label, val)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		// Name servers
		nameServers := extractAll(lines, "Name Server", "nserver", "Nameserver", "nameserver")
		WriteLine("[*] Name Servers")
		if len(nameServers) == 0 {
			WriteLine("  None found.")
		} else {
			for _, ns := range nameServers {
				plain := fmt.Sprintf("  %s", strings.ToLower(ns))
				WriteLineColored(yellow+plain+reset, plain)
			}
		}
		WriteLine("")
	},
}

func init() {
	whoisCmd.Flags().StringVarP(&whoisDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	whoisCmd.Flags().BoolVarP(&whoisRaw, "raw", "r", false, "Show raw WHOIS response")
	rootCmd.AddCommand(whoisCmd)
}
