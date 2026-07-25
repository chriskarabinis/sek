package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/dnsx"
	"github.com/chriskarabinis/sek/internal/output"
)

var (
	dnsDomain  string
	dnsType    string
	dnsServer  string
	dnsReverse string
)

// dnsLookups maps a -t value to its section title and lookup.
var dnsLookups = []struct {
	key    string
	title  string
	lookup func(*dnsx.Resolver, string) ([]dnsx.Record, error)
}{
	{"A", "A / AAAA", (*dnsx.Resolver).A},
	{"MX", "MX", (*dnsx.Resolver).MX},
	{"NS", "NS", (*dnsx.Resolver).NS},
	{"TXT", "TXT", (*dnsx.Resolver).TXT},
	{"CNAME", "CNAME", (*dnsx.Resolver).CNAME},
	{"SOA", "SOA", (*dnsx.Resolver).SOA},
	{"CAA", "CAA", (*dnsx.Resolver).CAA},
	{"EMAIL", "Email Security (SPF / DMARC / DKIM)", (*dnsx.Resolver).EmailSecurity},
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS record lookup",
	Long:  `Query DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and email security (SPF, DMARC, DKIM).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		resolver := dnsx.NewResolver(dnsServer)

		if dnsReverse != "" {
			return runReverseDNS(w, dnsReverse)
		}
		if dnsDomain == "" {
			return fmt.Errorf("domain is required, use -d <domain>")
		}

		res := &dnsx.Result{Domain: dnsDomain, Server: resolver.Server}
		wanted := strings.ToUpper(strings.TrimSpace(dnsType))
		all := wanted == ""

		for _, l := range dnsLookups {
			if !all && l.key != wanted {
				continue
			}
			records, err := l.lookup(resolver, dnsDomain)
			section := dnsx.Section{Title: l.title, Records: records}
			if err != nil {
				section.Error = err.Error()
			}
			res.Sections = append(res.Sections, section)
		}

		if !all && len(res.Sections) == 0 {
			return fmt.Errorf("unknown record type %q", dnsType)
		}

		if all {
			res.Wildcard = resolver.Wildcard(dnsDomain)
		}
		res.Platform = resolver.DetectPlatform(dnsDomain)

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderDNS(w, res, all)
		return nil
	},
}

func runReverseDNS(w *output.Writer, ip string) error {
	records, err := dnsx.Reverse(ip)
	if err != nil && len(records) == 0 {
		if w.IsJSON() {
			return w.JSON(&dnsx.Result{
				Domain:   ip,
				Sections: []dnsx.Section{{Title: "PTR", Error: err.Error()}},
			})
		}
		w.Header("Reverse DNS for: %s", ip)
		w.Note("No PTR records found.")
		w.Blank()
		return nil
	}

	res := &dnsx.Result{Domain: ip, Sections: []dnsx.Section{{Title: "PTR", Records: records}}}
	if w.IsJSON() {
		return w.JSON(res)
	}

	w.Header("Reverse DNS for: %s", ip)
	renderRecords(w, records)
	w.Blank()
	return nil
}

func renderDNS(w *output.Writer, res *dnsx.Result, all bool) {
	w.Header("DNS lookup for: %s", res.Domain)

	for _, section := range res.Sections {
		w.Section("%s", section.Title)
		switch {
		case section.Error != "":
			w.Note("Query failed: %s", section.Error)
		case len(section.Records) == 0:
			w.Note("No records found.")
		default:
			renderRecords(w, section.Records)
		}
		w.Blank()
	}

	if all {
		w.Section("Wildcard DNS")
		if res.Wildcard != "" {
			w.Highlightf("  *.%s  ->  %s  (wildcard detected)", res.Domain, res.Wildcard)
		} else {
			w.Note("No wildcard DNS detected.")
		}
		w.Blank()
	}

	platform := res.Platform
	if platform == "" {
		platform = "Custom / Unknown"
	}
	w.Highlightf("[*] Platform detected: %s", platform)
	w.Blank()
}

func renderRecords(w *output.Writer, records []dnsx.Record) {
	for _, r := range records {
		ttl := ""
		if r.TTL > 0 {
			ttl = fmt.Sprintf("  TTL: %ds", r.TTL)
		}
		w.Highlightf("  %-6s  %-50s%s", r.Type, r.Value, ttl)
	}
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	dnsCmd.Flags().StringVarP(&dnsType, "type", "t", "", "Record type: A, MX, NS, TXT, CNAME, SOA, CAA, EMAIL (default: all)")
	dnsCmd.Flags().StringVarP(&dnsServer, "server", "s", "", "DNS server to use (e.g. 8.8.8.8)")
	dnsCmd.Flags().StringVarP(&dnsReverse, "reverse", "r", "", "Reverse DNS lookup for an IP address")
	rootCmd.AddCommand(dnsCmd)
}
