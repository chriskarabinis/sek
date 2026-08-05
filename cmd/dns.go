package cmd

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

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

// dnsLookups maps a -t value to its section title and lookup. Aliases are the
// other spellings that select the same section: the A lookup answers for both
// families, and -t AAAA is what someone after the v6 addresses will reach for —
// it was rejected as an unknown record type even though the command's own help
// listed it as supported.
var dnsLookups = []struct {
	key     string
	aliases []string
	title   string
	lookup  dnsx.Lookup
}{
	{key: "A", aliases: []string{"AAAA"}, title: "A / AAAA", lookup: (*dnsx.Resolver).A},
	{key: "MX", title: "MX", lookup: (*dnsx.Resolver).MX},
	{key: "NS", title: "NS", lookup: (*dnsx.Resolver).NS},
	{key: "TXT", title: "TXT", lookup: (*dnsx.Resolver).TXT},
	{key: "CNAME", title: "CNAME", lookup: (*dnsx.Resolver).CNAME},
	{key: "SOA", title: "SOA", lookup: (*dnsx.Resolver).SOA},
	{key: "CAA", title: "CAA", lookup: (*dnsx.Resolver).CAA},
	{key: "EMAIL", title: "Email Security (SPF / DMARC / DKIM)", lookup: (*dnsx.Resolver).EmailSecurity},
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

		ctx, stop := commandContext()
		defer stop()

		resolver := dnsx.NewResolver(dnsServer)

		if dnsReverse != "" {
			return runReverseDNS(ctx, w, resolver, dnsReverse)
		}
		if dnsDomain == "" {
			return fmt.Errorf("domain is required, use -d <domain>")
		}

		res := &dnsx.Result{Domain: dnsDomain, Server: resolver.Server}
		wanted := strings.ToUpper(strings.TrimSpace(dnsType))
		all := wanted == ""

		selected := selectLookups(wanted)
		if len(selected) == 0 {
			return fmt.Errorf("unknown record type %q", dnsType)
		}

		// Each record type is an independent question, so ask them all at once.
		// Run in sequence, a bare `sek dns` cost the sum of every round-trip,
		// and the email-security probes alone are a dozen of them.
		type outcome struct {
			records []dnsx.Record
			err     error
		}
		outcomes := make([]outcome, len(selected))
		var wg sync.WaitGroup
		for n, i := range selected {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcomes[n].records, outcomes[n].err = dnsLookups[i].lookup(resolver, ctx, dnsDomain)
			}()
		}
		wg.Wait()

		// An interrupt leaves every lookup carrying "context canceled" as its
		// error. Rendering those as a finished report — sections, wildcard
		// verdict, platform line, exit status 0, and with -o a file that looks
		// complete — presents a run that answered nothing as one that answered
		// everything. `scan` already returns the context error at this point.
		if err := ctx.Err(); err != nil {
			return err
		}

		// Records are kept as they come back so platform detection can reuse
		// them instead of asking the resolver the same questions again.
		fetched := make(map[string][]dnsx.Record, len(selected))
		for n, i := range selected {
			l := dnsLookups[i]
			section := dnsx.Section{Title: l.title, Records: outcomes[n].records}
			if outcomes[n].err != nil {
				section.Error = outcomes[n].err.Error()
			} else {
				// A nil entry means "not fetched" to dnsx, so record an empty
				// non-nil slice for a query that ran and simply found nothing.
				records := outcomes[n].records
				if records == nil {
					records = []dnsx.Record{}
				}
				fetched[l.key] = records
			}
			res.Sections = append(res.Sections, section)
		}

		// The wildcard probe shares nothing with platform detection, so it runs
		// alongside it rather than after.
		if all {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res.Wildcard = resolver.Wildcard(ctx, dnsDomain)
			}()
		}
		res.Platform = resolver.DetectPlatform(ctx, dnsDomain, &dnsx.Known{
			NS:    fetched["NS"],
			CNAME: fetched["CNAME"],
			A:     fetched["A"],
		})
		wg.Wait()

		// And again for the second phase. Neither the wildcard probe nor
		// platform detection reports an error — a negative answer is the
		// expected result for both — so an interrupt arriving here left the
		// records intact and quietly turned the two verdicts into "no wildcard"
		// and "Custom / Unknown", which read exactly like real answers.
		if err := ctx.Err(); err != nil {
			return err
		}

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderDNS(w, res, all)
		return nil
	},
}

// selectLookups returns the indices into dnsLookups that a normalised -t value
// asks for. An empty value selects every section.
func selectLookups(wanted string) []int {
	selected := make([]int, 0, len(dnsLookups))
	for i, l := range dnsLookups {
		if wanted == "" || l.key == wanted || slices.Contains(l.aliases, wanted) {
			selected = append(selected, i)
		}
	}
	return selected
}

func runReverseDNS(ctx context.Context, w *output.Writer, resolver *dnsx.Resolver, ip string) error {
	records, err := resolver.Reverse(ctx, ip)
	// An address with no PTR answers NOERROR and no records, which is not an
	// error but is equally nothing to show. Keying the empty case off err alone
	// let that answer through to the success branch and printed a PTR heading
	// with nothing under it.
	if len(records) == 0 {
		if w.IsJSON() {
			section := dnsx.Section{Title: "PTR"}
			if err != nil {
				section.Error = err.Error()
			}
			return w.JSON(&dnsx.Result{
				Domain:   ip,
				Server:   resolver.Server,
				Sections: []dnsx.Section{section},
			})
		}
		w.Header("Reverse DNS for: %s", ip)
		w.Note("No PTR records found.")
		w.Blank()
		return nil
	}

	res := &dnsx.Result{
		Domain:   ip,
		Server:   resolver.Server,
		Sections: []dnsx.Section{{Title: "PTR", Records: records}},
	}
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
	dnsCmd.Flags().StringVarP(&dnsType, "type", "t", "", "Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, EMAIL (default: all)")
	dnsCmd.Flags().StringVarP(&dnsServer, "server", "s", "", "DNS server to use (e.g. 8.8.8.8)")
	dnsCmd.Flags().StringVarP(&dnsReverse, "reverse", "r", "", "Reverse DNS lookup for an IP address")
	rootCmd.AddCommand(dnsCmd)
}
