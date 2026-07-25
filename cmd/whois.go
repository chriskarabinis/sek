package cmd

import (
	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/output"
	"github.com/chriskarabinis/sek/internal/whoisx"
)

var (
	whoisDomain string
	whoisRaw    bool
)

var whoisCmd = &cobra.Command{
	Use:   "whois",
	Short: "WHOIS domain lookup",
	Long:  `Query WHOIS information for a domain — registrar, dates, nameservers, and status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ctx, stop := commandContext()
		defer stop()

		res, err := whoisx.Lookup(ctx, whoisDomain)
		if err != nil {
			return err
		}

		if w.IsJSON() {
			if !whoisRaw {
				res.Raw = ""
			}
			return w.JSON(res)
		}

		w.Header("WHOIS lookup for: %s", res.Domain)
		w.Section("Querying: %s", res.Server)
		w.Blank()

		if whoisRaw {
			w.Line(res.Raw)
			return nil
		}
		renderWhois(w, res)
		return nil
	},
}

func renderWhois(w *output.Writer, res *whoisx.Result) {
	if !res.Registered {
		w.Warn("Domain not registered: %s", res.Domain)
		w.Blank()
		return
	}

	if !res.DomainLevel {
		w.Warn("No domain-level WHOIS available for .%s — the registry has no public port-43 server.", whoisx.TLD(res.Domain))
		w.Blank()
		if res.WebLookup != "" {
			w.Highlightf("[*] Domain lookup: %s", res.WebLookup)
			w.Blank()
		}
		renderTLD(w, res.TLD)
		return
	}

	w.Section("Domain Info")
	for _, f := range []struct{ label, value string }{
		{"Registrar", res.Registrar},
		{"Registrant", res.Registrant},
		{"Created", res.Created},
		{"Updated", res.Updated},
		{"Expires", res.Expires},
		{"Status", res.Status},
		{"DNSSEC", res.DNSSEC},
	} {
		w.Field(12, f.label, orNA(f.value))
	}
	w.Blank()

	w.Section("Name Servers")
	if len(res.NameServers) == 0 {
		w.Note("None found.")
	} else {
		for _, ns := range res.NameServers {
			w.Highlightf("  %s", ns)
		}
	}
	w.Blank()
}

func renderTLD(w *output.Writer, tld *whoisx.TLDInfo) {
	if tld == nil {
		return
	}

	w.Section("TLD Registry Info (from IANA)")
	for _, f := range []struct{ label, value string }{
		{"Organisation", tld.Organisation},
		{"Status", tld.Status},
		{"Created", tld.Created},
		{"Changed", tld.Changed},
	} {
		if f.value != "" {
			w.Field(14, f.label, f.value)
		}
	}
	w.Blank()

	if len(tld.NameServers) > 0 {
		w.Section("TLD Name Servers")
		for _, ns := range tld.NameServers {
			w.Highlightf("  %s", ns)
		}
		w.Blank()
	}
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func init() {
	whoisCmd.Flags().StringVarP(&whoisDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	whoisCmd.Flags().BoolVarP(&whoisRaw, "raw", "r", false, "Show raw WHOIS response")
	whoisCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(whoisCmd)
}
