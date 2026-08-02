package cmd

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/subx"
)

var (
	subDomain      string
	subWordlist    string
	subConcurrency int
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Subdomain enumeration",
	Long:  `Discover subdomains using DNS brute force and certificate transparency logs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		words := subx.DefaultWordlist
		if subWordlist != "" {
			words, err = subx.LoadWordlist(subWordlist)
			if err != nil {
				return err
			}
		}

		ctx, stop := commandContext()
		defer stop()

		res := &subx.Result{Domain: subDomain, IPs: subx.LookupIPs(ctx, subDomain)}

		w.Header("%s  ->  %s", subDomain, joinOr(res.IPs, "N/A"))
		if subWordlist != "" {
			w.Section("Loaded %d words from %s", len(words), subWordlist)
			w.Blank()
		}

		// Wildcard DNS makes brute force meaningless: every name resolves, so
		// every word looks like a hit. Detect it first and filter against it.
		res.WildcardIPs = subx.DetectWildcardIPs(ctx, subDomain)
		if len(res.WildcardIPs) > 0 {
			w.Warn("Wildcard DNS detected: *.%s  ->  %s", subDomain, strings.Join(res.WildcardIPs, ", "))
			w.Note("Brute-force hits resolving only to these addresses will be filtered.")
			w.Blank()
		}

		seen := make(map[string]bool)

		// Source 1: certificate transparency logs.
		w.Section("Querying certificate transparency logs (crt.sh)...")
		names, err := subx.FetchCertLog(ctx, subDomain)
		if err != nil {
			res.CertLogError = err.Error()
			w.Warn("crt.sh failed: %s", err)
		} else {
			for _, finding := range subx.ResolveAll(ctx, names, subx.SourceCertLog, subConcurrency) {
				if seen[finding.Host] {
					continue
				}
				seen[finding.Host] = true
				res.Findings = append(res.Findings, finding)
				res.CertLogCount++
				w.Highlight(formatFinding(finding))
			}
			w.Blank()
			w.Note("-> %d subdomains from crt.sh", res.CertLogCount)
		}

		// Source 2: DNS brute force.
		w.Blank()
		w.Section("Running DNS brute force (%d words)...", len(words))

		hits, filtered := subx.BruteForce(ctx, subDomain, subx.Options{
			Words:       words,
			Concurrency: subConcurrency,
		}, res.WildcardIPs)

		for finding := range hits {
			if seen[finding.Host] {
				continue
			}
			seen[finding.Host] = true
			res.Findings = append(res.Findings, finding)
			res.BruteCount++
			w.Highlight(formatFinding(finding))
		}
		res.WildcardFiltered = filtered()

		sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].Host < res.Findings[j].Host })

		if w.IsJSON() {
			return w.JSON(res)
		}

		w.Blank()
		w.Note("-> %d new subdomains from brute force", res.BruteCount)
		if res.WildcardFiltered > 0 {
			w.Note("-> %d wildcard responses filtered out", res.WildcardFiltered)
		}
		w.Blank()
		w.Highlightf("[*] Done. Found %d unique subdomains total.", len(res.Findings))
		w.Blank()
		return nil
	},
}

func formatFinding(f subx.Finding) string {
	return "  " + pad(f.Host, 45) + " " + joinOr(f.IPs, "N/A")
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func joinOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, ", ")
}

func init() {
	subCmd.Flags().StringVarP(&subDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	subCmd.Flags().StringVarP(&subWordlist, "wordlist", "w", "", "Custom wordlist file")
	subCmd.Flags().IntVar(&subConcurrency, "concurrency", 50, "Number of DNS lookups in parallel")
	subCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(subCmd)
}
