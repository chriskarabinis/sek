package cmd

import (
	"sort"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/output"
	"github.com/chriskarabinis/sek/internal/webx"
)

var (
	headersDomain string
	headersHTTP   bool
	headersPort   string
	headersAll    bool
)

var headersCmd = &cobra.Command{
	Use:   "headers",
	Short: "HTTP security headers checker",
	Long:  `Fetch HTTP response headers and check for security best practices.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ctx, stop := commandContext()
		defer stop()

		res, err := webx.CheckHeaders(ctx, headersDomain, webx.Options{
			UseHTTP:    headersHTTP,
			Port:       headersPort,
			IncludeAll: headersAll,
		})
		if err != nil {
			return err
		}

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderHeaders(w, res)
		return nil
	},
}

func renderHeaders(w *output.Writer, res *webx.HeadersResult) {
	const tableWidth = 80

	w.Header("HTTP Security Headers for: %s", res.Target)

	w.Section("Response")
	w.Field(16, "Status", res.Status)
	w.Field(16, "Server", orDash(res.Server))
	w.Field(16, "Content-Type", orDash(res.ContentType))
	if res.Redirected {
		w.Field(16, "Redirected To", res.FinalURL)
	}
	w.Blank()

	w.Section("Security Headers")
	w.Highlightf("  %-34s %-9s %s", "HEADER", "STATE", "VALUE")
	w.Rule(tableWidth)
	for _, c := range res.Checks {
		w.Highlightf("  %-34s %-9s %s", c.Header, c.State, truncate(orDash(c.Value), 60))
	}
	w.Blank()

	w.Highlightf("[*] Score: %d/%d — %s", res.Score, res.MaxScore, res.Rating)
	w.Blank()

	if len(res.Deprecated) > 0 {
		w.Section("Deprecated Headers")
		for _, c := range res.Deprecated {
			// Wider state column: "DEPRECATED" does not fit the 9 used above.
			w.Highlightf("  %-34s %-10s %s", c.Header, c.State, truncate(c.Value, 60))
		}
		w.Blank()
	}

	missing := res.Missing()
	if len(missing) > 0 || len(res.Deprecated) > 0 {
		w.Section("Recommendations")
		for _, c := range missing {
			w.Note("Add to your server config:")
			w.Highlightf("  %s", c.Fix)
			w.Blank()
		}
		for _, c := range res.Deprecated {
			w.Note("%s is deprecated and should not be sent:", c.Header)
			w.Highlightf("  %s", c.Fix)
			w.Blank()
		}
	}

	if headersAll && len(res.AllHeaders) > 0 {
		w.Section("All Response Headers")
		keys := make([]string, 0, len(res.AllHeaders))
		for k := range res.AllHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.Highlightf("  %-35s  %s", k, res.AllHeaders[k])
		}
		w.Blank()
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func init() {
	headersCmd.Flags().StringVarP(&headersDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	headersCmd.Flags().BoolVar(&headersHTTP, "http", false, "Use HTTP instead of HTTPS")
	headersCmd.Flags().StringVarP(&headersPort, "port", "p", "", "Custom port")
	headersCmd.Flags().BoolVar(&headersAll, "all", false, "Show all response headers")
	headersCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(headersCmd)
}
