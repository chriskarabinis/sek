package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// flags
var headersDomain string
var headersHTTP bool
var headersPort string
var headersAll bool

type secHeader struct {
	key    string
	weight int
	fix    string
}

// securityHeaders lists the headers that count toward the score, with the value
// to add when missing. Weights reflect impact: a missing Content-Security-Policy
// is not equivalent to a missing Permissions-Policy, which flat scoring implied.
var securityHeaders = []secHeader{
	{
		"Content-Security-Policy", 3,
		"Content-Security-Policy: default-src 'self'",
	},
	{
		"Strict-Transport-Security", 3,
		"Strict-Transport-Security: max-age=31536000; includeSubDomains",
	},
	{
		"X-Frame-Options", 2,
		"X-Frame-Options: SAMEORIGIN",
	},
	{
		"X-Content-Type-Options", 1,
		"X-Content-Type-Options: nosniff",
	},
	{
		"Referrer-Policy", 1,
		"Referrer-Policy: strict-origin-when-cross-origin",
	},
	{
		"Permissions-Policy", 1,
		"Permissions-Policy: camera=(), microphone=(), geolocation=()",
	},
}

// deprecatedHeaders are headers whose presence is itself the finding.
// X-XSS-Protection switched on the legacy XSS auditor, which introduced
// injection vectors of its own and has been removed from every current
// browser. Current guidance (OWASP, MDN) is to drop it or send 0 — so it is
// reported as a problem when present, not rewarded when absent.
var deprecatedHeaders = []secHeader{
	{
		"X-XSS-Protection", 0,
		"Remove the header, or send: X-XSS-Protection: 0",
	},
}

func maxScore() int {
	total := 0
	for _, sh := range securityHeaders {
		total += sh.weight
	}
	return total
}

func scoreLabel(earned, total int) string {
	if total == 0 {
		return "Unknown"
	}
	ratio := float64(earned) / float64(total)
	switch {
	case ratio == 1.0:
		return "Excellent"
	case ratio >= 0.7:
		return "Good"
	case ratio >= 0.4:
		return "Fair"
	default:
		return "Poor"
	}
}

var headersCmd = &cobra.Command{
	Use:   "headers",
	Short: "HTTP security headers checker",
	Long:  `Fetch HTTP response headers and check for security best practices.`,
	Run: func(cmd *cobra.Command, args []string) {
		if headersDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		// Build URL
		scheme := "https"
		if headersHTTP {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s", scheme, headersDomain)
		if headersPort != "" {
			url = fmt.Sprintf("%s://%s:%s", scheme, headersDomain, headersPort)
		}

		header := fmt.Sprintf("\n[*] HTTP Security Headers for: %s\n", headersDomain)
		WriteLineColored(yellow+header+reset, header)

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		}

		resp, err := client.Get(url)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Request failed: %s\n", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Redirects are followed by default, so the headers reported below can
		// belong to a different origin than the one asked for. Say so instead
		// of silently attributing them to the requested host.
		finalURL := url
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}

		// Response info
		WriteLine("[*] Response")
		type infoField struct{ label, value string }
		infoFields := []infoField{
			{"Status", resp.Status},
			{"Server", resp.Header.Get("Server")},
			{"Content-Type", resp.Header.Get("Content-Type")},
		}
		if finalURL != url {
			infoFields = append(infoFields, infoField{"Redirected To", finalURL})
		}
		for _, f := range infoFields {
			val := f.value
			if val == "" {
				val = "-"
			}
			plain := fmt.Sprintf("  %-16s  %s", f.label, val)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		// Security headers table
		WriteLine("[*] Security Headers")
		plain := fmt.Sprintf("  %-34s %-9s %s", "HEADER", "STATE", "VALUE")
		WriteLineColored(yellow+plain+reset, plain)
		WriteLine("  " + strings.Repeat("-", 80))

		earned := 0
		var missing []secHeader
		for _, sh := range securityHeaders {
			val := resp.Header.Get(sh.key)
			state := "MISSING"
			display := "-"
			if val != "" {
				state = "PRESENT"
				display = val
				earned += sh.weight
			} else {
				missing = append(missing, sh)
			}
			// Truncate long values for display
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			plain := fmt.Sprintf("  %-34s %-9s %s", sh.key, state, display)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		total := maxScore()
		label := scoreLabel(earned, total)
		score := fmt.Sprintf("[*] Score: %d/%d — %s", earned, total, label)
		WriteLineColored(yellow+score+reset, score)
		WriteLine("")

		// Headers that should not be there at all
		var deprecated []secHeader
		for _, sh := range deprecatedHeaders {
			if val := resp.Header.Get(sh.key); val != "" {
				deprecated = append(deprecated, sh)
				plain := fmt.Sprintf("  %-34s %-9s %s", sh.key, "DEPRECATED", val)
				WriteLineColored(yellow+plain+reset, plain)
			}
		}
		if len(deprecated) > 0 {
			WriteLine("")
		}

		// Recommendations
		if len(missing) > 0 || len(deprecated) > 0 {
			WriteLine("[*] Recommendations")
			for _, sh := range missing {
				WriteLine("  Add to your server config:")
				plain := fmt.Sprintf("  %s", sh.fix)
				WriteLineColored(yellow+plain+reset, plain)
				WriteLine("")
			}
			for _, sh := range deprecated {
				WriteLine(fmt.Sprintf("  %s is deprecated and should not be sent:", sh.key))
				plain := fmt.Sprintf("  %s", sh.fix)
				WriteLineColored(yellow+plain+reset, plain)
				WriteLine("")
			}
		}

		// All headers
		if headersAll {
			WriteLine("[*] All Response Headers")
			for key, vals := range resp.Header {
				plain := fmt.Sprintf("  %-35s  %s", key, strings.Join(vals, ", "))
				WriteLineColored(yellow+plain+reset, plain)
			}
			WriteLine("")
		}
	},
}

func init() {
	headersCmd.Flags().StringVarP(&headersDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	headersCmd.Flags().BoolVar(&headersHTTP, "http", false, "Use HTTP instead of HTTPS")
	headersCmd.Flags().StringVarP(&headersPort, "port", "p", "", "Custom port")
	headersCmd.Flags().BoolVar(&headersAll, "all", false, "Show all response headers")
	rootCmd.AddCommand(headersCmd)
}
