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
var headersDomain  string
var headersHTTP    bool
var headersPort    string
var headersAll     bool

type secHeader struct {
	key         string
	description string
}

// securityHeaders lists the headers checked and why they matter
var securityHeaders = []secHeader{
	{"Strict-Transport-Security", "Forces HTTPS — prevents downgrade attacks"},
	{"Content-Security-Policy", "Prevents XSS and data injection attacks"},
	{"X-Frame-Options", "Prevents clickjacking"},
	{"X-Content-Type-Options", "Prevents MIME type sniffing"},
	{"Referrer-Policy", "Controls how much referrer info is sent"},
	{"Permissions-Policy", "Restricts access to browser features"},
	{"X-XSS-Protection", "Legacy XSS filter (older browsers)"},
}

func scoreLabel(present, total int) string {
	ratio := float64(present) / float64(total)
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

		// Response info
		WriteLine("[*] Response")
		infoFields := []struct{ label, value string }{
			{"Status", resp.Status},
			{"Server", resp.Header.Get("Server")},
			{"Content-Type", resp.Header.Get("Content-Type")},
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

		present := 0
		for _, sh := range securityHeaders {
			val := resp.Header.Get(sh.key)
			state := "MISSING"
			display := "-"
			if val != "" {
				state = "PRESENT"
				display = val
				present++
			}
			// Truncate long values for display
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			plain := fmt.Sprintf("  %-34s %-9s %s", sh.key, state, display)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		label := scoreLabel(present, len(securityHeaders))
		score := fmt.Sprintf("[*] Score: %d/%d — %s", present, len(securityHeaders), label)
		WriteLineColored(yellow+score+reset, score)
		WriteLine("")

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
