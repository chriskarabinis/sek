package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// flags
var tfTarget string
var tfHTTP   bool

type tfSignature struct {
	name      string
	category  string
	header    string // header name to check
	headerVal string // substring to match in header value (empty = just presence)
	cookie    string // cookie name substring
	body      string // substring to find in HTML body
}

// signatures covers servers, languages, CMS, JS frameworks, analytics, CDN
var tfSignatures = []tfSignature{
	// Web Server
	{name: "nginx", category: "Web Server", header: "Server", headerVal: "nginx"},
	{name: "Apache", category: "Web Server", header: "Server", headerVal: "apache"},
	{name: "Microsoft IIS", category: "Web Server", header: "Server", headerVal: "microsoft-iis"},
	{name: "LiteSpeed", category: "Web Server", header: "Server", headerVal: "litespeed"},
	{name: "Caddy", category: "Web Server", header: "Server", headerVal: "caddy"},
	{name: "OpenResty", category: "Web Server", header: "Server", headerVal: "openresty"},

	// Language / Runtime
	{name: "PHP", category: "Language", header: "X-Powered-By", headerVal: "php"},
	{name: "PHP", category: "Language", cookie: "PHPSESSID"},
	{name: "ASP.NET", category: "Language", header: "X-Powered-By", headerVal: "asp.net"},
	{name: "ASP.NET", category: "Language", cookie: "ASP.NET_SessionId"},
	{name: "Node.js / Express", category: "Language", header: "X-Powered-By", headerVal: "express"},
	{name: "Java", category: "Language", cookie: "JSESSIONID"},
	{name: "Python", category: "Language", header: "X-Powered-By", headerVal: "python"},

	// CMS
	{name: "WordPress", category: "CMS", body: "wp-content"},
	{name: "WordPress", category: "CMS", body: "wp-includes"},
	{name: "WordPress", category: "CMS", body: `content="WordPress`},
	{name: "Joomla", category: "CMS", body: `content="Joomla`},
	{name: "Joomla", category: "CMS", body: "/components/com_"},
	{name: "Drupal", category: "CMS", header: "X-Generator", headerVal: "drupal"},
	{name: "Drupal", category: "CMS", body: "Drupal.settings"},
	{name: "Magento", category: "CMS", body: "Mage.Cookies"},
	{name: "Shopify", category: "CMS", body: "cdn.shopify.com"},
	{name: "Wix", category: "CMS", body: "wixsite.com"},
	{name: "Squarespace", category: "CMS", body: "static.squarespace.com"},
	{name: "Ghost", category: "CMS", body: "ghost.io"},
	{name: "PrestaShop", category: "CMS", body: "/modules/ps_"},
	{name: "TYPO3", category: "CMS", body: "typo3conf"},
	{name: "HubSpot CMS", category: "CMS", body: "hubspot.com/hs-fs"},
	{name: "Webflow", category: "CMS", body: "webflow.com"},

	// JS Framework
	{name: "React", category: "JS Framework", body: "data-reactroot"},
	{name: "React", category: "JS Framework", body: "__react"},
	{name: "Next.js", category: "JS Framework", body: "__NEXT_DATA__"},
	{name: "Vue", category: "JS Framework", body: "__vue__"},
	{name: "Nuxt", category: "JS Framework", body: "__nuxt"},
	{name: "Angular", category: "JS Framework", body: "ng-version"},
	{name: "Svelte", category: "JS Framework", body: "__svelte"},
	{name: "Ember", category: "JS Framework", body: "ember-application"},

	// JS Library
	{name: "jQuery", category: "JS Library", body: "jquery"},
	{name: "Bootstrap", category: "JS Library", body: "bootstrap"},
	{name: "Tailwind CSS", category: "JS Library", body: "tailwind"},
	{name: "Font Awesome", category: "JS Library", body: "font-awesome"},
	{name: "GSAP", category: "JS Library", body: "gsap"},

	// Analytics
	{name: "Google Analytics", category: "Analytics", body: "google-analytics.com"},
	{name: "Google Analytics", category: "Analytics", body: "gtag("},
	{name: "Google Tag Manager", category: "Analytics", body: "GTM-"},
	{name: "Hotjar", category: "Analytics", body: "hotjar.com"},
	{name: "Facebook Pixel", category: "Analytics", body: "fbevents.js"},
	{name: "Plausible", category: "Analytics", body: "plausible.io"},
	{name: "Matomo", category: "Analytics", body: "matomo.js"},
	{name: "Clarity", category: "Analytics", body: "clarity.ms"},

	// CDN / Security
	{name: "Cloudflare", category: "CDN / Security", header: "CF-Ray"},
	{name: "Fastly", category: "CDN / Security", header: "X-Served-By"},
	{name: "Akamai", category: "CDN / Security", header: "X-Check-Cacheable"},
	{name: "Sucuri WAF", category: "CDN / Security", header: "X-Sucuri-ID"},
	{name: "Imperva", category: "CDN / Security", cookie: "visid_incap"},
}

// categoryOrder defines display order
var categoryOrder = []string{
	"Web Server", "Language", "CMS", "JS Framework", "JS Library", "Analytics", "CDN / Security",
}

var tfCmd = &cobra.Command{
	Use:   "tf",
	Short: "Technology fingerprinting",
	Long:  `Detect technologies used by a website — web server, CMS, frameworks, analytics, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		if tfTarget == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		scheme := "https"
		if tfHTTP {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s", scheme, tfTarget)

		header := fmt.Sprintf("\n[*] Technology Fingerprint for: %s\n", tfTarget)
		WriteLineColored(yellow+header+reset, header)

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: 5 * time.Second,
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
			},
		}

		resp, err := client.Get(url)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Request failed: %s\n", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Read body (limit to 100KB to avoid memory issues)
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		body := strings.ToLower(string(bodyBytes))

		// Build cookie name set
		cookieNames := make(map[string]bool)
		for _, c := range resp.Cookies() {
			cookieNames[strings.ToLower(c.Name)] = true
		}

		// Match signatures — deduplicate by name+category
		found := make(map[string]map[string]bool) // category → set of names
		for _, sig := range tfSignatures {
			matched := false

			if sig.header != "" {
				val := strings.ToLower(resp.Header.Get(sig.header))
				if val != "" && (sig.headerVal == "" || strings.Contains(val, sig.headerVal)) {
					matched = true
				}
			}
			if !matched && sig.cookie != "" {
				if cookieNames[strings.ToLower(sig.cookie)] {
					matched = true
				}
			}
			if !matched && sig.body != "" {
				if strings.Contains(body, strings.ToLower(sig.body)) {
					matched = true
				}
			}

			if matched {
				if found[sig.category] == nil {
					found[sig.category] = make(map[string]bool)
				}
				found[sig.category][sig.name] = true
			}
		}

		if len(found) == 0 {
			WriteLine("  No technologies detected.\n")
			return
		}

		for _, cat := range categoryOrder {
			names, ok := found[cat]
			if !ok {
				continue
			}
			plain := fmt.Sprintf("[*] %s", cat)
			WriteLineColored(yellow+plain+reset, plain)
			for name := range names {
				plain := fmt.Sprintf("  %s", name)
				WriteLineColored(yellow+plain+reset, plain)
			}
			WriteLine("")
		}
	},
}

func init() {
	tfCmd.Flags().StringVarP(&tfTarget, "domain", "d", "", "Target domain (e.g. example.com)")
	tfCmd.Flags().BoolVar(&tfHTTP, "http", false, "Use HTTP instead of HTTPS")
	rootCmd.AddCommand(tfCmd)
}
