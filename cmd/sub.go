package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// flags
var subDomain    string
var subWordlist  string

// built-in wordlist
var wordlist = []string{
	// Web
	"www", "www1", "www2", "www3", "web", "web1", "web2", "website",
	// Mail
	"mail", "mail1", "mail2", "smtp", "smtp1", "pop", "pop3", "imap",
	"webmail", "email", "mx", "mx1", "mx2", "mx3",
	// FTP / Files
	"ftp", "ftp1", "ftp2", "sftp", "files", "download", "downloads",
	"upload", "uploads",
	// API
	"api", "api1", "api2", "apis", "rest", "graphql", "v1", "v2", "v3",
	// Dev / Test / Staging
	"dev", "dev1", "dev2", "develop", "development",
	"test", "test1", "test2", "testing",
	"staging", "stage", "uat", "qa", "qa1",
	"sandbox", "demo", "preview", "beta", "alpha", "canary",
	// Production
	"prod", "production", "live",
	// Admin / Management
	"admin", "admin1", "administrator", "panel", "cpanel",
	"plesk", "manage", "management", "manager", "portal", "control",
	"dashboard", "dash",
	// Auth / Identity
	"auth", "oauth", "sso", "login", "signin", "signup",
	"account", "accounts", "user", "users", "id", "identity",
	// Security / Network
	"vpn", "vpn1", "vpn2", "remote", "ssh", "ssl",
	"secure", "security", "firewall", "fw", "proxy", "gateway",
	// DNS / NS
	"ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	// CDN / Static / Media
	"cdn", "cdn1", "cdn2", "static", "assets",
	"media", "img", "images", "image", "video", "videos",
	// Cloud / Storage
	"cloud", "aws", "azure", "gcp", "s3", "storage",
	"backup", "backups",
	// Apps / Mobile
	"app", "app1", "app2", "apps", "mobile", "m", "wap",
	// Monitoring / Analytics
	"monitor", "monitoring", "status", "health", "metrics",
	"grafana", "kibana", "prometheus", "nagios", "zabbix",
	"analytics", "stats", "statistics", "reports",
	// CI/CD / Git
	"ci", "cd", "jenkins", "gitlab", "git", "svn",
	"repo", "build", "builds", "deploy", "deployment", "pipeline",
	// Databases
	"db", "db1", "db2", "mysql", "postgres", "mongo", "redis",
	"elastic", "elasticsearch",
	// Support / Docs
	"support", "help", "helpdesk", "ticket", "tickets",
	"docs", "doc", "wiki", "kb", "blog", "news",
	"forum", "forums", "community",
	// Business
	"shop", "store", "commerce", "pay", "payment", "payments",
	"billing", "invoice", "crm",
	// Internal
	"internal", "intranet", "corp", "office", "private", "local",
	// Geographic
	"us", "eu", "uk", "de", "fr", "jp", "asia",
	// Old / Legacy
	"old", "new", "legacy", "archive", "beta2",
	// Misc
	"jira", "confluence", "slack", "zoom",
}

type findResult struct {
	host string
	ips  []string
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func fetchFromCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if strings.HasPrefix(name, "*") {
				continue
			}
			if strings.HasSuffix(name, "."+domain) && !seen[name] {
				seen[name] = true
				results = append(results, name)
			}
		}
	}
	return results, nil
}

func subLookupIPs(host string) []string {
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return ips
}

func checkSubdomain(sub, domain string, wg *sync.WaitGroup, results chan<- findResult) {
	defer wg.Done()
	host := sub + "." + domain
	ips, err := net.LookupHost(host)
	if err == nil {
		results <- findResult{host: host, ips: ips}
	}
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

func formatSubResult(r findResult) string {
	ipsStr := strings.Join(r.ips, ", ")
	if ipsStr == "" {
		ipsStr = "N/A"
	}
	return fmt.Sprintf("  %-45s %s", r.host, ipsStr)
}

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Subdomain enumeration",
	Long:  `Discover subdomains using DNS brute force and certificate transparency logs.`,
	Run: func(cmd *cobra.Command, args []string) {
		if subDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		// Load wordlist
		words := wordlist
		if subWordlist != "" {
			loaded, err := loadWordlist(subWordlist)
			if err != nil {
				fmt.Printf("[!] Cannot load wordlist: %s\n", err)
				os.Exit(1)
			}
			words = loaded
			WriteLine(fmt.Sprintf("[*] Loaded %d words from %s", len(words), subWordlist))
		}

		// Show main domain IP
		domainIPs := subLookupIPs(subDomain)
		domainIPStr := strings.Join(domainIPs, ", ")
		if domainIPStr == "" {
			domainIPStr = "N/A"
		}
		header := fmt.Sprintf("\n[*] %s  ->  %s\n", subDomain, domainIPStr)
		WriteLineColored(yellow+header+reset, header)

		found := make(map[string]bool)
		var mu sync.Mutex

		// --- Source 1: crt.sh ---
		WriteLine("[*] Querying certificate transparency logs (crt.sh)...")
		crtResults, err := fetchFromCrtSh(subDomain)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] crt.sh failed: %s", err))
		} else {
			for _, sub := range crtResults {
				mu.Lock()
				if !found[sub] {
					found[sub] = true
					ips := subLookupIPs(sub)
					plain := formatSubResult(findResult{host: sub, ips: ips})
					WriteLineColored(yellow+plain+reset, plain)
				}
				mu.Unlock()
			}
			WriteLine(fmt.Sprintf("\n  -> %d subdomains from crt.sh", len(crtResults)))
		}

		// --- Source 2: DNS Brute Force ---
		WriteLine(fmt.Sprintf("\n[*] Running DNS brute force (%d words)...", len(words)))

		results := make(chan findResult)
		var wg sync.WaitGroup

		for _, sub := range words {
			wg.Add(1)
			go checkSubdomain(sub, subDomain, &wg, results)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		bruteCount := 0
		for r := range results {
			mu.Lock()
			if !found[r.host] {
				found[r.host] = true
				plain := formatSubResult(r)
				WriteLineColored(yellow+plain+reset, plain)
				bruteCount++
			}
			mu.Unlock()
		}
		WriteLine(fmt.Sprintf("\n  -> %d new subdomains from brute force", bruteCount))
		WriteLine(fmt.Sprintf("\n[*] Done. Found %d unique subdomains total.\n", len(found)))
	},
}

func init() {
	subCmd.Flags().StringVarP(&subDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	subCmd.Flags().StringVarP(&subWordlist, "wordlist", "w", "", "Custom wordlist file")
	rootCmd.AddCommand(subCmd)
}
