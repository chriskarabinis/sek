// Package subx discovers subdomains from certificate transparency logs and by
// resolving a wordlist against the target.
package subx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chriskarabinis/sek/internal/dnsx"
)

// Source names for where a subdomain was found.
const (
	SourceCertLog    = "crt.sh"
	SourceBruteForce = "brute"
)

// Finding is one discovered subdomain.
type Finding struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips,omitempty"`
	Source string   `json:"source"`
}

// Result is a completed enumeration.
type Result struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips,omitempty"`
	// WildcardIPs is non-empty when the domain answers for any name, which
	// makes brute-force hits meaningless unless filtered against it.
	WildcardIPs      []string  `json:"wildcard_ips,omitempty"`
	Findings         []Finding `json:"findings"`
	CertLogCount     int       `json:"cert_log_count"`
	BruteCount       int       `json:"brute_count"`
	WildcardFiltered int       `json:"wildcard_filtered"`
	CertLogError     string    `json:"cert_log_error,omitempty"`
}

// Options configures an enumeration.
type Options struct {
	Words       []string
	Concurrency int
	Timeout     time.Duration
}

// LoadWordlist reads a newline-separated wordlist, skipping blanks and #
// comments.
func LoadWordlist(path string) ([]string, error) {
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %s is empty", path)
	}
	return words, nil
}

// DetectWildcardIPs probes random names to find out whether the domain answers
// for anything. A non-empty result holds the addresses the wildcard resolves
// to, so brute-force hits pointing only there can be dropped.
func DetectWildcardIPs(domain string) []string {
	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		addrs, err := net.LookupHost(dnsx.RandomLabel() + "." + domain)
		if err != nil || len(addrs) == 0 {
			return nil
		}
		for _, ip := range addrs {
			seen[ip] = true
		}
	}
	return sortedKeys(seen)
}

// isWildcardHit reports whether every address for a host belongs to the
// wildcard set. A host with even one address outside it is a real find.
func isWildcardHit(ips, wildcard []string) bool {
	if len(wildcard) == 0 || len(ips) == 0 {
		return false
	}
	set := make(map[string]bool, len(wildcard))
	for _, ip := range wildcard {
		set[ip] = true
	}
	for _, ip := range ips {
		if !set[ip] {
			return false
		}
	}
	return true
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// FetchCertLog queries crt.sh for names seen in published certificates.
func FetchCertLog(ctx context.Context, domain string) ([]string, error) {
	// The leading % is crt.sh's SQL LIKE wildcard and is deliberately sent
	// unescaped, which is what the service expects. Go passes RawQuery through
	// untouched, so it reaches crt.sh verbatim.
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	suffix := "." + domain
	seen := make(map[string]bool)
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			// Wildcard entries name no specific host, so they are not findings.
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			if strings.HasSuffix(name, suffix) {
				seen[name] = true
			}
		}
	}
	return sortedKeys(seen), nil
}

// BruteForce resolves each word against the domain through a fixed worker pool
// and streams the hits.
//
// The pool is what makes this usable: a SecLists wordlist runs to tens of
// thousands of entries, and one goroutine per word buries the resolver, which
// then drops queries and turns into silent false negatives.
func BruteForce(ctx context.Context, domain string, opts Options, wildcard []string) (<-chan Finding, func() int) {
	out := make(chan Finding)

	var mu sync.Mutex
	filtered := 0

	workers := opts.Concurrency
	if workers < 1 {
		workers = 50
	}
	if len(opts.Words) < workers {
		workers = len(opts.Words)
	}

	go func() {
		defer close(out)
		if workers == 0 {
			return
		}

		jobs := make(chan string)
		var wg sync.WaitGroup

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for word := range jobs {
					host := word + "." + domain
					ips, err := net.LookupHost(host)
					if err != nil {
						continue
					}
					if isWildcardHit(ips, wildcard) {
						mu.Lock()
						filtered++
						mu.Unlock()
						continue
					}
					select {
					case out <- Finding{Host: host, IPs: ips, Source: SourceBruteForce}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

	dispatch:
		for _, word := range opts.Words {
			select {
			case jobs <- word:
			case <-ctx.Done():
				break dispatch
			}
		}
		close(jobs)
		wg.Wait()
	}()

	return out, func() int {
		mu.Lock()
		defer mu.Unlock()
		return filtered
	}
}

// LookupIPs resolves a host, returning nil when it does not resolve.
func LookupIPs(host string) []string {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return addrs
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
