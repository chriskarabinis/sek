// Package subx discovers subdomains from certificate transparency logs and by
// resolving a wordlist against the target.
package subx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
//
// The three probes run together: they are independent, and one after another
// they were three full DNS timeouts standing between the user and any output on
// a domain that does not answer.
func DetectWildcardIPs(ctx context.Context, domain string) []string {
	const probes = 3

	results := make([][]string, probes)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = LookupIPs(ctx, dnsx.RandomLabel()+"."+domain)
		}()
	}
	wg.Wait()

	seen := make(map[string]bool)
	for _, addrs := range results {
		// A probe that does not resolve means there is no wildcard; treating a
		// partial answer as one would filter out real findings.
		if len(addrs) == 0 {
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

// certLogLimit caps how much of a crt.sh answer is decoded.
const certLogLimit = 64 << 20

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

	// crt.sh answers for a heavily-certificated domain run to hundreds of
	// megabytes. Cap what is decoded so one unlucky target cannot exhaust memory.
	var entries []crtEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, certLogLimit)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("cannot parse crt.sh response: %w", err)
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
					if ctx.Err() != nil {
						continue
					}
					host := word + "." + domain
					ips := LookupIPs(ctx, host)
					if len(ips) == 0 {
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

// resolveHost is the single DNS entry point for this package. It is a var so
// tests can count and control lookups without touching the network.
var resolveHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// LookupIPs resolves a host through the context-aware resolver, returning nil
// when it does not resolve. net.LookupHost takes no context, so a cancelled run
// had to sit through the full DNS timeout on every lookup already in flight
// before it could return.
func LookupIPs(ctx context.Context, host string) []string {
	addrs, err := resolveHost(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}

// ResolveAll resolves hosts through a bounded worker pool and returns one
// Finding per host, in input order, tagged with source.
//
// Certificate transparency logs routinely return hundreds of names for a
// domain. Resolving them one at a time meant the command sat blocked on
// sequential DNS for minutes before printing anything.
func ResolveAll(ctx context.Context, hosts []string, source string, concurrency int) []Finding {
	findings := make([]Finding, len(hosts))
	for i, h := range hosts {
		findings[i] = Finding{Host: h, Source: source}
	}
	// A context cancelled before the pool starts must do no work at all. The
	// dispatch select below happens to achieve that today only because no
	// worker has parked on the channel yet, so the send is never ready; once
	// one has, Go picks between the send and ctx.Done() at random. State the
	// guarantee here rather than leaving it to scheduling.
	if len(hosts) == 0 || ctx.Err() != nil {
		return findings
	}

	if concurrency < 1 {
		concurrency = 50
	}
	workers := min(concurrency, len(hosts))

	indices := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indices {
				// Cancellation mid-run drains the queue rather than resolving it.
				if ctx.Err() != nil {
					continue
				}
				findings[i].IPs = LookupIPs(ctx, findings[i].Host)
			}
		}()
	}

dispatch:
	for i := range hosts {
		select {
		case indices <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(indices)
	wg.Wait()

	return findings
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
