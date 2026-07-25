// Package webx inspects HTTP responses: security headers and the technologies
// a site's headers, cookies and markup give away.
package webx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Header states.
const (
	StatePresent    = "PRESENT"
	StateMissing    = "MISSING"
	StateDeprecated = "DEPRECATED"
)

// SecHeader describes a header the checker knows about.
type SecHeader struct {
	Key string
	// Weight is how much the header contributes to the score. Impact differs
	// enough that counting them equally misrepresents the result.
	Weight int
	// Fix is the remediation line shown to the user.
	Fix string
}

// SecurityHeaders are the headers that count toward the score.
var SecurityHeaders = []SecHeader{
	{"Content-Security-Policy", 3, "Content-Security-Policy: default-src 'self'"},
	{"Strict-Transport-Security", 3, "Strict-Transport-Security: max-age=31536000; includeSubDomains"},
	{"X-Frame-Options", 2, "X-Frame-Options: SAMEORIGIN"},
	{"X-Content-Type-Options", 1, "X-Content-Type-Options: nosniff"},
	{"Referrer-Policy", 1, "Referrer-Policy: strict-origin-when-cross-origin"},
	{"Permissions-Policy", 1, "Permissions-Policy: camera=(), microphone=(), geolocation=()"},
}

// DeprecatedHeaders are headers whose presence is itself the finding.
//
// X-XSS-Protection switched on the legacy XSS auditor, which introduced
// injection vectors of its own and has been removed from every current browser.
// Current guidance (OWASP, MDN) is to drop it or send 0, so it is reported as a
// problem when present rather than rewarded when absent.
var DeprecatedHeaders = []SecHeader{
	{"X-XSS-Protection", 0, "Remove the header, or send: X-XSS-Protection: 0"},
}

// HeaderCheck is the outcome for one header.
type HeaderCheck struct {
	Header string `json:"header"`
	State  string `json:"state"`
	Value  string `json:"value,omitempty"`
	Fix    string `json:"fix,omitempty"`
	Weight int    `json:"weight,omitempty"`
}

// HeadersResult is a completed security-header check.
type HeadersResult struct {
	Target      string            `json:"target"`
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	Redirected  bool              `json:"redirected"`
	Status      string            `json:"status"`
	StatusCode  int               `json:"status_code"`
	Server      string            `json:"server,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Checks      []HeaderCheck     `json:"checks"`
	Deprecated  []HeaderCheck     `json:"deprecated,omitempty"`
	Score       int               `json:"score"`
	MaxScore    int               `json:"max_score"`
	Rating      string            `json:"rating"`
	AllHeaders  map[string]string `json:"all_headers,omitempty"`
}

// Missing returns the checks for headers that are absent.
func (r *HeadersResult) Missing() []HeaderCheck {
	var out []HeaderCheck
	for _, c := range r.Checks {
		if c.State == StateMissing {
			out = append(out, c)
		}
	}
	return out
}

// MaxScore is the total weight available.
func MaxScore() int {
	total := 0
	for _, sh := range SecurityHeaders {
		total += sh.Weight
	}
	return total
}

// Rating labels a score.
func Rating(earned, total int) string {
	if total == 0 {
		return "Unknown"
	}
	switch ratio := float64(earned) / float64(total); {
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

// Options configures an HTTP inspection.
type Options struct {
	// UseHTTP requests over plaintext instead of TLS.
	UseHTTP bool
	Port    string
	Timeout time.Duration
	// IncludeAll records every response header, not just the checked ones.
	IncludeAll bool
}

// BuildURL assembles the request URL for a target.
func BuildURL(target string, opts Options) string {
	scheme := "https"
	if opts.UseHTTP {
		scheme = "http"
	}
	if opts.Port != "" {
		return fmt.Sprintf("%s://%s:%s", scheme, target, opts.Port)
	}
	return fmt.Sprintf("%s://%s", scheme, target)
}

func client(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

// CheckHeaders fetches the target and evaluates its security headers.
func CheckHeaders(ctx context.Context, target string, opts Options) (*HeadersResult, error) {
	url := BuildURL(target, opts)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client(opts.Timeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Redirects are followed by default, so the headers below can belong to a
	// different origin than the one asked for. Record where they came from.
	finalURL := url
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	res := &HeadersResult{
		Target:      target,
		URL:         url,
		FinalURL:    finalURL,
		Redirected:  finalURL != url,
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		Server:      resp.Header.Get("Server"),
		ContentType: resp.Header.Get("Content-Type"),
		MaxScore:    MaxScore(),
	}

	for _, sh := range SecurityHeaders {
		check := HeaderCheck{Header: sh.Key, Weight: sh.Weight}
		if val := resp.Header.Get(sh.Key); val != "" {
			check.State = StatePresent
			check.Value = val
			res.Score += sh.Weight
		} else {
			check.State = StateMissing
			check.Fix = sh.Fix
		}
		res.Checks = append(res.Checks, check)
	}

	for _, sh := range DeprecatedHeaders {
		if val := resp.Header.Get(sh.Key); val != "" {
			res.Deprecated = append(res.Deprecated, HeaderCheck{
				Header: sh.Key,
				State:  StateDeprecated,
				Value:  val,
				Fix:    sh.Fix,
			})
		}
	}

	res.Rating = Rating(res.Score, res.MaxScore)

	if opts.IncludeAll {
		res.AllHeaders = make(map[string]string, len(resp.Header))
		for key, vals := range resp.Header {
			res.AllHeaders[key] = strings.Join(vals, ", ")
		}
	}
	return res, nil
}
