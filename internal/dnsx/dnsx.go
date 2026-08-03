// Package dnsx queries DNS records and infers the hosting platform behind a
// domain.
package dnsx

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// RcodeError reports a DNS response code other than NOERROR, letting callers
// tell "this name does not exist" apart from "this name has no such records".
type RcodeError struct{ Rcode int }

func (e *RcodeError) Error() string {
	if s, ok := dns.RcodeToString[e.Rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE %d", e.Rcode)
}

// Record is a single DNS answer.
type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

// Section groups the answers for one record type, or the reason there are none.
type Section struct {
	Title   string   `json:"title"`
	Records []Record `json:"records"`
	Error   string   `json:"error,omitempty"`
}

// Result is a complete lookup.
type Result struct {
	Domain   string    `json:"domain"`
	Server   string    `json:"server"`
	Sections []Section `json:"sections"`
	Wildcard string    `json:"wildcard,omitempty"`
	Platform string    `json:"platform,omitempty"`
}

// Resolver queries a single upstream DNS server.
type Resolver struct {
	Server  string
	Timeout time.Duration
}

// NewResolver builds a resolver for server, falling back to the system
// configuration and then to a public resolver.
func NewResolver(server string) *Resolver {
	return &Resolver{Server: serverAddress(server), Timeout: 5 * time.Second}
}

// serverAddress normalises a user-supplied server, or discovers one.
func serverAddress(custom string) string {
	if custom != "" {
		if _, _, err := net.SplitHostPort(custom); err != nil {
			return net.JoinHostPort(custom, "53")
		}
		return custom
	}

	if config, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		for _, srv := range config.Servers {
			// IPv6 link-local entries carry a zone that miekg/dns will not dial.
			if strings.HasPrefix(srv, "fe80") {
				continue
			}
			return net.JoinHostPort(srv, config.Port)
		}
	}
	return "8.8.8.8:53"
}

// query sends one question, retrying over TCP when the UDP answer is truncated.
func (r *Resolver) query(domain string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: r.Timeout}
	resp, _, err := c.Exchange(m, r.Server)
	if err != nil {
		return nil, err
	}

	if resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.Exchange(m, r.Server)
		if err != nil {
			return nil, err
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, &RcodeError{Rcode: resp.Rcode}
	}
	return resp.Answer, nil
}

// lookup runs a query and maps each answer through fn, which reports false for
// record types it does not handle.
func (r *Resolver) lookup(domain string, qtype uint16, fn func(dns.RR) (Record, bool)) ([]Record, error) {
	rrs, err := r.query(domain, qtype)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range rrs {
		if rec, ok := fn(rr); ok {
			records = append(records, rec)
		}
	}
	return records, nil
}

// A returns A and AAAA records together. The two queries are independent, so
// they go out at once rather than costing a round-trip each.
func (r *Resolver) A(domain string) ([]Record, error) {
	var (
		v4, v6        []Record
		errA, errAAAA error
		wg            sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		v4, errA = r.lookup(domain, dns.TypeA, func(rr dns.RR) (Record, bool) {
			a, ok := rr.(*dns.A)
			if !ok {
				return Record{}, false
			}
			return Record{"A", a.A.String(), a.Hdr.Ttl}, true
		})
	}()
	go func() {
		defer wg.Done()
		v6, errAAAA = r.lookup(domain, dns.TypeAAAA, func(rr dns.RR) (Record, bool) {
			aaaa, ok := rr.(*dns.AAAA)
			if !ok {
				return Record{}, false
			}
			return Record{"AAAA", aaaa.AAAA.String(), aaaa.Hdr.Ttl}, true
		})
	}()
	wg.Wait()

	records := append(v4, v6...)
	// Having only one address family is normal, so report a failure only when
	// neither query produced anything.
	if len(records) == 0 {
		if errA != nil {
			return nil, errA
		}
		if errAAAA != nil {
			return nil, errAAAA
		}
	}
	return records, nil
}

// MX returns mail exchanger records.
func (r *Resolver) MX(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeMX, func(rr dns.RR) (Record, bool) {
		mx, ok := rr.(*dns.MX)
		if !ok {
			return Record{}, false
		}
		value := fmt.Sprintf("%s (priority: %d)", trimDot(mx.Mx), mx.Preference)
		return Record{"MX", value, mx.Hdr.Ttl}, true
	})
}

// NS returns nameserver records.
func (r *Resolver) NS(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeNS, func(rr dns.RR) (Record, bool) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			return Record{}, false
		}
		return Record{"NS", trimDot(ns.Ns), ns.Hdr.Ttl}, true
	})
}

// TXT returns text records.
func (r *Resolver) TXT(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeTXT, func(rr dns.RR) (Record, bool) {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			return Record{}, false
		}
		return Record{"TXT", strings.Join(txt.Txt, ""), txt.Hdr.Ttl}, true
	})
}

// CNAME returns canonical name records.
func (r *Resolver) CNAME(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeCNAME, func(rr dns.RR) (Record, bool) {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			return Record{}, false
		}
		return Record{"CNAME", trimDot(cname.Target), cname.Hdr.Ttl}, true
	})
}

// SOA returns the start-of-authority record.
func (r *Resolver) SOA(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeSOA, func(rr dns.RR) (Record, bool) {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			return Record{}, false
		}
		value := fmt.Sprintf("primary: %s | admin: %s | serial: %d | refresh: %ds",
			trimDot(soa.Ns), mailbox(soa.Mbox), soa.Serial, soa.Refresh)
		return Record{"SOA", value, soa.Hdr.Ttl}, true
	})
}

// CAA returns certificate authority authorisation records.
func (r *Resolver) CAA(domain string) ([]Record, error) {
	return r.lookup(domain, dns.TypeCAA, func(rr dns.RR) (Record, bool) {
		caa, ok := rr.(*dns.CAA)
		if !ok {
			return Record{}, false
		}
		value := fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value)
		return Record{"CAA", value, caa.Hdr.Ttl}, true
	})
}

// dkimSelectors are the selector names worth guessing at. There is no way to
// enumerate them, so this is a best-effort list of common defaults.
var dkimSelectors = []string{
	"google", "default", "mail", "k1", "s1", "s2",
	"selector1", "selector2", "dkim", "smtp",
}

// EmailSecurity collects SPF, DMARC and any DKIM keys found at common
// selectors. Every lookup here is a probe whose absence is a valid answer, so
// it never reports an error.
//
// The twelve queries run together. Asked one after another they made this by
// far the slowest section of `sek dns` — ten of them are guesses at DKIM
// selectors that usually do not exist, so the command spent most of its time
// waiting out negative answers in series.
func (r *Resolver) EmailSecurity(domain string) ([]Record, error) {
	names := make([]string, 0, len(dkimSelectors)+2)
	names = append(names, domain, "_dmarc."+domain)
	for _, sel := range dkimSelectors {
		names = append(names, sel+"._domainkey."+domain)
	}

	answers := make([][]Record, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], _ = r.TXT(name)
		}()
	}
	wg.Wait()

	// Answers are read back by index, so the output order stays fixed rather
	// than following whichever query finished first.
	var records []Record
	for _, txt := range answers[0] {
		if strings.HasPrefix(txt.Value, "v=spf1") {
			records = append(records, Record{"SPF", txt.Value, txt.TTL})
		}
	}
	for _, txt := range answers[1] {
		if strings.HasPrefix(txt.Value, "v=DMARC1") {
			records = append(records, Record{"DMARC", txt.Value, txt.TTL})
		}
	}
	for i, sel := range dkimSelectors {
		for _, txt := range answers[i+2] {
			if strings.Contains(txt.Value, "v=DKIM1") {
				records = append(records, Record{"DKIM", fmt.Sprintf("[%s] %s", sel, txt.Value), txt.TTL})
			}
		}
	}

	return records, nil
}

// Reverse resolves an IP address to its PTR names.
func Reverse(ip string) ([]Record, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("not an IP address: %s", ip)
	}
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, n := range names {
		records = append(records, Record{Type: "PTR", Value: trimDot(n)})
	}
	return records, nil
}

// Wildcard returns the address a random subdomain resolves to, or "" when the
// domain has no wildcard record. NXDOMAIN is the expected negative answer.
func (r *Resolver) Wildcard(domain string) string {
	rrs, err := r.query(RandomLabel()+"."+domain, dns.TypeA)
	if err != nil {
		return ""
	}
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// RootDomain returns the registrable domain using the Public Suffix List, so
// multi-label suffixes resolve correctly: shop.example.co.uk yields
// example.co.uk rather than co.uk. Also covers .com.gr and similar.
func RootDomain(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return root
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

// mailbox turns a SOA RNAME into an email address.
func mailbox(mbox string) string {
	m := trimDot(mbox)
	name, domain, ok := strings.Cut(m, ".")
	if !ok {
		return m
	}
	return name + "@" + domain
}
