package dnsx

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
)

// RandomLabel returns a random DNS label, used to probe for wildcard records.
func RandomLabel() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "sek-wildcard-probe"
	}
	return "sek-" + hex.EncodeToString(b)
}

// knownProviders maps hostname keywords to provider names.
var knownProviders = []struct {
	keyword  string
	provider string
}{
	// Global CDN / Security
	{"cloudflare", "Cloudflare"},
	{"awsdns", "Amazon Route 53 (AWS)"},
	{"cloudfront.net", "Amazon CloudFront (AWS)"},
	{"azure-dns", "Azure DNS (Microsoft)"},
	{"googledomains", "Google Cloud DNS"},
	{"google", "Google Cloud DNS"},
	{"sucuri", "Sucuri WAF"},
	{"incapsula", "Imperva Incapsula"},
	{"akamai", "Akamai"},
	{"fastly", "Fastly CDN"},
	{"stackpath", "StackPath CDN"},
	{"cdn77", "CDN77"},
	{"ovh", "OVH"},
	{"hetzner", "Hetzner"},
	{"digitalocean", "DigitalOcean"},
	// Greek / Cyprus providers
	{"fastpath", "Fastpath (GR)"},
	{"papaki", "Papaki (GR)"},
	{"tophost", "Top.Host (GR)"},
	{"top.host", "Top.Host (GR)"},
	{"forthnet", "Forthnet (GR)"},
	{"otenet", "OTEnet / Cosmote (GR)"},
	{"cosmote", "Cosmote (GR)"},
	{"hol.gr", "Hol (GR)"},
	{"wind.gr", "Wind Hellas (GR)"},
	{"cyta", "Cyta (CY)"},
	{"cytanet", "Cyta (CY)"},
	{"hosting.gr", "Hosting.gr (GR)"},
}

// providerRange ties a published network range to the operator that owns it.
type providerRange struct {
	net      netip.Prefix
	provider string
}

// providerCIDRs are the ranges checked when nothing else identifies a host.
//
// They are matched as real CIDRs rather than as leading-digit strings. The
// string form silently omitted whole blocks — 104.16.0.0/13 spans 104.16
// through 104.23, but only 104.16-104.21 were listed, so Cloudflare-fronted
// sites on 104.22.x and 104.23.x came back as "Custom / Unknown".
var providerCIDRs = parseRanges(map[string]string{
	// Cloudflare — official IPv4 list from cloudflare.com/ips-v4
	"103.21.244.0/22":  "Cloudflare",
	"103.22.200.0/22":  "Cloudflare",
	"103.31.4.0/22":    "Cloudflare",
	"104.16.0.0/13":    "Cloudflare",
	"104.24.0.0/14":    "Cloudflare",
	"108.162.192.0/18": "Cloudflare",
	"131.0.72.0/22":    "Cloudflare",
	"141.101.64.0/18":  "Cloudflare",
	"162.158.0.0/15":   "Cloudflare",
	"172.64.0.0/13":    "Cloudflare",
	"173.245.48.0/20":  "Cloudflare",
	"188.114.96.0/20":  "Cloudflare",
	"190.93.240.0/20":  "Cloudflare",
	"197.234.240.0/22": "Cloudflare",
	"198.41.128.0/17":  "Cloudflare",
	// Cloudflare — official IPv6 list from cloudflare.com/ips-v6
	"2400:cb00::/32": "Cloudflare",
	"2405:8100::/32": "Cloudflare",
	"2405:b500::/32": "Cloudflare",
	"2606:4700::/32": "Cloudflare",
	"2803:f800::/32": "Cloudflare",
	"2a06:98c0::/29": "Cloudflare",
	"2c0f:f248::/32": "Cloudflare",
})

// parseRanges builds the lookup table at init. The input is a compile-time
// constant, so a malformed prefix is a programming error, not a runtime one.
//
// Ranges are sorted most-specific first so a narrow entry always wins over a
// broader one containing it, and so the answer never depends on Go's
// randomised map iteration order.
func parseRanges(table map[string]string) []providerRange {
	out := make([]providerRange, 0, len(table))
	for cidr, provider := range table {
		out = append(out, providerRange{netip.MustParsePrefix(cidr), provider})
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].net.Bits(), out[j].net.Bits(); a != b {
			return a > b
		}
		return out[i].net.String() < out[j].net.String()
	})
	return out
}

// providerForIP returns the provider owning an address, or "".
func providerForIP(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	for _, p := range providerCIDRs {
		if p.net.Contains(ip) {
			return p.provider
		}
	}
	return ""
}

// matchProvider finds the provider whose keyword appears in host.
func matchProvider(host string) string {
	h := strings.ToLower(host)
	for _, p := range knownProviders {
		if strings.Contains(h, p.keyword) {
			return p.provider
		}
	}
	return ""
}

// Known holds records a caller has already looked up, so platform detection
// does not repeat queries the caller just made. A nil field means "not
// fetched"; detection queries for it itself.
type Known struct {
	NS    []Record
	CNAME []Record
	A     []Record
}

// DetectPlatform infers the hosting or CDN provider, checking nameservers
// first, then the registrable domain's nameservers, then CNAME targets, and
// finally the address ranges.
//
// Records already in known are reused rather than queried again; pass nil to
// have every lookup run. `sek dns` without -t asks for NS, CNAME and A anyway,
// and repeating them here cost three extra round-trips on every run.
func (r *Resolver) DetectPlatform(domain string, known *Known) string {
	if known == nil {
		known = &Known{}
	}

	if p := matchAny(r.records(known.NS, domain, (*Resolver).NS)); p != "" {
		return p
	}
	// The registrable domain is only worth a second query when it differs.
	if root := RootDomain(domain); root != domain {
		ns, _ := r.NS(root)
		if p := matchAny(ns); p != "" {
			return p
		}
	}
	if p := matchAny(r.records(known.CNAME, domain, (*Resolver).CNAME)); p != "" {
		return p
	}

	for _, rec := range r.records(known.A, domain, (*Resolver).A) {
		if p := providerForIP(rec.Value); p != "" {
			return p
		}
	}
	return ""
}

// records returns cached if the caller supplied it, otherwise runs the lookup.
func (r *Resolver) records(cached []Record, domain string, lookup func(*Resolver, string) ([]Record, error)) []Record {
	if cached != nil {
		return cached
	}
	out, _ := lookup(r, domain)
	return out
}

// matchAny returns the first provider named by any record value.
func matchAny(records []Record) string {
	for _, rec := range records {
		if p := matchProvider(rec.Value); p != "" {
			return p
		}
	}
	return ""
}
