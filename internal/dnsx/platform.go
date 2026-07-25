package dnsx

import (
	"crypto/rand"
	"encoding/hex"
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

// ipProviders maps IP prefixes to provider names, from the operators' own
// published ranges.
var ipProviders = []struct {
	prefix   string
	provider string
}{
	// Cloudflare — official ranges from cloudflare.com/ips
	{"103.21.244.", "Cloudflare"}, {"103.22.200.", "Cloudflare"}, {"103.31.4.", "Cloudflare"},
	{"104.16.", "Cloudflare"}, {"104.17.", "Cloudflare"}, {"104.18.", "Cloudflare"},
	{"104.19.", "Cloudflare"}, {"104.20.", "Cloudflare"}, {"104.21.", "Cloudflare"},
	{"104.24.", "Cloudflare"}, {"104.25.", "Cloudflare"}, {"104.26.", "Cloudflare"},
	{"108.162.", "Cloudflare"}, {"141.101.", "Cloudflare"},
	{"162.158.", "Cloudflare"}, {"162.159.", "Cloudflare"},
	{"172.64.", "Cloudflare"}, {"172.65.", "Cloudflare"},
	{"172.66.", "Cloudflare"}, {"172.67.", "Cloudflare"},
	{"173.245.", "Cloudflare"}, {"188.114.", "Cloudflare"},
	{"190.93.", "Cloudflare"}, {"197.234.", "Cloudflare"}, {"198.41.", "Cloudflare"},
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

// DetectPlatform infers the hosting or CDN provider, checking nameservers
// first, then the registrable domain's nameservers, then CNAME targets, and
// finally the address ranges.
func (r *Resolver) DetectPlatform(domain string) string {
	if p := r.platformFromNS(domain); p != "" {
		return p
	}
	if root := RootDomain(domain); root != domain {
		if p := r.platformFromNS(root); p != "" {
			return p
		}
	}

	cnames, _ := r.CNAME(domain)
	for _, rec := range cnames {
		if p := matchProvider(rec.Value); p != "" {
			return p
		}
	}

	addrs, _ := r.A(domain)
	for _, rec := range addrs {
		for _, p := range ipProviders {
			if strings.HasPrefix(rec.Value, p.prefix) {
				return p.provider
			}
		}
	}
	return ""
}

func (r *Resolver) platformFromNS(domain string) string {
	ns, _ := r.NS(domain)
	for _, rec := range ns {
		if p := matchProvider(rec.Value); p != "" {
			return p
		}
	}
	return ""
}
