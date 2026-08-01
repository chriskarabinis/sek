package webx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// bodyLimit caps how much markup is inspected. Signatures live in the head and
// early body, so reading further only costs memory.
const bodyLimit = 512 * 1024

// Signature matches one technology by response header, cookie name, or markup.
type Signature struct {
	Name     string
	Category string
	// Header matches when present; HeaderVal, if set, must appear in its value.
	Header    string
	HeaderVal string
	// Cookie matches on a cookie name.
	Cookie string
	// Body matches when any of these substrings appears in the markup.
	Body []string
}

// Categories in display order.
var Categories = []string{
	"Web Server", "Language", "CMS", "JS Framework", "JS Library", "Analytics", "CDN / Security",
}

// Signatures covers servers, languages, CMS, JS frameworks, analytics and CDNs.
//
// Markup patterns are deliberately asset-shaped ("jquery.js", "/jquery-")
// rather than bare product names: matching on "bootstrap" or "jquery" anywhere
// in the page flags any article that merely mentions them.
var Signatures = []Signature{
	// Web Server
	{Name: "nginx", Category: "Web Server", Header: "Server", HeaderVal: "nginx"},
	{Name: "Apache", Category: "Web Server", Header: "Server", HeaderVal: "apache"},
	{Name: "Microsoft IIS", Category: "Web Server", Header: "Server", HeaderVal: "microsoft-iis"},
	{Name: "LiteSpeed", Category: "Web Server", Header: "Server", HeaderVal: "litespeed"},
	{Name: "Caddy", Category: "Web Server", Header: "Server", HeaderVal: "caddy"},
	{Name: "OpenResty", Category: "Web Server", Header: "Server", HeaderVal: "openresty"},

	// Language / Runtime
	{Name: "PHP", Category: "Language", Header: "X-Powered-By", HeaderVal: "php"},
	{Name: "PHP", Category: "Language", Cookie: "PHPSESSID"},
	{Name: "ASP.NET", Category: "Language", Header: "X-Powered-By", HeaderVal: "asp.net"},
	{Name: "ASP.NET", Category: "Language", Header: "X-AspNet-Version"},
	{Name: "ASP.NET", Category: "Language", Cookie: "ASP.NET_SessionId"},
	{Name: "Node.js / Express", Category: "Language", Header: "X-Powered-By", HeaderVal: "express"},
	{Name: "Java", Category: "Language", Cookie: "JSESSIONID"},
	{Name: "Python", Category: "Language", Header: "X-Powered-By", HeaderVal: "python"},

	// CMS
	{Name: "WordPress", Category: "CMS", Body: []string{"/wp-content/", "/wp-includes/", `content="wordpress`}},
	{Name: "Joomla", Category: "CMS", Body: []string{`content="joomla`, "/components/com_", "/media/jui/"}},
	{Name: "Drupal", Category: "CMS", Header: "X-Generator", HeaderVal: "drupal"},
	{Name: "Drupal", Category: "CMS", Body: []string{"drupal.settings", "/sites/default/files/", "drupal-settings-json"}},
	{Name: "Magento", Category: "CMS", Body: []string{"mage.cookies", "/static/version", "magento_"}},
	{Name: "Shopify", Category: "CMS", Body: []string{"cdn.shopify.com", "shopify-features"}},
	{Name: "Wix", Category: "CMS", Body: []string{"wixsite.com", "static.parastorage.com"}},
	{Name: "Squarespace", Category: "CMS", Body: []string{"static.squarespace.com", "squarespace-headers"}},
	{Name: "Ghost", Category: "CMS", Body: []string{`content="ghost`, "/ghost/api/"}},
	{Name: "PrestaShop", Category: "CMS", Body: []string{"/modules/ps_", "prestashop"}},
	{Name: "TYPO3", Category: "CMS", Body: []string{"typo3conf", "typo3temp"}},
	{Name: "HubSpot CMS", Category: "CMS", Body: []string{"hubspot.com/hs-fs", "hs-scripts.com"}},
	{Name: "Webflow", Category: "CMS", Body: []string{"assets.website-files.com", `content="webflow`}},

	// JS Framework
	{Name: "React", Category: "JS Framework", Body: []string{"data-reactroot", "__reactcontainer", "react-dom"}},
	{Name: "Next.js", Category: "JS Framework", Body: []string{"__next_data__", "/_next/static/"}},
	{Name: "Vue", Category: "JS Framework", Body: []string{"__vue__", "vue.min.js", "data-v-app"}},
	{Name: "Nuxt", Category: "JS Framework", Body: []string{"__nuxt", "/_nuxt/"}},
	{Name: "Angular", Category: "JS Framework", Body: []string{"ng-version", "ng-app", "angular.min.js"}},
	{Name: "Svelte", Category: "JS Framework", Body: []string{"__svelte", "svelte-"}},
	{Name: "Ember", Category: "JS Framework", Body: []string{"ember-application", "ember.min.js"}},

	// JS Library
	{Name: "jQuery", Category: "JS Library", Body: []string{"jquery.js", "jquery.min.js", "/jquery-", "libs/jquery"}},
	{Name: "Bootstrap", Category: "JS Library", Body: []string{"bootstrap.css", "bootstrap.min.css", "bootstrap.min.js", "bootstrap.bundle"}},
	{Name: "Tailwind CSS", Category: "JS Library", Body: []string{"tailwind.css", "tailwind.min.css", "cdn.tailwindcss.com"}},
	{Name: "Font Awesome", Category: "JS Library", Body: []string{"font-awesome.css", "fontawesome.com", "fa-solid"}},
	{Name: "GSAP", Category: "JS Library", Body: []string{"gsap.min.js", "gsap.js", "tweenmax"}},

	// Analytics
	{Name: "Google Analytics", Category: "Analytics", Body: []string{"google-analytics.com", "gtag(", "googletagmanager.com/gtag"}},
	{Name: "Google Tag Manager", Category: "Analytics", Body: []string{"googletagmanager.com/gtm", "gtm-"}},
	{Name: "Hotjar", Category: "Analytics", Body: []string{"static.hotjar.com", "hotjar.com/c/hotjar"}},
	{Name: "Facebook Pixel", Category: "Analytics", Body: []string{"fbevents.js", "connect.facebook.net"}},
	{Name: "Plausible", Category: "Analytics", Body: []string{"plausible.io/js"}},
	{Name: "Matomo", Category: "Analytics", Body: []string{"matomo.js", "piwik.js"}},
	{Name: "Clarity", Category: "Analytics", Body: []string{"clarity.ms"}},

	// CDN / Security
	{Name: "Cloudflare", Category: "CDN / Security", Header: "CF-Ray"},
	{Name: "Fastly", Category: "CDN / Security", Header: "X-Served-By"},
	{Name: "Akamai", Category: "CDN / Security", Header: "X-Check-Cacheable"},
	{Name: "Sucuri WAF", Category: "CDN / Security", Header: "X-Sucuri-ID"},
	{Name: "Imperva", Category: "CDN / Security", Cookie: "visid_incap"},
}

// Technology is one detected product.
type Technology struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version,omitempty"`
}

// TechResult is a completed fingerprint.
type TechResult struct {
	Target       string       `json:"target"`
	URL          string       `json:"url"`
	StatusCode   int          `json:"status_code"`
	Technologies []Technology `json:"technologies"`
}

// ByCategory groups the detected technologies for display.
func (r *TechResult) ByCategory() map[string][]Technology {
	out := make(map[string][]Technology)
	for _, t := range r.Technologies {
		out[t.Category] = append(out[t.Category], t)
	}
	return out
}

// versionPattern pulls a version out of a header value such as "nginx/1.18.0".
var versionPattern = regexp.MustCompile(`/(\d+(?:\.\d+)+)`)

// Fingerprint fetches the target and matches it against the signature set.
func Fingerprint(ctx context.Context, target string, opts Options) (*TechResult, error) {
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

	raw, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w", err)
	}
	body := strings.ToLower(string(raw))

	cookies := make(map[string]bool)
	for _, c := range resp.Cookies() {
		cookies[strings.ToLower(c.Name)] = true
	}

	res := &TechResult{Target: target, URL: url, StatusCode: resp.StatusCode}

	// Keep the strongest version found per product; a signature can match
	// several ways and only the header carries a version.
	found := make(map[string]Technology)
	for _, sig := range Signatures {
		version, ok := match(sig, resp.Header, cookies, body)
		if !ok {
			continue
		}
		key := sig.Category + "\x00" + sig.Name
		if existing, seen := found[key]; seen && existing.Version != "" {
			continue
		}
		found[key] = Technology{Name: sig.Name, Category: sig.Category, Version: version}
	}

	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Technologies = append(res.Technologies, found[k])
	}
	return res, nil
}

// match reports whether a signature fires, along with any version it revealed.
func match(sig Signature, header http.Header, cookies map[string]bool, body string) (string, bool) {
	if sig.Header != "" {
		if val := header.Get(sig.Header); val != "" {
			lower := strings.ToLower(val)
			if sig.HeaderVal == "" || strings.Contains(lower, sig.HeaderVal) {
				if m := versionPattern.FindStringSubmatch(val); len(m) == 2 {
					return m[1], true
				}
				return "", true
			}
		}
	}

	if sig.Cookie != "" && cookies[strings.ToLower(sig.Cookie)] {
		return "", true
	}

	// body is already lower-cased by Fingerprint and every Body pattern in the
	// table is written lower-case (TestSignaturePatternsAreLowercase enforces
	// it), so there is nothing to fold here.
	for _, pattern := range sig.Body {
		if strings.Contains(body, pattern) {
			return "", true
		}
	}
	return "", false
}
