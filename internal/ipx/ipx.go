// Package ipx looks up geolocation and network ownership for an IP or host.
package ipx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/chriskarabinis/sek/internal/netx"
)

// endpoint is the free ip-api.com service (45 requests/min, no key). It offers
// no HTTPS on the free tier, so lookups are visible to anything on the path.
// A var rather than a const so tests can point it at a local server.
var endpoint = "http://ip-api.com/json/"

// Result is the resolved network information for a target.
type Result struct {
	Target       string  `json:"target"`
	IP           string  `json:"ip"`
	Country      string  `json:"country,omitempty"`
	CountryCode  string  `json:"country_code,omitempty"`
	Region       string  `json:"region,omitempty"`
	City         string  `json:"city,omitempty"`
	Zip          string  `json:"zip,omitempty"`
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`
	Timezone     string  `json:"timezone,omitempty"`
	ISP          string  `json:"isp,omitempty"`
	Organization string  `json:"organization,omitempty"`
	ASN          string  `json:"asn,omitempty"`
}

type apiResponse struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
}

// Lookup resolves target to an address if needed, then queries the geolocation
// service for it.
func Lookup(ctx context.Context, target string) (*Result, error) {
	ip, err := netx.ResolveIP(ctx, target)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup failed: HTTP %d", resp.StatusCode)
	}

	var data apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	if data.Status != "success" {
		// The service does not always send a message with a failure, and an
		// error whose text is empty prints as a bare "[!]".
		if data.Message == "" {
			return nil, fmt.Errorf("lookup failed for %s", ip)
		}
		return nil, fmt.Errorf("lookup failed for %s: %s", ip, data.Message)
	}

	return &Result{
		Target:       target,
		IP:           data.Query,
		Country:      data.Country,
		CountryCode:  data.CountryCode,
		Region:       data.RegionName,
		City:         data.City,
		Zip:          data.Zip,
		Latitude:     data.Lat,
		Longitude:    data.Lon,
		Timezone:     data.Timezone,
		ISP:          data.ISP,
		Organization: data.Org,
		ASN:          data.AS,
	}, nil
}
