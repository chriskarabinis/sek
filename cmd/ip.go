package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// flags
var ipTarget string

type ipAPIResponse struct {
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

func queryIPAPI(ip string) (*ipAPIResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "IP geolocation lookup",
	Long:  `Look up geolocation, ISP, ASN, and network info for an IP address or domain.`,
	Run: func(cmd *cobra.Command, args []string) {
		if ipTarget == "" {
			fmt.Println("Error: target is required. Use -d <domain or IP>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		// Resolve domain to IP if needed
		ip := ipTarget
		if net.ParseIP(ipTarget) == nil {
			ips, err := net.LookupHost(ipTarget)
			if err != nil || len(ips) == 0 {
				WriteLine(fmt.Sprintf("[!] Cannot resolve: %s\n", ipTarget))
				os.Exit(1)
			}
			// Prefer IPv4
			for _, addr := range ips {
				if net.ParseIP(addr).To4() != nil {
					ip = addr
					break
				}
			}
			if ip == ipTarget {
				ip = ips[0]
			}
		}

		header := fmt.Sprintf("\n[*] IP Lookup for: %s\n", ipTarget)
		WriteLineColored(yellow+header+reset, header)

		data, err := queryIPAPI(ip)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Lookup failed: %s\n", err))
			os.Exit(1)
		}

		if data.Status != "success" {
			WriteLine(fmt.Sprintf("[!] %s\n", data.Message))
			os.Exit(1)
		}

		fields := []struct{ label, value string }{
			{"IP", data.Query},
			{"Country", fmt.Sprintf("%s (%s)", data.Country, data.CountryCode)},
			{"Region", data.RegionName},
			{"City", data.City},
			{"ZIP", data.Zip},
			{"Coordinates", fmt.Sprintf("%.4f, %.4f", data.Lat, data.Lon)},
			{"Timezone", data.Timezone},
			{"ISP", data.ISP},
			{"Organization", data.Org},
			{"ASN", data.AS},
		}

		for _, f := range fields {
			if f.value == "" || f.value == " ()" {
				continue
			}
			plain := fmt.Sprintf("  %-14s  %s", f.label, f.value)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")
	},
}

func init() {
	ipCmd.Flags().StringVarP(&ipTarget, "domain", "d", "", "Target IP or domain (e.g. 8.8.8.8 or example.com)")
	rootCmd.AddCommand(ipCmd)
}
