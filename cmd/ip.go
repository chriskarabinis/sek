package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/ipx"
	"github.com/chriskarabinis/sek/internal/output"
)

var ipTarget string

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "IP geolocation lookup",
	Long:  `Look up geolocation, ISP, ASN, and network info for an IP address or domain.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ctx, stop := commandContext()
		defer stop()

		res, err := ipx.Lookup(ctx, ipTarget)
		if err != nil {
			return err
		}

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderIP(w, res)
		return nil
	},
}

func renderIP(w *output.Writer, res *ipx.Result) {
	w.Header("IP Lookup for: %s", res.Target)

	country := res.Country
	if res.CountryCode != "" {
		country = fmt.Sprintf("%s (%s)", res.Country, res.CountryCode)
	}

	// Formatted coordinates are never the empty string, so an address the
	// service has no fix for used to be shown as a confident "0.0000, 0.0000"
	// off the coast of Africa. Leave the row out instead.
	coordinates := ""
	if res.Latitude != 0 || res.Longitude != 0 {
		coordinates = fmt.Sprintf("%.4f, %.4f", res.Latitude, res.Longitude)
	}

	for _, f := range []struct{ label, value string }{
		{"IP", res.IP},
		{"Country", country},
		{"Region", res.Region},
		{"City", res.City},
		{"ZIP", res.Zip},
		{"Coordinates", coordinates},
		{"Timezone", res.Timezone},
		{"ISP", res.ISP},
		{"Organization", res.Organization},
		{"ASN", res.ASN},
	} {
		if f.value == "" {
			continue
		}
		w.Field(14, f.label, f.value)
	}
	w.Blank()
}

func init() {
	ipCmd.Flags().StringVarP(&ipTarget, "domain", "d", "", "Target IP or domain (e.g. 8.8.8.8 or example.com)")
	ipCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(ipCmd)
}
