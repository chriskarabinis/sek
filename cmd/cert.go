package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/certx"
	"github.com/chriskarabinis/sek/internal/output"
)

var (
	certDomain     string
	certPort       string
	certInsecure   bool
	certChain      bool
	certExpiryDays int
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "SSL/TLS certificate info",
	Long: `Inspect SSL/TLS certificates for a domain — expiry, issuer, SANs, TLS version, and cipher suite.

With --expiry-days, exit non-zero when the certificate expires within that many
days, which makes the command usable as a monitoring check.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ctx, stop := commandContext()
		defer stop()

		res, err := certx.Inspect(ctx, certDomain, certx.Options{
			Port:     certPort,
			Insecure: certInsecure,
		})
		if err != nil {
			return err
		}

		if w.IsJSON() {
			if err := w.JSON(res); err != nil {
				return err
			}
		} else {
			renderCert(w, res)
		}

		// Signal expiry through the exit code so cron and CI can act on it.
		if certExpiryDays > 0 && res.ExpiresWithin(certExpiryDays) {
			// Report the date rather than a day count: one that lapsed in the
			// last 24 hours rounds to zero and would read as "expired 0 days ago".
			if res.Expired() {
				return fmt.Errorf("certificate for %s expired on %s",
					res.Host, res.NotAfter.Format("2006-01-02 15:04:05 UTC"))
			}
			return fmt.Errorf("certificate for %s expires in %d days", res.Host, res.DaysLeft)
		}
		return nil
	},
}

func renderCert(w *output.Writer, res *certx.Result) {
	label := res.Host
	if res.Port != "443" {
		label = fmt.Sprintf("%s:%s", res.Host, res.Port)
	}
	w.Header("SSL/TLS Certificate for: %s", label)

	w.Section("Certificate")
	w.Field(12, "Subject", res.Subject)
	w.Field(12, "Issuer", res.Issuer)
	w.Field(12, "Org", res.IssuerOrg)
	w.Field(12, "Valid From", res.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	w.Field(12, "Valid To", res.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	w.Field(12, "Days Left", fmt.Sprintf("%d days  [%s]", res.DaysLeft, res.Status))
	w.Field(12, "Serial", res.Serial)
	w.Blank()

	w.Section("Subject Alternative Names (SANs)")
	if len(res.DNSNames) == 0 {
		w.Note("None found.")
	} else {
		for _, san := range res.DNSNames {
			w.Highlightf("  %s", san)
		}
	}
	w.Blank()

	w.Section("TLS")
	w.Field(12, "Version", res.TLSVersion)
	w.Field(12, "Cipher", res.Cipher)
	w.Blank()

	if certChain {
		w.Section("Certificate Chain")
		for _, c := range res.Chain {
			w.Highlightf("  [%d] %s  (%s)", c.Index, c.Subject, c.Role)
		}
		w.Blank()
	}
}

func init() {
	certCmd.Flags().StringVarP(&certDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	certCmd.Flags().StringVarP(&certPort, "port", "p", "443", "Port to connect to")
	certCmd.Flags().BoolVar(&certInsecure, "insecure", false, "Skip certificate verification (for self-signed certs)")
	certCmd.Flags().BoolVarP(&certChain, "chain", "c", false, "Show full certificate chain")
	certCmd.Flags().IntVar(&certExpiryDays, "expiry-days", 0, "Exit non-zero if the certificate expires within this many days")
	certCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(certCmd)
}
