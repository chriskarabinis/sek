package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// flags
var certDomain   string
var certPort     string
var certInsecure bool
var certChain    bool

// tlsVersionName converts TLS version uint16 to readable string
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

// expiryStatus returns a status label based on days remaining
func expiryStatus(daysLeft int) string {
	switch {
	case daysLeft < 0:
		return "[EXPIRED]"
	case daysLeft <= 14:
		return "[EXPIRING SOON]"
	case daysLeft <= 30:
		return "[EXPIRING SOON]"
	default:
		return "[OK]"
	}
}

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "SSL/TLS certificate info",
	Long:  `Inspect SSL/TLS certificates for a domain — expiry, issuer, SANs, TLS version, and cipher suite.`,
	Run: func(cmd *cobra.Command, args []string) {
		if certDomain == "" {
			fmt.Println("Error: domain is required. Use -d <domain>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		address := certDomain + ":" + certPort

		// Show port in header only if non-default
		label := certDomain
		if certPort != "443" {
			label = address
		}
		header := fmt.Sprintf("\n[*] SSL/TLS Certificate for: %s\n", label)
		WriteLineColored(yellow+header+reset, header)

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: certInsecure,
			ServerName:         certDomain,
		})
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Connection failed: %s\n", err))
			os.Exit(1)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		certs := state.PeerCertificates

		if len(certs) == 0 {
			WriteLine("[!] No certificates returned by server.")
			os.Exit(1)
		}

		cert := certs[0] // leaf certificate

		// --- Certificate details ---
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		status := expiryStatus(daysLeft)

		WriteLine("[*] Certificate")

		fields := []struct{ label, value string }{
			{"Subject", cert.Subject.CommonName},
			{"Issuer", cert.Issuer.CommonName},
			{"Org", strings.Join(cert.Issuer.Organization, ", ")},
			{"Valid From", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC")},
			{"Valid To", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC")},
			{"Days Left", fmt.Sprintf("%d days  %s", daysLeft, status)},
			{"Serial", fmt.Sprintf("%X", cert.SerialNumber)},
		}

		for _, f := range fields {
			plain := fmt.Sprintf("  %-12s  %s", f.label, f.value)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		// --- Subject Alternative Names (SANs) ---
		WriteLine("[*] Subject Alternative Names (SANs)")
		if len(cert.DNSNames) == 0 {
			WriteLine("  None found.")
		} else {
			for _, san := range cert.DNSNames {
				plain := fmt.Sprintf("  %s", san)
				WriteLineColored(yellow+plain+reset, plain)
			}
		}
		WriteLine("")

		// --- TLS connection info ---
		WriteLine("[*] TLS")
		tlsFields := []struct{ label, value string }{
			{"Version", tlsVersionName(state.Version)},
			{"Cipher", tls.CipherSuiteName(state.CipherSuite)},
		}
		for _, f := range tlsFields {
			plain := fmt.Sprintf("  %-12s  %s", f.label, f.value)
			WriteLineColored(yellow+plain+reset, plain)
		}
		WriteLine("")

		// --- Certificate chain ---
		if certChain {
			WriteLine("[*] Certificate Chain")
			for i, c := range certs {
				role := "intermediate"
				if i == 0 {
					role = "leaf"
				} else if i == len(certs)-1 {
					role = "root"
				}
				plain := fmt.Sprintf("  [%d] %s  (%s)", i, c.Subject.CommonName, role)
				WriteLineColored(yellow+plain+reset, plain)
			}
			WriteLine("")
		}
	},
}

func init() {
	certCmd.Flags().StringVarP(&certDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	certCmd.Flags().StringVarP(&certPort, "port", "p", "443", "Port to connect to (default: 443)")
	certCmd.Flags().BoolVar(&certInsecure, "insecure", false, "Skip certificate verification (for self-signed certs)")
	certCmd.Flags().BoolVarP(&certChain, "chain", "c", false, "Show full certificate chain")
	rootCmd.AddCommand(certCmd)
}