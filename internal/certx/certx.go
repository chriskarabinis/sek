// Package certx inspects the TLS certificate and connection parameters a host
// presents.
package certx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Status labels for how close a certificate is to expiry.
const (
	StatusOK        = "OK"
	StatusExpiring  = "EXPIRING SOON"
	StatusCritical  = "CRITICAL"
	StatusExpired   = "EXPIRED"
	criticalDays    = 14
	expiringSoonDay = 30
)

// ChainEntry is one certificate in the presented chain.
type ChainEntry struct {
	Index   int    `json:"index"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Role    string `json:"role"`
}

// Result describes a host's certificate and negotiated TLS parameters.
type Result struct {
	Host       string       `json:"host"`
	Port       string       `json:"port"`
	Subject    string       `json:"subject"`
	Issuer     string       `json:"issuer"`
	IssuerOrg  string       `json:"issuer_org,omitempty"`
	NotBefore  time.Time    `json:"not_before"`
	NotAfter   time.Time    `json:"not_after"`
	DaysLeft   int          `json:"days_left"`
	Status     string       `json:"status"`
	Serial     string       `json:"serial"`
	DNSNames   []string     `json:"dns_names,omitempty"`
	TLSVersion string       `json:"tls_version"`
	Cipher     string       `json:"cipher"`
	Chain      []ChainEntry `json:"chain,omitempty"`
}

// Options controls how the connection is made.
type Options struct {
	Port string
	// Insecure skips verification, needed to inspect self-signed certificates.
	Insecure bool
	Timeout  time.Duration
}

// Expired reports whether the certificate is past its validity window.
func (r *Result) Expired() bool { return r.DaysLeft < 0 }

// ExpiresWithin reports whether the certificate expires in at most days.
func (r *Result) ExpiresWithin(days int) bool { return r.DaysLeft <= days }

// expiryStatus maps days remaining onto a status label. The critical band is
// distinct from the 30-day band so a certificate about to lapse is visibly
// different from one merely approaching renewal.
func expiryStatus(daysLeft int) string {
	switch {
	case daysLeft < 0:
		return StatusExpired
	case daysLeft <= criticalDays:
		return StatusCritical
	case daysLeft <= expiringSoonDay:
		return StatusExpiring
	default:
		return StatusOK
	}
}

// tlsVersionName renders a TLS version constant.
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

// chainRole labels a certificate's position in the presented chain.
func chainRole(index, total int) string {
	switch {
	case index == 0:
		return "leaf"
	case index == total-1:
		return "root"
	default:
		return "intermediate"
	}
}

// Inspect connects to host and reports its certificate.
func Inspect(ctx context.Context, host string, opts Options) (*Result, error) {
	if opts.Port == "" {
		opts.Port = "443"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	// tls.Dialer rather than tls.DialWithDialer: only the former honours ctx, so
	// Ctrl+C during a hung handshake actually stops the command.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: opts.Timeout},
		Config:    &tls.Config{InsecureSkipVerify: opts.Insecure, ServerName: host},
	}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, opts.Port))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer raw.Close()

	conn, ok := raw.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("unexpected connection type %T", raw)
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates returned by server")
	}
	return build(host, opts.Port, state), nil
}

func build(host, port string, state tls.ConnectionState) *Result {
	leaf := state.PeerCertificates[0]
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	res := &Result{
		Host:       host,
		Port:       port,
		Subject:    leaf.Subject.CommonName,
		Issuer:     leaf.Issuer.CommonName,
		IssuerOrg:  strings.Join(leaf.Issuer.Organization, ", "),
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		DaysLeft:   daysLeft,
		Status:     expiryStatus(daysLeft),
		Serial:     fmt.Sprintf("%X", leaf.SerialNumber),
		DNSNames:   leaf.DNSNames,
		TLSVersion: tlsVersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
	}

	for i, c := range state.PeerCertificates {
		res.Chain = append(res.Chain, ChainEntry{
			Index:   i,
			Subject: certName(c),
			Issuer:  c.Issuer.CommonName,
			Role:    chainRole(i, len(state.PeerCertificates)),
		})
	}
	return res
}

// certName falls back to the first SAN when a certificate carries no common
// name, which is increasingly normal for modern issuers.
func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return c.Subject.String()
}
