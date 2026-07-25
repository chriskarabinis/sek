package certx

import (
	"crypto/tls"
	"testing"
)

// TestExpiryStatus pins the boundaries. The 14-day branch used to return the
// same label as the 30-day one, which made it unreachable in practice.
func TestExpiryStatus(t *testing.T) {
	tests := []struct {
		name     string
		daysLeft int
		want     string
	}{
		{"long past", -100, StatusExpired},
		{"just expired", -1, StatusExpired},
		{"expires today", 0, StatusCritical},
		{"critical upper bound", 14, StatusCritical},
		{"just past critical", 15, StatusExpiring},
		{"expiring upper bound", 30, StatusExpiring},
		{"just past expiring", 31, StatusOK},
		{"healthy", 90, StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expiryStatus(tt.daysLeft); got != tt.want {
				t.Errorf("expiryStatus(%d) = %q, want %q", tt.daysLeft, got, tt.want)
			}
		})
	}
}

// TestExpiryStatusBandsAreDistinct guards the specific defect: two branches
// returning the same string.
func TestExpiryStatusBandsAreDistinct(t *testing.T) {
	critical := expiryStatus(10)
	expiring := expiryStatus(20)
	if critical == expiring {
		t.Errorf("the 14-day and 30-day bands both report %q; they must differ", critical)
	}
}

func TestExpiresWithin(t *testing.T) {
	tests := []struct {
		name      string
		daysLeft  int
		threshold int
		want      bool
	}{
		{"well inside", 5, 30, true},
		{"on the boundary", 30, 30, true},
		{"outside", 31, 30, false},
		{"already expired", -3, 30, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &Result{DaysLeft: tt.daysLeft}
			if got := res.ExpiresWithin(tt.threshold); got != tt.want {
				t.Errorf("ExpiresWithin(%d) with %d days left = %v, want %v",
					tt.threshold, tt.daysLeft, got, tt.want)
			}
		})
	}
}

func TestExpired(t *testing.T) {
	if (&Result{DaysLeft: -1}).Expired() != true {
		t.Error("Expired() = false for a certificate past its validity")
	}
	if (&Result{DaysLeft: 0}).Expired() != false {
		t.Error("Expired() = true for a certificate expiring today")
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tlsVersionName(tt.version); got != tt.want {
				t.Errorf("tlsVersionName(%#x) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}

	if got := tlsVersionName(0x9999); got == "" {
		t.Error("tlsVersionName() for an unknown version returned an empty string")
	}
}

func TestChainRole(t *testing.T) {
	tests := []struct {
		name  string
		index int
		total int
		want  string
	}{
		{"leaf of a full chain", 0, 3, "leaf"},
		{"intermediate", 1, 3, "intermediate"},
		{"root", 2, 3, "root"},
		{"single certificate is a leaf", 0, 1, "leaf"},
		{"second of two is the root", 1, 2, "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chainRole(tt.index, tt.total); got != tt.want {
				t.Errorf("chainRole(%d, %d) = %q, want %q", tt.index, tt.total, got, tt.want)
			}
		})
	}
}
