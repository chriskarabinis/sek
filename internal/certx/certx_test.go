package certx

import (
	"crypto/tls"
	"testing"
	"time"
)

// daysFromNow builds a NotAfter for a certificate with that many whole days
// left. The extra hour keeps day 0 meaning "expires later today" rather than
// landing exactly on now, where the comparison could fall either way.
func daysFromNow(days int) time.Time {
	return time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour)
}

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
			if got := expiryStatus(daysFromNow(tt.daysLeft), tt.daysLeft); got != tt.want {
				t.Errorf("expiryStatus(%d) = %q, want %q", tt.daysLeft, got, tt.want)
			}
		})
	}
}

// TestExpiryStatusBandsAreDistinct guards the specific defect: two branches
// returning the same string.
func TestExpiryStatusBandsAreDistinct(t *testing.T) {
	critical := expiryStatus(daysFromNow(10), 10)
	expiring := expiryStatus(daysFromNow(20), 20)
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
			res := &Result{DaysLeft: tt.daysLeft, NotAfter: daysFromNow(tt.daysLeft)}
			if got := res.ExpiresWithin(tt.threshold); got != tt.want {
				t.Errorf("ExpiresWithin(%d) with %d days left = %v, want %v",
					tt.threshold, tt.daysLeft, got, tt.want)
			}
		})
	}
}

// TestExpired covers the exact-expiry predicate. DaysLeft truncates toward
// zero, so a certificate that lapsed in the last 24 hours reports 0 days left;
// keying off that value reported it as still valid.
func TestExpired(t *testing.T) {
	tests := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"long expired", time.Now().Add(-100 * 24 * time.Hour), true},
		{"expired yesterday", time.Now().Add(-25 * time.Hour), true},
		{"expired five hours ago", time.Now().Add(-5 * time.Hour), true},
		{"expired one minute ago", time.Now().Add(-time.Minute), true},
		{"expires in one hour", time.Now().Add(time.Hour), false},
		{"expires tomorrow", time.Now().Add(25 * time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &Result{NotAfter: tt.notAfter, DaysLeft: int(time.Until(tt.notAfter).Hours() / 24)}
			if got := res.Expired(); got != tt.want {
				t.Errorf("Expired() = %v, want %v (DaysLeft = %d)", got, tt.want, res.DaysLeft)
			}
		})
	}
}

// TestRecentlyExpiredIsReported ties the two helpers together for the case
// that slipped through: a certificate a few hours past NotAfter must be
// flagged by both the status label and the --expiry-days gate.
func TestRecentlyExpiredIsReported(t *testing.T) {
	notAfter := time.Now().Add(-5 * time.Hour)
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	if daysLeft != 0 {
		t.Fatalf("precondition: DaysLeft = %d, want 0 for a certificate expired 5 hours ago", daysLeft)
	}

	if got := expiryStatus(notAfter, daysLeft); got != StatusExpired {
		t.Errorf("expiryStatus() = %q, want %q", got, StatusExpired)
	}
	res := &Result{NotAfter: notAfter, DaysLeft: daysLeft}
	if !res.ExpiresWithin(30) {
		t.Error("ExpiresWithin(30) = false for an already-expired certificate")
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
