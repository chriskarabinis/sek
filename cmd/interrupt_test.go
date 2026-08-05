package cmd

import (
	"context"
	"errors"
	"testing"
)

// stubCommandContext hands the command under test a context it does not
// control, so an interrupt can be simulated without signalling the process.
func stubCommandContext(t *testing.T, ctx context.Context) {
	t.Helper()
	prev := commandContext
	commandContext = func() (context.Context, context.CancelFunc) {
		return ctx, func() {}
	}
	t.Cleanup(func() { commandContext = prev })
}

// setGlobal restores a package-level flag variable after the test.
func setGlobal(t *testing.T, dst *string, value string) {
	t.Helper()
	prev := *dst
	*dst = value
	t.Cleanup(func() { *dst = prev })
}

// TestDNSReportsInterruption pins what an interrupted `sek dns` must do. Every
// lookup comes back carrying "context canceled", and rendering those as a
// finished report — sections, wildcard verdict, platform line, exit status 0,
// and with -o a file that looks complete — presented a run that answered
// nothing as one that answered everything.
func TestDNSReportsInterruption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stubCommandContext(t, ctx)

	// An address nothing listens on: the queries must fail on the cancelled
	// context rather than reaching a resolver.
	setGlobal(t, &dnsServer, "127.0.0.1:1")
	setGlobal(t, &dnsDomain, "example.invalid")
	setGlobal(t, &dnsType, "")
	setGlobal(t, &dnsReverse, "")
	setGlobal(t, &globalFormat, "json")

	err := dnsCmd.RunE(dnsCmd, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("dns on a cancelled context returned %v, want context.Canceled", err)
	}
}

// TestSubReportsInterruption is the same contract for `sek sub`, which
// otherwise closed with "Done. Found N unique subdomains total." and exit 0
// after an interrupt — and in JSON mode emitted a document indistinguishable
// from a completed enumeration.
func TestSubReportsInterruption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stubCommandContext(t, ctx)

	setGlobal(t, &subDomain, "example.invalid")
	setGlobal(t, &subWordlist, "")
	setGlobal(t, &globalFormat, "json")

	err := subCmd.RunE(subCmd, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("sub on a cancelled context returned %v, want context.Canceled", err)
	}
}
