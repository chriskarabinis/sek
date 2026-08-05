package cmd

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
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

// startCancellingNameserver runs a local nameserver that answers normally until
// the nth query, then cancels the context it was handed. Cancelling from inside
// the resolver is what makes the phase boundary deterministic: the caller knows
// exactly how many queries precede the point it wants to interrupt.
func startCancellingNameserver(t *testing.T, cancelOn int64, cancel context.CancelFunc) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}

	var queries atomic.Int64
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeMX {
			if rr, err := dns.NewRR(req.Question[0].Name + " 300 IN MX 10 mail.example.com."); err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
		if queries.Add(1) == cancelOn {
			cancel()
		}
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}

// TestDNSReportsInterruptionDuringPlatformDetection covers the second half of
// the run. Neither the wildcard probe nor platform detection reports an error —
// a negative answer is the expected result for both — so an interrupt arriving
// after the record lookups had already succeeded left the records intact and
// quietly turned the two verdicts into "no wildcard" and "Custom / Unknown",
// which read exactly like real answers.
//
// -t MX makes the phase boundary exact: one query answers the section, so
// cancelling on the second query lands inside platform detection, after the
// first cancellation check has already passed.
func TestDNSReportsInterruptionDuringPlatformDetection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stubCommandContext(t, ctx)

	setGlobal(t, &dnsServer, startCancellingNameserver(t, 2, cancel))
	setGlobal(t, &dnsDomain, "example.com")
	setGlobal(t, &dnsType, "MX")
	setGlobal(t, &dnsReverse, "")
	setGlobal(t, &globalFormat, "json")

	err := dnsCmd.RunE(dnsCmd, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("dns interrupted during platform detection returned %v, want context.Canceled", err)
	}
}
