package dnsx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testServer is a local UDP nameserver that answers from a fixed table, so the
// resolver can be exercised without touching the network.
type testServer struct {
	addr    string
	queries atomic.Int64
	// delay is applied to every answer, which is what makes a sequential
	// implementation distinguishable from a concurrent one.
	delay time.Duration
}

// startTestServer serves the given TXT answers, keyed by fully-qualified name.
func startTestServer(t *testing.T, txt map[string][]string, delay time.Duration) *testServer {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}

	ts := &testServer{addr: conn.LocalAddr().String(), delay: delay}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		ts.queries.Add(1)
		time.Sleep(ts.delay)

		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeTXT {
			for _, value := range txt[req.Question[0].Name] {
				rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN TXT %q", req.Question[0].Name, value))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: conn, Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return ts
}

// TestEmailSecurityOrdersRecords pins the output order now that the twelve
// probes run concurrently: SPF first, then DMARC, then the DKIM selectors in
// table order, regardless of which answer arrived first.
func TestEmailSecurityOrdersRecords(t *testing.T) {
	ts := startTestServer(t, map[string][]string{
		"example.com.":                      {"v=spf1 -all"},
		"_dmarc.example.com.":               {"v=DMARC1; p=reject"},
		"smtp._domainkey.example.com.":      {"v=DKIM1; k=rsa; p=LAST"},
		"google._domainkey.example.com.":    {"v=DKIM1; k=rsa; p=FIRST"},
		"unrelated._domainkey.example.com.": {"v=DKIM1; k=rsa; p=NEVER"},
	}, 0)

	r := &Resolver{Server: ts.addr, Timeout: 2 * time.Second}
	records, err := r.EmailSecurity(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("EmailSecurity returned error: %v", err)
	}

	var got []string
	for _, rec := range records {
		got = append(got, rec.Type)
	}
	want := []string{"SPF", "DMARC", "DKIM", "DKIM"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("record types = %v, want %v", got, want)
	}

	// "google" precedes "smtp" in dkimSelectors, so it must come out first even
	// though the answers race.
	if !strings.Contains(records[2].Value, "[google]") {
		t.Errorf("first DKIM record = %q, want the google selector", records[2].Value)
	}
	if !strings.Contains(records[3].Value, "[smtp]") {
		t.Errorf("second DKIM record = %q, want the smtp selector", records[3].Value)
	}
}

// TestEmailSecurityProbesConcurrently is the regression test for the twelve
// lookups running one after another, which made this the slowest part of
// `sek dns` — ten of them are guesses that usually go unanswered.
func TestEmailSecurityProbesConcurrently(t *testing.T) {
	const delay = 100 * time.Millisecond

	ts := startTestServer(t, map[string][]string{"example.com.": {"v=spf1 -all"}}, delay)

	r := &Resolver{Server: ts.addr, Timeout: 5 * time.Second}

	start := time.Now()
	if _, err := r.EmailSecurity(context.Background(), "example.com"); err != nil {
		t.Fatalf("EmailSecurity returned error: %v", err)
	}
	elapsed := time.Since(start)

	wantQueries := int64(len(dkimSelectors) + 2)
	if got := ts.queries.Load(); got != wantQueries {
		t.Errorf("server saw %d queries, want %d", got, wantQueries)
	}
	// Sequentially this is twelve delays; concurrently it is about one. Half
	// the sequential cost is a wide margin that still fails the old behaviour.
	if limit := time.Duration(wantQueries) * delay / 2; elapsed > limit {
		t.Errorf("EmailSecurity took %v for %d probes, want under %v", elapsed, wantQueries, limit)
	}
}

// TestAQueriesBothFamiliesConcurrently covers the same change for A/AAAA, which
// cost a round-trip each when run in sequence.
func TestAQueriesBothFamiliesConcurrently(t *testing.T) {
	const delay = 150 * time.Millisecond

	ts := startTestServer(t, nil, delay)

	r := &Resolver{Server: ts.addr, Timeout: 5 * time.Second}

	start := time.Now()
	// The server answers no A or AAAA records; the timing is the point.
	if _, err := r.A(context.Background(), "example.com"); err != nil {
		t.Fatalf("A returned error: %v", err)
	}
	elapsed := time.Since(start)

	if got := ts.queries.Load(); got != 2 {
		t.Errorf("server saw %d queries, want 2 (A and AAAA)", got)
	}
	if elapsed > 2*delay {
		t.Errorf("A took %v, want under %v — the two families should overlap", elapsed, 2*delay)
	}
}

// startRecordServer answers any question from a fixed table of zone-file lines,
// keyed by fully-qualified name.
func startRecordServer(t *testing.T, records map[string][]string) *testServer {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}

	ts := &testServer{addr: conn.LocalAddr().String()}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		ts.queries.Add(1)

		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 {
			for _, line := range records[req.Question[0].Name] {
				if rr, err := dns.NewRR(line); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: conn, Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return ts
}

// TestReverseUsesTheConfiguredServer is the regression test for `sek dns -r`
// ignoring -s. Reverse went through net.LookupAddr, which always asks the
// system resolver, so the one lookup the user had named a server for was the
// one that did not use it. The test server answers a PTR the system resolver
// could not know about, so an answer at all proves it was asked.
func TestReverseUsesTheConfiguredServer(t *testing.T) {
	ts := startRecordServer(t, map[string][]string{
		"1.2.0.192.in-addr.arpa.": {"1.2.0.192.in-addr.arpa. 300 IN PTR host.example.test."},
	})

	r := &Resolver{Server: ts.addr, Timeout: 2 * time.Second}
	records, err := r.Reverse(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Reverse returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Reverse returned %d records, want 1", len(records))
	}
	if records[0].Type != "PTR" || records[0].Value != "host.example.test" {
		t.Errorf("Reverse = %+v, want a PTR for host.example.test", records[0])
	}
	if got := ts.queries.Load(); got != 1 {
		t.Errorf("configured server saw %d queries, want 1", got)
	}
}

// An address with no PTR is not an error, and must not be reported as records.
func TestReverseWithNoPTR(t *testing.T) {
	ts := startRecordServer(t, nil)

	r := &Resolver{Server: ts.addr, Timeout: 2 * time.Second}
	records, err := r.Reverse(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Reverse returned error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("Reverse = %v, want no records", records)
	}
}

func TestReverseRejectsNonAddresses(t *testing.T) {
	r := &Resolver{Server: "127.0.0.1:1", Timeout: time.Millisecond}
	if _, err := r.Reverse(context.Background(), "example.com"); err == nil {
		t.Error("Reverse(\"example.com\") returned no error")
	}
}

// TestQueriesHonourCancellation is the point of threading a context through the
// resolver: `sek dns` was the only command a Ctrl+C could not reach. Every
// query sat out the full timeout, and with -o that left the file half written.
func TestQueriesHonourCancellation(t *testing.T) {
	// A blackhole address: nothing answers, so only the context can end this.
	r := &Resolver{Server: "192.0.2.1:53", Timeout: 30 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lookups := map[string]func(context.Context) error{
		"A":     func(ctx context.Context) error { _, err := r.A(ctx, "example.com"); return err },
		"MX":    func(ctx context.Context) error { _, err := r.MX(ctx, "example.com"); return err },
		"NS":    func(ctx context.Context) error { _, err := r.NS(ctx, "example.com"); return err },
		"TXT":   func(ctx context.Context) error { _, err := r.TXT(ctx, "example.com"); return err },
		"CNAME": func(ctx context.Context) error { _, err := r.CNAME(ctx, "example.com"); return err },
		"SOA":   func(ctx context.Context) error { _, err := r.SOA(ctx, "example.com"); return err },
		"CAA":   func(ctx context.Context) error { _, err := r.CAA(ctx, "example.com"); return err },
		"PTR":   func(ctx context.Context) error { _, err := r.Reverse(ctx, "192.0.2.9"); return err },
	}

	for name, lookup := range lookups {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- lookup(ctx) }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s with a cancelled context returned no error", name)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s ignored the cancelled context", name)
			}
		})
	}
}

// EmailSecurity and Wildcard never report an error — absence is a valid answer
// for both — so cancellation shows up as returning promptly rather than as a
// failure. Twelve probes against a blackhole would otherwise cost the timeout.
func TestProbesReturnPromptlyWhenCancelled(t *testing.T) {
	r := &Resolver{Server: "192.0.2.1:53", Timeout: 30 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.EmailSecurity(ctx, "example.com")
		r.Wildcard(ctx, "example.com")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the probes ignored the cancelled context")
	}
}
