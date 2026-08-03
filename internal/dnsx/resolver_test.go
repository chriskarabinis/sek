package dnsx

import (
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
	records, err := r.EmailSecurity("example.com")
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
	if _, err := r.EmailSecurity("example.com"); err != nil {
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
	if _, err := r.A("example.com"); err != nil {
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
