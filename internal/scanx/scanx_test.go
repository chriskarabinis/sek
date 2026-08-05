package scanx

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []int
	}{
		{"single", "80", []int{80}},
		{"list", "80,443,22", []int{80, 443, 22}},
		{"range", "80-83", []int{80, 81, 82, 83}},
		{"mixed", "22,80-82", []int{22, 80, 81, 82}},
		{"deduplicates", "80,80,443,80", []int{80, 443}},
		{"deduplicates across range", "80,79-81", []int{80, 79, 81}},
		{"tolerates spaces", " 80 , 443 ", []int{80, 443}},
		{"tolerates empty segments", "80,,443", []int{80, 443}},
		{"boundaries", "1,65535", []int{1, 65535}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			if err != nil {
				t.Fatalf("ParsePorts(%q) returned error: %v", tt.spec, err)
			}
			if !equal(got, tt.want) {
				t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParsePortsRejects(t *testing.T) {
	for _, spec := range []string{
		"",
		"abc",
		"0",
		"65536",
		"-1",
		"100-50",
		"1-65536",
		"80-",
		"80-abc",
	} {
		t.Run(spec, func(t *testing.T) {
			if got, err := ParsePorts(spec); err == nil {
				t.Errorf("ParsePorts(%q) = %v, want an error", spec, got)
			}
		})
	}
}

func TestServiceName(t *testing.T) {
	if got := ServiceName(443); got != "HTTPS" {
		t.Errorf("ServiceName(443) = %q, want %q", got, "HTTPS")
	}
	if got := ServiceName(64999); got != "unknown" {
		t.Errorf("ServiceName(64999) = %q, want %q", got, "unknown")
	}
}

func TestAllPorts(t *testing.T) {
	ports := AllPorts()
	if len(ports) != 65535 {
		t.Fatalf("AllPorts() returned %d ports, want 65535", len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Errorf("AllPorts() spans %d..%d, want 1..65535", ports[0], ports[len(ports)-1])
	}
}

func TestExtractServerHeader(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{"simple", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "nginx/1.18.0"},
		{"lowercase key", "HTTP/1.1 200 OK\r\nserver: Apache\r\n\r\n", "Apache"},
		{"absent", "HTTP/1.1 200 OK\r\nDate: today\r\n\r\n", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractServerHeader(tt.response); got != tt.want {
				t.Errorf("extractServerHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHTTPServerHeaderSpansReads is the regression test for the banner grab
// issuing a single conn.Read: a server that flushed its status line separately
// from its headers had its Server value dropped, and the port was reported with
// no version.
func TestHTTPServerHeaderSpansReads(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Deliberately split: the status line lands in one segment and the
		// headers in the next, which is exactly what the old code missed.
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		time.Sleep(50 * time.Millisecond)
		io.WriteString(conn, "Server: nginx/1.24.0\r\nDate: today\r\n\r\n")
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("cannot dial: %v", err)
	}
	defer conn.Close()

	if got := httpServerHeader(conn, "127.0.0.1", 2*time.Second); got != "nginx/1.24.0" {
		t.Errorf("httpServerHeader() = %q, want %q", got, "nginx/1.24.0")
	}
}

// TestHTTPServerHeaderStopsAtHeaderEnd pins the other half of the contract: a
// server that ignores the HTTP/1.0 request and holds the connection open must
// not cost a full timeout, so the read stops at the blank line rather than EOF.
func TestHTTPServerHeaderStopsAtHeaderEnd(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer listener.Close()

	held := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\n")
		<-held // keep the connection open, as a keep-alive server would
	}()
	defer close(held)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("cannot dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	got := httpServerHeader(conn, "127.0.0.1", 5*time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("httpServerHeader() waited %v for a connection held open, want a prompt return", elapsed)
	}
	if got != "Caddy" {
		t.Errorf("httpServerHeader() = %q, want %q", got, "Caddy")
	}
}

// TestHostPort covers the address construction that broke IPv6 scanning. It
// runs everywhere, unlike the live IPv6 scan below, which needs a v6 stack.
func TestHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{"ipv4", "127.0.0.1", 443, "127.0.0.1:443"},
		{"hostname", "example.com", 80, "example.com:80"},
		{"ipv6 loopback", "::1", 443, "[::1]:443"},
		{"ipv6 full", "2606:4700:10::6814:179a", 8443, "[2606:4700:10::6814:179a]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostPort(tt.host, tt.port)
			if got != tt.want {
				t.Errorf("hostPort(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
			// Whatever we build has to survive a round trip, which the old
			// "%s:%d" form did not for IPv6.
			host, _, err := net.SplitHostPort(got)
			if err != nil {
				t.Errorf("SplitHostPort(%q) failed: %v", got, err)
			}
			if host != tt.host {
				t.Errorf("SplitHostPort(%q) host = %q, want %q", got, host, tt.host)
			}
		})
	}
}

// TestScanFindsOpenAndClosedPorts checks the two states that matter against a
// listener we control, rather than trusting a remote host to behave.
func TestScanFindsOpenAndClosedPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer listener.Close()
	go acceptAndClose(listener)

	openPort := listener.Addr().(*net.TCPAddr).Port
	closedPort := freePort(t, "127.0.0.1")

	ip, err := Resolve(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	res, err := ScanAddr(context.Background(), "127.0.0.1", ip, []int{openPort, closedPort}, Options{
		Timeout:     2 * time.Second,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("ScanAddr returned error: %v", err)
	}

	states := map[int]string{}
	for _, p := range res.Ports {
		states[p.Port] = p.State
	}
	if states[openPort] != StateOpen {
		t.Errorf("port %d = %q, want %q", openPort, states[openPort], StateOpen)
	}
	if states[closedPort] != StateClosed {
		t.Errorf("port %d = %q, want %q", closedPort, states[closedPort], StateClosed)
	}
	if res.Open != 1 || res.Closed != 1 {
		t.Errorf("counts: open=%d closed=%d, want 1 and 1", res.Open, res.Closed)
	}
}

// TestScanIPv6 is the regression test for addresses being built with
// fmt.Sprintf("%s:%d"), which yields "::1:443" and never connects — every port
// on an IPv6 target was reported closed.
func TestScanIPv6(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	defer listener.Close()
	go acceptAndClose(listener)

	port := listener.Addr().(*net.TCPAddr).Port

	res, err := ScanAddr(context.Background(), "::1", "::1", []int{port}, Options{
		Timeout:     2 * time.Second,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("ScanAddr returned error: %v", err)
	}
	if len(res.Ports) != 1 || res.Ports[0].State != StateOpen {
		t.Errorf("IPv6 scan reported %+v, want one open port", res.Ports)
	}
}

// TestScanRespectsCancellation makes sure a cancelled context stops the scan
// instead of running to completion.
func TestScanRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ScanAddr(ctx, "127.0.0.1", "127.0.0.1", AllPorts(), Options{
		Timeout:     time.Second,
		Concurrency: 8,
	})
	if err == nil {
		t.Error("ScanAddr with a cancelled context returned no error")
	}
}

func acceptAndClose(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

// freePort returns a port with nothing listening on it.
func freePort(t *testing.T, host string) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("cannot reserve a port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBannerPortsHaveServiceNames catches a port the scanner knows enough about
// to speak HTTP or TLS to, but has no name for. 81, 2095 and 2096 were in the
// banner tables and missing from services, so an open cPanel webmail port came
// back with its banner grabbed and its service reported as "unknown".
func TestBannerPortsHaveServiceNames(t *testing.T) {
	for name, table := range map[string]map[int]bool{"tlsPorts": tlsPorts, "httpPorts": httpPorts} {
		for port := range table {
			if got := ServiceName(port); got == "unknown" {
				t.Errorf("%s lists %d but services has no name for it", name, port)
			}
		}
	}
}

// A port cannot be both plaintext HTTP and TLS: grabVersion checks tlsPorts
// first, so an entry in both would silently never be probed in the clear.
func TestBannerPortTablesDoNotOverlap(t *testing.T) {
	for port := range tlsPorts {
		if httpPorts[port] {
			t.Errorf("port %d is in both tlsPorts and httpPorts", port)
		}
	}
}

// DefaultPorts is the set scanned with no -p, so a repeated entry is a port
// probed twice on every default run.
func TestDefaultPortsAreUniqueAndSorted(t *testing.T) {
	seen := make(map[int]bool, len(DefaultPorts))
	for i, port := range DefaultPorts {
		if seen[port] {
			t.Errorf("DefaultPorts repeats %d", port)
		}
		seen[port] = true
		if i > 0 && port <= DefaultPorts[i-1] {
			t.Errorf("DefaultPorts is out of order at index %d: %d follows %d",
				i, port, DefaultPorts[i-1])
		}
	}
}

// TestHTTPServerHeaderAcceptsBareLF covers header blocks separated by a bare
// LF, which embedded and hand-rolled servers send. Waiting for the CRLF pair
// that never arrives cost the full timeout on every such port — the exact case
// the read loop stops early to avoid.
func TestHTTPServerHeaderAcceptsBareLF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer listener.Close()

	held := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.0 200 OK\nServer: lighttpd/1.4.59\n\n")
		<-held // hold the connection open, as a keep-alive server would
	}()
	defer close(held)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("cannot dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	got := httpServerHeader(conn, "127.0.0.1", 5*time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("httpServerHeader() waited %v for an LF-terminated block, want a prompt return", elapsed)
	}
	if got != "lighttpd/1.4.59" {
		t.Errorf("httpServerHeader() = %q, want %q", got, "lighttpd/1.4.59")
	}
}

func TestEndOfHeaders(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"crlf terminated", "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n", true},
		{"lf terminated", "HTTP/1.0 200 OK\nServer: x\n\n", true},
		{"status line only", "HTTP/1.1 200 OK\r\n", false},
		{"headers still arriving", "HTTP/1.1 200 OK\r\nServer: x\r\n", false},
		{"a lone crlf is not a terminator", "HTTP/1.0 200 OK\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endOfHeaders([]byte(tt.raw)); got != tt.want {
				t.Errorf("endOfHeaders(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestProbeOpensOneConnectionPerPort pins the socket handed to the banner grab.
// Probing used to open a connection, close it to record the port as open, then
// open a second one to ask the service what it was: two handshakes per open
// port, a banner that could come from a different backend than the one probed,
// and twice the connection count on a wide scan.
func TestProbeOpensOneConnectionPerPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer listener.Close()

	var accepts atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer conn.Close()
				io.WriteString(conn, "SSH-2.0-OpenSSH_9.6p1\r\n")
			}()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	got := probe(context.Background(), "127.0.0.1", port, 2*time.Second)

	if got.State != StateOpen {
		t.Fatalf("probe reported %q, want %q", got.State, StateOpen)
	}
	if got.Version != "SSH-2.0-OpenSSH_9.6p1" {
		t.Errorf("probe read banner %q, want %q", got.Version, "SSH-2.0-OpenSSH_9.6p1")
	}
	if n := accepts.Load(); n != 1 {
		t.Errorf("probe opened %d connections to one port, want 1", n)
	}
}
