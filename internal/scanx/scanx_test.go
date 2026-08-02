package scanx

import (
	"context"
	"net"
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

	res, err := Scan(context.Background(), "127.0.0.1", []int{openPort, closedPort}, Options{
		Timeout:     2 * time.Second,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
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

	res, err := Scan(context.Background(), "::1", []int{port}, Options{
		Timeout:     2 * time.Second,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
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

	_, err := Scan(ctx, "127.0.0.1", AllPorts(), Options{
		Timeout:     time.Second,
		Concurrency: 8,
	})
	if err == nil {
		t.Error("Scan with a cancelled context returned no error")
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

// TestReadHeaderBlockSpansReads is the regression test for the banner grab
// taking a single Read: a server that dribbles its header block out across
// several writes had its Server value dropped, and the port was reported with
// no version at all.
func TestReadHeaderBlockSpansReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		for _, part := range []string{
			"HTTP/1.1 200 OK\r\n",
			"Date: Mon, 02 Jan 2006 15:04:05 GMT\r\n",
			"Server: ngi",
			"nx/1.24.0\r\n",
			"Content-Type: text/html\r\n\r\n",
		} {
			if _, err := server.Write([]byte(part)); err != nil {
				return
			}
		}
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	got := extractServerHeader(readHeaderBlock(client))
	if got != "nginx/1.24.0" {
		t.Errorf("Server header = %q, want %q", got, "nginx/1.24.0")
	}
}

// readHeaderBlock must stop at the end of the headers rather than draining the
// body, so a keep-alive response does not cost the whole timeout.
func TestReadHeaderBlockStopsAtEndOfHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		server.Write([]byte("HTTP/1.1 200 OK\r\nServer: caddy\r\n\r\n"))
		// Left open, as a keep-alive server would: no EOF is coming.
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan string, 1)
	go func() { done <- extractServerHeader(readHeaderBlock(client)) }()

	select {
	case got := <-done:
		if got != "caddy" {
			t.Errorf("Server header = %q, want %q", got, "caddy")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readHeaderBlock kept reading past the end of the headers")
	}
	server.Close()
}

// A bare-LF header block is unusual but real on embedded servers.
func TestReadHeaderBlockAcceptsBareLF(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		server.Write([]byte("HTTP/1.0 200 OK\nServer: lighttpd/1.4.55\n\nbody"))
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if got := extractServerHeader(readHeaderBlock(client)); got != "lighttpd/1.4.55" {
		t.Errorf("Server header = %q, want %q", got, "lighttpd/1.4.55")
	}
}
