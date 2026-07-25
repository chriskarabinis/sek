// Package scanx performs TCP connect port scans and identifies the services
// found. Connect scanning needs no privileges, unlike a SYN scan.
package scanx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Port states.
const (
	StateOpen     = "open"
	StateFiltered = "filtered"
	StateClosed   = "closed"
)

// Port is the outcome of probing a single port.
type Port struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
}

// Result is a completed scan.
type Result struct {
	Target   string `json:"target"`
	IP       string `json:"ip"`
	Scanned  int    `json:"scanned"`
	Open     int    `json:"open"`
	Filtered int    `json:"filtered"`
	Closed   int    `json:"closed"`
	Ports    []Port `json:"ports"`
}

// Options configures a scan.
type Options struct {
	Timeout     time.Duration
	Concurrency int
}

// OpenPorts returns only the ports accepting connections.
func (r *Result) OpenPorts() []Port { return r.filter(StateOpen) }

// FilteredPorts returns only the ports a firewall is dropping.
func (r *Result) FilteredPorts() []Port { return r.filter(StateFiltered) }

func (r *Result) filter(state string) []Port {
	var out []Port
	for _, p := range r.Ports {
		if p.State == state {
			out = append(out, p)
		}
	}
	return out
}

// ParsePorts parses a spec such as "80,443", "1-1000" or "22,80,1000-2000",
// preserving order and dropping duplicates.
func ParsePorts(spec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}

		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports in %q", spec)
	}
	return ports, nil
}

// AllPorts returns the full TCP range.
func AllPorts() []int {
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports
}

// hostPort builds a dialable address. It must go through net.JoinHostPort:
// concatenating host and port directly produces "::1:443" for an IPv6 literal,
// which never dials, so every port on an IPv6 target looked closed.
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Resolve turns a hostname into an address, preferring IPv4.
func Resolve(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve: %s", target)
	}
	for _, addr := range addrs {
		if net.ParseIP(addr).To4() != nil {
			return addr, nil
		}
	}
	return addrs[0], nil
}

// Scan probes every port through a fixed worker pool. The pool size is what
// bounds resource use: one goroutine per port would park 65535 of them on a
// full-range scan.
func Scan(ctx context.Context, target string, ports []int, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 300
	}

	ip, err := Resolve(target)
	if err != nil {
		return nil, err
	}

	results := make([]Port, len(ports))
	workers := min(opts.Concurrency, len(ports))

	type job struct{ idx, port int }
	jobs := make(chan job)
	done := make(chan struct{})

	for w := 0; w < workers; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range jobs {
				results[j.idx] = probe(ctx, ip, j.port, opts.Timeout)
			}
		}()
	}

dispatch:
	for i, p := range ports {
		select {
		case jobs <- job{idx: i, port: p}:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	for w := 0; w < workers; w++ {
		<-done
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	res := &Result{Target: target, IP: ip, Scanned: len(ports), Ports: results}
	for _, p := range results {
		switch p.State {
		case StateOpen:
			res.Open++
		case StateFiltered:
			res.Filtered++
		default:
			res.Closed++
		}
	}
	return res, nil
}

// probe connects to one port and classifies the outcome. A timeout means a
// firewall is dropping packets; an outright refusal means nothing is listening.
func probe(ctx context.Context, host string, port int, timeout time.Duration) Port {
	address := hostPort(host, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		conn.Close()
		return Port{
			Port:    port,
			State:   StateOpen,
			Service: ServiceName(port),
			Version: grabVersion(ctx, host, port, timeout),
		}
	}

	var netErr net.Error
	if ok := asNetError(err, &netErr); ok && netErr.Timeout() {
		return Port{Port: port, State: StateFiltered, Service: ServiceName(port)}
	}
	return Port{Port: port, State: StateClosed}
}

func asNetError(err error, target *net.Error) bool {
	if ne, ok := err.(net.Error); ok {
		*target = ne
		return true
	}
	return false
}

// grabVersion asks an open port to identify itself: an HTTP request for web
// ports, otherwise whatever banner the service volunteers on connect.
func grabVersion(ctx context.Context, host string, port int, timeout time.Duration) string {
	address := hostPort(host, port)

	if tlsPorts[port] {
		// SNI must be a hostname; sending an IP literal is invalid.
		serverName := host
		if net.ParseIP(host) != nil {
			serverName = ""
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address,
			&tls.Config{InsecureSkipVerify: true, ServerName: serverName})
		if err != nil {
			return ""
		}
		defer conn.Close()
		return httpServerHeader(conn, host, timeout)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()

	if httpPorts[port] {
		return httpServerHeader(conn, host, timeout)
	}

	// SSH, FTP, SMTP and friends announce themselves on connect.
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	line := strings.TrimSpace(string(buf[:n]))
	if i := strings.IndexAny(line, "\r\n"); i > 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

func httpServerHeader(conn net.Conn, host string, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return extractServerHeader(string(buf[:n]))
}

// extractServerHeader pulls the Server value out of a raw HTTP response.
func extractServerHeader(response string) string {
	const key = "server:"
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(strings.ToLower(line), key) {
			return strings.TrimSpace(line[len(key):])
		}
	}
	return ""
}
