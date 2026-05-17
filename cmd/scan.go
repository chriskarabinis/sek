package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// flags
var scanTarget     string
var scanPorts      string
var scanTimeout    int
var scanAll        bool
var scanShowFilter bool

type scanResult struct {
	port    int
	state   string // "open", "filtered", "closed"
	service string
	version string
}

// serviceMap maps well-known port numbers to service names
var serviceMap = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	69:    "TFTP",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	161:   "SNMP",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	587:   "SMTP",
	636:   "LDAPS",
	993:   "IMAPS",
	995:   "POP3S",
	1080:  "SOCKS",
	1194:  "OpenVPN",
	1433:  "MSSQL",
	1521:  "Oracle DB",
	1723:  "PPTP",
	2049:  "NFS",
	2082:  "cPanel HTTP",
	2083:  "cPanel HTTPS",
	2086:  "WHM HTTP",
	2087:  "WHM HTTPS",
	2181:  "ZooKeeper",
	2222:  "SSH-alt",
	2375:  "Docker HTTP",
	2376:  "Docker HTTPS",
	3000:  "HTTP-alt",
	3306:  "MySQL",
	3389:  "RDP",
	3690:  "SVN",
	4443:  "HTTPS-alt",
	4444:  "Metasploit",
	4848:  "GlassFish",
	5000:  "HTTP-alt",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5985:  "WinRM HTTP",
	5986:  "WinRM HTTPS",
	6379:  "Redis",
	6443:  "Kubernetes API",
	7001:  "WebLogic",
	7080:  "HTTP-alt",
	7443:  "HTTPS-alt",
	8000:  "HTTP-alt",
	8008:  "HTTP-alt",
	8080:  "HTTP-alt",
	8081:  "HTTP-alt",
	8082:  "HTTP-alt",
	8083:  "HTTP-alt",
	8085:  "HTTP-alt",
	8086:  "HTTP-alt",
	8088:  "HTTP-alt",
	8090:  "HTTP-alt",
	8180:  "HTTP-alt",
	8181:  "HTTP-alt",
	8200:  "Vault HTTP",
	8443:  "HTTPS-alt",
	8444:  "HTTPS-alt",
	8500:  "Consul HTTP",
	8800:  "HTTP-alt",
	8880:  "HTTP-alt",
	8888:  "HTTP-alt",
	8983:  "Solr",
	9000:  "HTTP-alt",
	9001:  "HTTP-alt",
	9090:  "HTTP-alt",
	9091:  "HTTP-alt",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch",
	9418:  "Git",
	9443:  "HTTPS-alt",
	9999:  "HTTP-alt",
	10000: "Webmin",
	27017: "MongoDB",
	27018: "MongoDB",
	50000: "IBM DB2",
}

// tlsPortSet: ports that get probed with TLS
var tlsPortSet = map[int]bool{
	443: true, 2083: true, 2087: true, 2096: true,
	4443: true, 5986: true, 6443: true, 7443: true,
	8443: true, 8444: true, 9443: true,
}

// httpPortSet: ports that get probed with plain HTTP
var httpPortSet = map[int]bool{
	80: true, 81: true, 2082: true, 2086: true, 2095: true,
	3000: true, 4848: true, 5000: true, 7001: true, 7080: true,
	8000: true, 8008: true, 8080: true, 8081: true, 8082: true,
	8083: true, 8085: true, 8086: true, 8088: true, 8090: true,
	8180: true, 8181: true, 8200: true, 8500: true, 8800: true,
	8880: true, 8888: true, 8983: true, 9000: true, 9001: true,
	9090: true, 9091: true, 9200: true, 9999: true, 10000: true,
}

// defaultTopPorts: most security-relevant ports (similar to nmap top ports)
var defaultTopPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389,
	443, 445, 465, 587, 636, 993, 995, 1080, 1194, 1433, 1521,
	1723, 2049, 2082, 2083, 2086, 2087, 2181, 2222,
	2375, 2376, 3000, 3306, 3389, 3690, 4443, 4444, 4848, 5000,
	5432, 5900, 5985, 5986, 6379, 6443, 7001, 7080, 7443, 8000,
	8008, 8080, 8081, 8082, 8083, 8085, 8086, 8088, 8090, 8180,
	8181, 8200, 8443, 8444, 8500, 8800, 8880, 8888, 8983, 9000,
	9001, 9090, 9091, 9200, 9300, 9418, 9443, 9999, 10000, 27017,
	27018, 50000,
}

// parsePorts parses a port spec like "80,443" or "1-1000" or "22,80,1000-2000"
func parsePorts(spec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}

// grabVersion attempts to identify the service version running on an open port
func grabVersion(host string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", host, port)

	if tlsPortSet[port] {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp", address,
			&tls.Config{InsecureSkipVerify: true, ServerName: host},
		)
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		return extractServerHeader(string(buf[:n]))
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if httpPortSet[port] {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		return extractServerHeader(string(buf[:n]))
	}

	// For SSH, FTP, SMTP, etc. — servers send a banner on connect
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		line := strings.TrimSpace(string(buf[:n]))
		if i := strings.Index(line, "\n"); i > 0 {
			line = line[:i]
		}
		return strings.TrimSpace(line)
	}
	return ""
}

func extractServerHeader(response string) string {
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

// probePort performs a TCP connect scan and grabs a banner if open
func probePort(host string, port int, timeout time.Duration) scanResult {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err == nil {
		conn.Close()
		svc := serviceMap[port]
		if svc == "" {
			svc = "unknown"
		}
		ver := grabVersion(host, port, timeout)
		return scanResult{port: port, state: "open", service: svc, version: ver}
	}

	// Timeout → firewall is dropping packets (filtered)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		svc := serviceMap[port]
		return scanResult{port: port, state: "filtered", service: svc}
	}
	// Connection refused / reset → port is closed (host actively rejected)
	return scanResult{port: port, state: "closed"}
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Port scanner",
	Long:  `Scan a host for open ports. Detects services, banners, and firewall filtering.`,
	Run: func(cmd *cobra.Command, args []string) {
		if scanTarget == "" {
			fmt.Println("Error: target is required. Use -d <domain or IP>")
			os.Exit(1)
		}

		InitOutput()
		defer CloseOutput()

		timeout := time.Duration(scanTimeout) * time.Millisecond

		// Resolve hostname — prefer IPv4
		ips, err := net.LookupHost(scanTarget)
		if err != nil || len(ips) == 0 {
			WriteLine(fmt.Sprintf("[!] Cannot resolve: %s\n", scanTarget))
			os.Exit(1)
		}
		ip := ips[0]
		for _, addr := range ips {
			if net.ParseIP(addr).To4() != nil {
				ip = addr
				break
			}
		}

		// Build port list
		var ports []int
		if scanAll {
			for p := 1; p <= 65535; p++ {
				ports = append(ports, p)
			}
		} else if scanPorts != "" {
			ports, err = parsePorts(scanPorts)
			if err != nil {
				WriteLine(fmt.Sprintf("[!] %s\n", err))
				os.Exit(1)
			}
		} else {
			ports = defaultTopPorts
		}

		headerLabel := scanTarget
		if ip != scanTarget {
			headerLabel = fmt.Sprintf("%s (%s)", scanTarget, ip)
		}
		header := fmt.Sprintf("\n[*] Port scan for: %s\n", headerLabel)
		WriteLineColored(yellow+header+reset, header)
		WriteLine(fmt.Sprintf("[*] Scanning %d ports...\n", len(ports)))

		// Concurrent scan
		results := make([]scanResult, len(ports))
		concurrency := 300
		if len(ports) < concurrency {
			concurrency = len(ports)
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for i, port := range ports {
			wg.Add(1)
			go func(idx, p int) {
				defer wg.Done()
				sem <- struct{}{}
				results[idx] = probePort(ip, p, timeout)
				<-sem
			}(i, port)
		}
		wg.Wait()

		// Sort by port number
		sort.Slice(results, func(i, j int) bool {
			return results[i].port < results[j].port
		})

		// Print table header
		plain := fmt.Sprintf("  %-12s %-10s %-20s %s", "PORT", "STATE", "SERVICE", "VERSION")
		WriteLineColored(yellow+plain+reset, plain)
		WriteLine("  " + strings.Repeat("-", 66))

		openCount, filteredCount, closedCount := 0, 0, 0
		for _, r := range results {
			switch r.state {
			case "open":
				openCount++
			case "filtered":
				filteredCount++
				continue // skip filtered in output — too noisy for large scans
			default:
				closedCount++
				continue
			}
			portStr := fmt.Sprintf("%d/tcp", r.port)
			ver := r.version
			if ver == "" {
				ver = "-"
			}
			svc := r.service
			if svc == "" {
				svc = "unknown"
			}
			plain := fmt.Sprintf("  %-12s %-10s %-20s %s", portStr, r.state, svc, ver)
			WriteLineColored(yellow+plain+reset, plain)
		}

		// Print filtered ports only if --filter is set
		if scanShowFilter {
			hasFiltered := false
			for _, r := range results {
				if r.state != "filtered" {
					continue
				}
				if !hasFiltered {
					WriteLine("")
					plain := fmt.Sprintf("  %-12s %-10s %-20s", "PORT", "STATE", "SERVICE")
					WriteLineColored(yellow+plain+reset, plain)
					WriteLine("  " + strings.Repeat("-", 66))
					hasFiltered = true
				}
				portStr := fmt.Sprintf("%d/tcp", r.port)
				svc := r.service
				if svc == "" {
					svc = "unknown"
				}
				plain := fmt.Sprintf("  %-12s %-10s %-20s", portStr, r.state, svc)
				WriteLineColored(yellow+plain+reset, plain)
			}
		}

		if openCount == 0 && filteredCount == 0 {
			WriteLine("  No open or filtered ports found.")
		}

		WriteLine("")
		summary := fmt.Sprintf("[*] Done. %d open  |  %d filtered  |  %d closed", openCount, filteredCount, closedCount)
		WriteLineColored(yellow+summary+reset, summary)
		WriteLine("")
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanTarget, "domain", "d", "", "Target domain or IP (e.g. example.com or 1.2.3.4)")
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "", "Ports: comma-separated or range (e.g. 80,443 or 1-1000). Default: top 85 common ports")
	scanCmd.Flags().IntVarP(&scanTimeout, "timeout", "t", 2000, "Connection timeout in milliseconds")
	scanCmd.Flags().BoolVar(&scanAll, "all", false, "Scan all 65535 ports")
	scanCmd.Flags().BoolVar(&scanShowFilter, "filter", false, "Also show filtered (firewalled) ports")
	rootCmd.AddCommand(scanCmd)
}
