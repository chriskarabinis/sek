# sek — Cloud CLI Kit

```
 ___  ___  _  __
/ __|| __|| |/ /
\__ \| _| | ' <
|___/|___||_|\_\
```

A fast, modular security toolkit for the terminal. Written in Go — single binary, no dependencies.

---

## Global Flags

Available on all commands:

| Flag | Description |
|------|-------------|
| `-o results.txt` | Save output to file |
| `--no-color` | Disable colored output (auto-disabled when piping) |

---

## Installation

### Install script (macOS & Linux) — recommended
```bash
curl -fsSL https://raw.githubusercontent.com/chriskarabinis/sek/main/install.sh | bash
```

### Homebrew (macOS)
```bash
brew install chriskarabinis/sek/sek
```

### Using Go
```bash
go install github.com/chriskarabinis/sek@latest
```

### Clone & Build
```bash
git clone https://github.com/chriskarabinis/sek.git
cd sek
go build -o sek
sudo mv sek /usr/local/bin/
```

---

## Commands

| Command | Description |
|---------|-------------|
| `sek sub` | Subdomain enumeration |
| `sek dns` | DNS record lookup + platform detection |
| `sek cert` | SSL/TLS certificate info — expiry, issuer, SANs, TLS version |
| `sek whois` | WHOIS domain lookup — registrar, dates, nameservers |
| `sek scan` | Port scanner — open ports, services, banners, firewall detection |
| `sek update` | Update sek to the latest version |
| `sek uninstall` | Remove sek from your system |
| `sek version` | Show current version |

---

## sek sub

Discover subdomains using two methods:
- **DNS Brute Force** — tests 200+ common subdomain prefixes in parallel
- **Certificate Transparency Logs** — queries [crt.sh](https://crt.sh) for known subdomains from public SSL certificates

### Usage

```bash
sek sub -d <domain> [flags]
```

### Flags

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain (required) |
| `-w` | `--wordlist` | Custom wordlist file |

### Examples

```bash
# Basic scan
sek sub -d example.com

# Save results to file
sek sub -d example.com -o results.txt

# Use a custom wordlist
sek sub -d example.com -w wordlist.txt

# Custom wordlist and save output
sek sub -d example.com -w wordlist.txt -o results.txt
```

### Output

```
[*] example.com  ->  93.184.216.34

[*] Querying certificate transparency logs (crt.sh)...
  mail.example.com          93.184.216.34
  api.example.com           93.184.216.35

[*] Running DNS brute force (214 words)...
  www.example.com           93.184.216.34
  staging.example.com       93.184.216.36

[*] Done. Found 3 unique subdomains total.
```

### Custom Wordlist Format

Plain text, one word per line. Lines starting with `#` are ignored.

```
# My wordlist
www
api
admin
dev
```

For deep enumeration, use [SecLists](https://github.com/danielmiessler/SecLists):

```bash
brew install seclists
sek sub -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

---

## sek dns

Query DNS records for a domain and automatically detect the hosting/CDN platform.

### Usage

```bash
sek dns -d <domain> [flags]
sek dns -r <ip>
```

### Flags

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain (required) |
| `-t` | `--type` | Record type: A, MX, NS, TXT, CNAME, SOA, CAA, EMAIL (default: all) |
| `-s` | `--server` | Custom DNS server (e.g. 8.8.8.8) |
| `-r` | `--reverse` | Reverse DNS lookup for an IP address |

### Examples

```bash
# All records
sek dns -d example.com

# Specific record type
sek dns -d example.com -t MX
sek dns -d example.com -t TXT
sek dns -d example.com -t SOA
sek dns -d example.com -t EMAIL

# Custom DNS server
sek dns -d example.com -s 8.8.8.8
sek dns -d example.com -s 1.1.1.1

# Reverse DNS
sek dns -r 8.8.8.8
```

### Output

```
[*] DNS lookup for: example.com

[*] A / AAAA
  A       93.184.216.34

[*] MX
  MX      mail.example.com (priority: 10)

[*] NS
  NS      ns1.example.com

[*] TXT
  TXT     v=spf1 include:_spf.example.com ~all

[*] SOA
  SOA     primary: ns1.example.com | admin: admin@example.com | serial: 2024010101 | refresh: 900s

[*] CAA
  CAA     0 issue "letsencrypt.org"

[*] Email Security (SPF / DMARC / DKIM)
  SPF     v=spf1 include:_spf.example.com ~all
  DMARC   v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  DKIM    [google] v=DKIM1; k=rsa; p=...

[*] Platform detected: Cloudflare
```

Also shows:
- **TTL** for every record
- **Wildcard DNS detection** — checks if `*.domain` resolves to anything
- **Platform detection** via NS records, CNAME patterns, and Cloudflare IP ranges. Supports global providers (Cloudflare, AWS, Azure, Akamai, Fastly) and Greek providers (Fastpath, Papaki, Top.Host, Forthnet, Cosmote).

---

---

## sek cert

Inspect SSL/TLS certificates for a domain.

### Usage

```bash
sek cert -d <domain> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-p` | Port (default: 443) |
| `-c` | Show full certificate chain |
| `--insecure` | Skip verification (for self-signed certs) |

### Examples

```bash
# Basic
sek cert -d example.com

# With chain
sek cert -d example.com -c

# Custom port
sek cert -d example.com -p 8443
```

### Output

```
[*] SSL/TLS Certificate for: example.com

[*] Certificate
  Subject       example.com
  Issuer        R12
  Org           Let's Encrypt
  Valid From    2026-01-01 00:00:00 UTC
  Valid To      2026-04-01 00:00:00 UTC
  Days Left     71 days  [OK]
  Serial        ABC123...

[*] Subject Alternative Names (SANs)
  example.com
  www.example.com

[*] TLS
  Version       TLS 1.3
  Cipher        TLS_AES_128_GCM_SHA256
```

Status labels: `[OK]` · `[EXPIRING SOON]` (≤30 days) · `[EXPIRED]`

---

---

## sek whois

Query WHOIS information for a domain.

### Usage

```bash
sek whois -d <domain> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-r` | Show raw WHOIS response |

### Examples

```bash
# Parsed output
sek whois -d example.com

# Raw response
sek whois -d example.com -r
```

### Output

```
[*] WHOIS lookup for: example.com

[*] Querying: whois.verisign-grs.com

[*] Domain Info
  Registrar     MarkMonitor Inc.
  Created       1997-09-15T04:00:00Z
  Updated       2024-01-01T00:00:00Z
  Expires       2028-09-14T04:00:00Z
  Status        clientDeleteProhibited
  DNSSEC        unsigned

[*] Name Servers
  ns1.example.com
  ns2.example.com
```

> Note: Some TLDs (e.g. `.gr`) do not operate a public WHOIS server on port 43. For those, `sek whois` displays TLD registry info from IANA and shows a link to the web-based lookup (e.g. `https://grweb.ics.forth.gr/` for `.gr`).

---

---

## sek scan

Scan a host for open ports, identify running services, and detect firewall filtering.

Uses TCP connect scanning — no root required.

### Usage

```bash
sek scan -d <domain or IP> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `-d` | Target domain or IP (required) |
| `-p` | Ports to scan: comma-separated or range (e.g. `80,443` or `1-1000`). Default: top 84 common ports |
| `-t` | Connection timeout in milliseconds (default: 2000) |
| `--all` | Scan all 65535 ports |

### Examples

```bash
# Default scan (top 84 common ports)
sek scan -d example.com

# Specific ports
sek scan -d example.com -p 22,80,443,3306

# Port range
sek scan -d example.com -p 1-1000

# Full scan
sek scan -d example.com --all

# Save results to file
sek scan -d example.com -o results.txt
```

### Output

```
[*] Port scan for: example.com (93.184.216.34)

[*] Scanning 84 ports...

  PORT         STATE      SERVICE              VERSION
  ------------------------------------------------------------------
  22/tcp       open       SSH                  OpenSSH_8.4p1 Ubuntu
  80/tcp       open       HTTP                 nginx/1.18.0
  443/tcp      open       HTTPS                nginx/1.18.0

  PORT         STATE      SERVICE
  ------------------------------------------------------------------
  3306/tcp     filtered   MySQL
  5432/tcp     filtered   PostgreSQL

[*] Done. 3 open  |  2 filtered  |  79 closed
```

Port states:
- **open** — port is accepting connections (service is running)
- **filtered** — firewall is dropping packets (port is protected)
- **closed** — host actively refused the connection (no service, no firewall)

---

## Requirements

- Go 1.21+
- macOS or Linux

---

## License

MIT
