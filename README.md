# sek — Cloud CLI Kit

```
 ___  ___  _  __
/ __|| __|| |/ /
\__ \| _| | ' <
|___/|___||_|\_\
```

A fast, modular security toolkit for the terminal. Written in Go — single binary, no dependencies.

---

## Installation

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
| `-o` | `--output` | Save results to file |
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
```

### Flags

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain (required) |
| `-t` | `--type` | Record type: A, MX, NS, TXT, CNAME (default: all) |

### Examples

```bash
# All records
sek dns -d example.com

# Specific record type
sek dns -d example.com -t MX
sek dns -d example.com -t TXT
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
  NS      ns2.example.com

[*] TXT
  TXT     v=spf1 include:_spf.example.com ~all

[*] CNAME
  No records found.

[*] Platform detected: Cloudflare
```

Detects platforms via NS records, CNAME patterns, and IP ranges. Supports global providers (Cloudflare, AWS, Azure, Akamai, Fastly) and Greek providers (Papaki, Top.Host, Forthnet, Cosmote).

---

## Requirements

- Go 1.21+
- macOS or Linux

---

## License

MIT
