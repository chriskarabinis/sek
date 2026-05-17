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

## Requirements

- Go 1.21+
- macOS or Linux

---

## License

MIT
