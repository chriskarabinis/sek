<div align="center">

<pre>
 ___  ___  _  __
/ __|| __|| |/ /
\__ \| _| | ' &lt;
|___/|___||_|\_\
</pre>

# sek — Cloud CLI Kit

**A single-binary reconnaissance toolkit for the terminal.**
DNS, subdomains, certificates, WHOIS, port scanning, HTTP security headers, IP
geolocation and technology fingerprinting — one tool, one consistent interface,
no setup.

[github.com/chriskarabinis/sek](https://github.com/chriskarabinis/sek)

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/chriskarabinis/sek?style=flat-square&color=success&label=Release)](https://github.com/chriskarabinis/sek/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/chriskarabinis/sek/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/chriskarabinis/sek/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey?style=flat-square)](#requirements)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

</div>

---

## Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command overview](#command-overview)
- [Global flags](#global-flags)
- [JSON output](#json-output)
- [Shell completion](#shell-completion)
- [Command reference](#command-reference)
  - [sek sub](#sek-sub--subdomain-enumeration)
  - [sek dns](#sek-dns--dns-records--platform-detection)
  - [sek cert](#sek-cert--tls-certificate-inspection)
  - [sek whois](#sek-whois--domain-registration-lookup)
  - [sek scan](#sek-scan--tcp-port-scanning)
  - [sek headers](#sek-headers--http-security-headers)
  - [sek ip](#sek-ip--ip-geolocation)
  - [sek tf](#sek-tf--technology-fingerprinting)
  - [sek update](#sek-update--self-update)
  - [sek uninstall](#sek-uninstall--removal)
- [Requirements](#requirements)
- [Development](#development)
- [Architecture](#architecture)
- [Responsible use](#responsible-use)
- [License](#license)

---

## Overview

`sek` exists to replace the habit of downloading and juggling a different tool
for every routine reconnaissance task. Everything is in one binary, every
command takes the same flags, and every command can emit JSON.

| | |
|---|---|
| **Single binary** | No runtime, no dependencies, no configuration file. Written in Go. |
| **Consistent interface** | Every command takes `-d` for its target and supports `-o`, `-f` and `--no-color`. |
| **Scriptable** | `-f json` on any command; errors go to stderr with a non-zero exit code. |
| **Unprivileged** | TCP connect scanning rather than SYN, so no root is required. |

It is also a deliberate exercise in understanding how security tooling is built
from the ground up, as part of growing as a SysAdmin and DevOps engineer.

---

## Installation

### Install script — recommended (macOS and Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/chriskarabinis/sek/main/install.sh | bash
```

### Go toolchain

```bash
go install github.com/chriskarabinis/sek@latest
```

### From source

```bash
git clone https://github.com/chriskarabinis/sek.git
cd sek
go build -o sek
sudo mv sek /usr/local/bin/
```

---

## Quick start

```bash
sek dns     -d example.com          # every record type plus platform detection
sek sub     -d example.com          # subdomains from CT logs and brute force
sek cert    -d example.com          # certificate expiry, issuer, SANs, TLS version
sek scan    -d example.com          # top 84 ports with service and banner detection
sek headers -d example.com          # security-header audit with a weighted score
```

---

## Command overview

| Command | Purpose |
|---------|---------|
| [`sek sub`](#sek-sub--subdomain-enumeration) | Subdomain enumeration via certificate transparency logs and DNS brute force |
| [`sek dns`](#sek-dns--dns-records--platform-detection) | DNS record lookup, email-security records, wildcard and platform detection |
| [`sek cert`](#sek-cert--tls-certificate-inspection) | TLS certificate expiry, issuer, SANs, chain, negotiated cipher |
| [`sek whois`](#sek-whois--domain-registration-lookup) | WHOIS registration data — registrar, dates, nameservers, status |
| [`sek scan`](#sek-scan--tcp-port-scanning) | TCP port scanning with service identification and firewall detection |
| [`sek headers`](#sek-headers--http-security-headers) | HTTP security-header audit with a weighted score and remediation |
| [`sek ip`](#sek-ip--ip-geolocation) | IP geolocation — country, city, ISP, organisation, ASN |
| [`sek tf`](#sek-tf--technology-fingerprinting) | Technology fingerprinting — server, language, CMS, frameworks, CDN |
| [`sek update`](#sek-update--self-update) | Checksum-verified, atomic self-update |
| [`sek uninstall`](#sek-uninstall--removal) | Remove the binary from the system |

---

## Global flags

Available on every command.

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Write results to a file in addition to stdout |
| `-f`, `--format` | Output format: `text` (default) or `json` |
| `--no-color` | Disable ANSI colour. Also disabled automatically when stdout is not a terminal, or when `NO_COLOR` is set |

---

## JSON output

Every command can emit its result as a single JSON document, which makes `sek`
composable with `jq` and anything else that reads a pipe.

```bash
sek dns     -d example.com -f json | jq -r '.sections[].records[].value'
sek scan    -d example.com -f json | jq '.ports[] | select(.state == "open") | .port'
sek headers -d example.com -f json | jq '.score, .rating'
sek cert    -d example.com -f json | jq -r '.days_left'
```

In JSON mode progress messages are suppressed and warnings are routed to stderr,
so stdout always holds exactly one document. `-o` writes that same document to a
file.

Failures set a non-zero exit code, so they are detectable in scripts:

```bash
if ! sek cert -d example.com --expiry-days 30 >/dev/null; then
  echo "certificate needs renewing"
fi
```

---

## Shell completion

Tab completion for all commands and flags.

```bash
# zsh
echo 'source <(sek completion zsh)' >> ~/.zshrc && source ~/.zshrc

# bash
echo 'source <(sek completion bash)' >> ~/.bashrc && source ~/.bashrc
```

---

## Command reference

### `sek sub` — subdomain enumeration

Discovers subdomains from two independent sources:

- **Certificate transparency logs** — queries [crt.sh](https://crt.sh) for names
  appearing in published certificates.
- **DNS brute force** — resolves a built-in list of 214 common prefixes through
  a bounded worker pool.

```bash
sek sub -d <domain> [flags]
```

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain (required) |
| `-w` | `--wordlist` | Custom wordlist file |
|      | `--concurrency` | Parallel DNS lookups (default: 50) |

```bash
sek sub -d example.com
sek sub -d example.com -o results.txt
sek sub -d example.com -w wordlist.txt
sek sub -d example.com --concurrency 100
```

**Wildcard DNS.** A domain with a `*.example.com` record answers for every name,
which would make brute force report every word in the list as a real subdomain.
`sek sub` probes for a wildcard first, filters out hits that resolve only to the
wildcard addresses, and reports how many it dropped.

```
[!] Wildcard DNS detected: *.example.com  ->  203.0.113.10
    Brute-force hits resolving only to these addresses will be filtered.
```

**Output.**

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

**Custom wordlists.** Plain text, one entry per line; blank lines and lines
starting with `#` are ignored.

```
# My wordlist
www
api
admin
```

For deeper enumeration, point it at [SecLists](https://github.com/danielmiessler/SecLists):

```bash
sek sub -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

### `sek dns` — DNS records + platform detection

Queries every common record type and infers the hosting or CDN provider behind
the domain.

```bash
sek dns -d <domain> [flags]
sek dns -r <ip>
```

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain (required unless `-r` is used) |
| `-t` | `--type` | Record type: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`, `EMAIL` (default: all) |
| `-s` | `--server` | Upstream DNS server (e.g. `8.8.8.8`), also used by `-r` |
| `-r` | `--reverse` | Reverse lookup for an IP address |

`A` and `AAAA` select the same section, which reports both address families.

```bash
sek dns -d example.com
sek dns -d example.com -t MX
sek dns -d example.com -t EMAIL
sek dns -d example.com -s 1.1.1.1
sek dns -r 8.8.8.8
```

**Output.**

```
[*] DNS lookup for: example.com

[*] A / AAAA
  A       93.184.216.34                    TTL: 300s

[*] MX
  MX      mail.example.com (priority: 10)  TTL: 3600s

[*] Email Security (SPF / DMARC / DKIM)
  SPF     v=spf1 include:_spf.example.com ~all
  DMARC   v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  DKIM    [google] v=DKIM1; k=rsa; p=...

[*] Wildcard DNS
  No wildcard DNS detected.

[*] Platform detected: Cloudflare
```

TTL is shown for every record. Platform detection works through nameservers,
CNAME targets and published IP ranges, matched as real CIDRs rather than string
prefixes. It covers global providers (Cloudflare, AWS, Azure, Akamai, Fastly,
DigitalOcean, Hetzner, OVH) and Greek providers (Fastpath, Papaki, Top.Host,
Forthnet, Cosmote, Cyta).

`EMAIL` probes SPF, DMARC and DKIM at ten common selectors. There is no way to
enumerate DKIM selectors, so absence is not proof that none exists.

---

### `sek cert` — TLS certificate inspection

```bash
sek cert -d <domain> [flags]
```

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-p` | Port (default: `443`) |
| `-c` | Show the full presented chain |
| `--insecure` | Skip verification, for self-signed certificates |
| `--expiry-days N` | Exit non-zero if the certificate expires within N days |

```bash
sek cert -d example.com
sek cert -d example.com -c
sek cert -d example.com -p 8443
sek cert -d example.com --expiry-days 30    # for cron or CI
```

**Output.**

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

Status labels: `[OK]` · `[EXPIRING SOON]` (≤ 30 days) · `[CRITICAL]` (≤ 14 days)
· `[EXPIRED]`.

Expiry is decided by comparing the certificate's `NotAfter` against the current
time, not by the rounded day count, so a certificate that lapsed within the last
24 hours is still reported as expired.

---

### `sek whois` — domain registration lookup

```bash
sek whois -d <domain> [flags]
```

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-r` | Show the raw WHOIS response |

```bash
sek whois -d example.com
sek whois -d example.com -r
```

**Output.**

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

Thin registries such as `.com` answer with a referral rather than the
registrant details, so the registrar's own server is queried as well and the
fields are merged. Multi-label public suffixes (`co.uk`, `com.gr`, `act.edu.au`)
are resolved to the registry that actually serves them.

> Some TLDs — `.gr` among them — operate no public WHOIS service on port 43. For
> those, `sek whois` shows the TLD registry data from IANA and a link to the
> web-based lookup.

---

### `sek scan` — TCP port scanning

Connect scanning, so no elevated privileges are needed. Identifies services and
grabs banners from open ports, and distinguishes a firewalled port from a
closed one.

```bash
sek scan -d <domain or IP> [flags]
```

| Flag | Description |
|------|-------------|
| `-d` | Target domain or IP (required) |
| `-p` | Ports: comma-separated or a range, e.g. `80,443` or `1-1000` (default: top 84) |
| `-t` | Connection timeout in milliseconds (default: `2000`) |
| `--all` | Scan all 65535 ports |
| `--filter` | Also show filtered ports |
| `--concurrency` | Ports probed in parallel (default: `300`) |

```bash
sek scan -d example.com
sek scan -d example.com -p 22,80,443,3306
sek scan -d example.com -p 1-1000
sek scan -d example.com --all --concurrency 500
sek scan -d example.com --filter
```

IPv6 targets, IPv4 targets and hostnames are all supported.

**Output.**

```
[*] Port scan for: example.com (93.184.216.34)

[*] Scanning 84 ports...

  PORT         STATE      SERVICE              VERSION
  ------------------------------------------------------------------
  22/tcp       open       SSH                  OpenSSH_8.4p1 Ubuntu
  80/tcp       open       HTTP                 nginx/1.18.0
  443/tcp      open       HTTPS                nginx/1.18.0

[*] Done. 3 open  |  2 filtered  |  79 closed
```

| State | Meaning |
|-------|---------|
| `open` | The port accepted the connection — a service is listening |
| `filtered` | The connection timed out — a firewall is dropping packets. Hidden unless `--filter` is given, since on a wide scan these dominate the output |
| `closed` | The host actively refused — no service, no firewall |

---

### `sek headers` — HTTP security headers

```bash
sek headers -d <domain> [flags]
```

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-p` | Custom port |
| `--http` | Use HTTP instead of HTTPS |
| `--all` | Show every response header |

```bash
sek headers -d example.com
sek headers -d example.com --http
sek headers -d example.com --all
```

**Output.**

```
[*] HTTP Security Headers for: example.com

[*] Response
  Status            200 OK
  Server            nginx/1.18.0
  Content-Type      text/html; charset=UTF-8

[*] Security Headers
  HEADER                             STATE     VALUE
  --------------------------------------------------------------------------------
  Content-Security-Policy            MISSING   -
  Strict-Transport-Security          PRESENT   max-age=31536000
  X-Frame-Options                    PRESENT   SAMEORIGIN
  X-Content-Type-Options             PRESENT   nosniff
  Referrer-Policy                    PRESENT   strict-origin-when-cross-origin
  Permissions-Policy                 PRESENT   camera=(), microphone=()

[*] Score: 8/11 — Good

[*] Deprecated Headers
  X-XSS-Protection                   DEPRECATED 1; mode=block
```

**Scoring.** Weighted rather than a plain count, because these headers do not
matter equally.

| Header | Points |
|--------|--------|
| `Content-Security-Policy` | 3 |
| `Strict-Transport-Security` | 3 |
| `X-Frame-Options` | 2 |
| `X-Content-Type-Options` | 1 |
| `Referrer-Policy` | 1 |
| `Permissions-Policy` | 1 |

Ratings: `Excellent` (11/11) · `Good` (≥ 70%) · `Fair` (≥ 40%) · `Poor` (< 40%).

`X-XSS-Protection` is deliberately **not** scored. The legacy XSS auditor it
enables introduced injection vectors of its own and has been removed from every
current browser, so current guidance is to drop it or send `0`. `sek` reports it
as a finding when present rather than rewarding its absence.

Redirects are followed, so when the response comes from a different origin than
the one requested, that URL is reported as `Redirected To`.

---

### `sek ip` — IP geolocation

```bash
sek ip -d <IP or domain>
```

```bash
sek ip -d 8.8.8.8
sek ip -d example.com
```

**Output.**

```
[*] IP Lookup for: example.com

  IP              93.184.216.34
  Country         United States (US)
  Region          Massachusetts
  City            Norwood
  Coordinates     42.1615, -71.2065
  Timezone        America/New_York
  ISP             Edgecast Inc.
  Organization    MCI Communications Services
  ASN             AS15133 Edgecast Inc.
```

Fields the service has no data for are omitted rather than shown as blank or
zero values.

> Backed by [ip-api.com](http://ip-api.com) — free, no API key, 45 requests per
> minute. The free tier is HTTP-only, so these lookups are visible to anything
> on the network path.

---

### `sek tf` — technology fingerprinting

Identifies the web server, language, CMS, JavaScript frameworks, analytics and
CDN behind a site from its response headers, cookies and markup. 51 signatures
covering 47 products across 7 categories.

```bash
sek tf -d <domain> [flags]
```

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-p` | Custom port |
| `--http` | Use HTTP instead of HTTPS |

```bash
sek tf -d example.com
sek tf -d example.com --http
sek tf -d example.com -p 8080
```

**Output.**

```
[*] Technology Fingerprint for: example.com

[*] Web Server
  nginx 1.18.0

[*] CMS
  WordPress

[*] JS Library
  jQuery
  Bootstrap

[*] Analytics
  Google Analytics

[*] CDN / Security
  Cloudflare
```

Versions are reported wherever the response reveals them. Markup signatures
match asset references (`jquery.min.js`, `/jquery-`) rather than bare product
names, so an article that merely mentions a library is not reported as using it.

---

### `sek update` — self-update

Detects the operating system and architecture, then downloads the matching
release binary.

```bash
sek update
sudo sek update    # if the install directory is not writable
```

The download is verified against the `checksums.txt` published with each release
and installed with an atomic rename, so an interrupted update leaves the
existing binary intact rather than truncated.

---

### `sek uninstall` — removal

```bash
sek uninstall
sek uninstall --yes    # skip the confirmation prompt
sudo sek uninstall     # if the install directory is not writable
```

The resolved path is shown and confirmation requested first, because the binary
being run is not always the installed one — a `./sek` built in a working copy is
a real possibility.

---

## Requirements

| | |
|---|---|
| **Operating system** | macOS or Linux |
| **Runtime dependencies** | None — `sek` ships as a single self-contained binary |
| **Go** | 1.24 or newer, only when installing via `go install` or building from source |

---

## Development

```bash
go build ./...      # build
go test -race ./... # test suite
go vet ./...        # static analysis
gofmt -l .          # formatting — should print nothing
go mod tidy         # dependency hygiene
```

CI runs all of the above on every push and pull request, plus a cross-compile of
all four release targets (`darwin/amd64`, `darwin/arm64`, `linux/amd64`,
`linux/arm64`).

---

## Architecture

```
cmd/                 cobra commands — flag parsing and rendering only
internal/
  ├── dnsx/          DNS queries, platform detection
  ├── subx/          subdomain enumeration, wordlist handling
  ├── certx/         TLS certificate inspection
  ├── scanx/         TCP connect scanning, service identification
  ├── whoisx/        WHOIS querying and response parsing
  ├── webx/          HTTP security headers, technology fingerprinting
  ├── ipx/           IP geolocation
  └── output/        text and JSON rendering, colour handling
```

The split is deliberate: `cmd/` never contains logic, and each `internal`
package returns typed results rather than printing. That is what both the test
suite and the JSON output are built on — the JSON is the result struct, not a
second rendering path that can drift from the text one.

---

## Responsible use

`sek` performs **active** reconnaissance — it opens TCP connections, brute-forces
DNS names and issues HTTP requests against a target. Use it only against systems
you own or have explicit written permission to test. Unauthorised scanning is
illegal in many jurisdictions.

---

## License

[MIT](LICENSE)

<div align="center">

Built by [Chris Karabinis](https://github.com/chriskarabinis)

</div>
