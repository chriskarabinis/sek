# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`sek` is a security/reconnaissance CLI toolkit built in Go by Chris Karabinis. It follows the git-style subcommand pattern (`sek <command>`), built with [Cobra](https://github.com/spf13/cobra).

Current version: `0.1.6` (in `cmd/root.go`)

## Build & Run

```bash
# Run without building
go run main.go <command> [flags]

# Build binary
go build -o sek .

# Install to system
go build -o sek . && sudo mv sek /usr/local/bin/
```

No test suite exists yet. Debug by running commands directly against real domains (e.g. `fastpath.gr`, `frenzy.gr`, `google.com`).

## Architecture

Every command is a separate file in `cmd/`. Each file:
1. Declares its own flag variables at the top
2. Defines a `var xxxCmd = &cobra.Command{...}` with the logic in `Run:`
3. Registers itself in `func init()` via `rootCmd.AddCommand(xxxCmd)`

`cmd/root.go` is the shared layer — it owns:
- Global constants: `yellow`, `reset` (ANSI colors), `version`
- Global flags: `-o` (output file), `--no-color`
- Output helpers: `WriteLine()`, `WriteLineColored()`, `InitOutput()`, `CloseOutput()`
- The root command banner and `versionCmd`

## Output conventions

Always use `WriteLineColored(colored, plain)` for result lines — colored to stdout, plain to file. Use `WriteLine()` for headers/labels. Never use `fmt.Println` directly in commands.

Color: yellow only (`yellow+text+reset`). Colors auto-disable when piping or `--no-color` is set.

## Releases

Releases are triggered by pushing a git tag:
```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```
GitHub Actions (`.github/workflows/release.yml`) builds binaries for darwin/linux × amd64/arm64 and uploads them to GitHub Releases. Always bump `version` in `cmd/root.go` before tagging.

## Commands overview

| Command | File | Key deps |
|---------|------|----------|
| `sek sub` | `sub.go` | `net` (DNS), `crt.sh` HTTP API |
| `sek dns` | `dns.go` | `github.com/miekg/dns` |
| `sek cert` | `cert.go` | `crypto/tls` |
| `sek whois` | `whois.go` | raw TCP port 43 |
| `sek scan` | `scan.go` | `net` (TCP connect), `crypto/tls` |
| `sek headers` | `headers.go` | `net/http` |
| `sek ip` | `ip.go` | `ip-api.com` (free, no key) |
| `sek tf` | `tf.go` | `net/http`, signature matching |
| `sek update` | `update.go` | GitHub Releases API |
| `sek uninstall` | `uninstall.go` | `os.Executable()` |

## Key patterns

- **IPv4 preference**: when resolving hostnames, loop through `net.LookupHost` results and pick the first `To4() != nil` address. See `scan.go` and `ip.go`.
- **DNS queries**: use `dnsQuery()` in `dns.go` — it retries with TCP when UDP response is truncated, and skips `fe80::` link-local addresses from `/etc/resolv.conf`.
- **sek scan**: TCP connect scan only (no root required). Shows open ports with banner grabbing, filtered ports only with `--filter` flag. Concurrency via semaphore channel (300 goroutines max).
- **sek tf**: signature-based detection against headers, cookies, and HTML body (capped at 100KB). Results deduplicated by name+category.
- **sek whois**: for TLDs without port-43 WHOIS (e.g. `.gr`), falls back to IANA and shows TLD-level info + web registry URL.
- **sek update**: uses semver comparison (`isNewer()`) to avoid downgrades. Replaces binary via `io.Copy` to handle cross-device filesystem moves.
