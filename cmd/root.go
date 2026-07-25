package cmd

import (
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

const (
	yellow = "\033[93m"
	reset  = "\033[0m"
)

// fallbackVersion is what a plain `go build` reports. Release builds overwrite
// `version` at link time; `go install module@vX` picks the tag up from the
// embedded build info instead. It must stay a plain string literal for the
// linker's -X to apply.
const fallbackVersion = "0.1.6"

var version = fallbackVersion

// releaseTag matches a clean release version such as "v0.1.7". The
// pseudo-versions Go synthesises for a build inside a work tree
// ("v0.0.0-20260725164926-23e2cfa54d6e+dirty") deliberately do not match, so
// a local `go build` keeps reporting the compiled-in value.
var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// resolveVersion prefers a version stamped in by -ldflags, then the tag
// recorded by `go install module@vX.Y.Z`, and finally the compiled-in fallback.
func resolveVersion() string {
	if version != fallbackVersion {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && releaseTag.MatchString(info.Main.Version) {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return fallbackVersion
}

// Global flags available to all commands
var (
	globalOutput  string
	globalNoColor bool
	outFile       *os.File
)

// isColorEnabled returns true if colors should be used.
// Colors are disabled when --no-color is set or output is piped (not a terminal).
func isColorEnabled() bool {
	if globalNoColor {
		return false
	}
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// Col wraps text in yellow if colors are enabled, otherwise returns plain text
func Col(s string) string {
	if !isColorEnabled() {
		return s
	}
	return yellow + s + reset
}

// InitOutput opens the output file if -o was specified. Call at start of each command.
func InitOutput() {
	if globalOutput == "" {
		return
	}
	f, err := os.Create(globalOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot create output file: %s\n", err)
		os.Exit(1)
	}
	outFile = f
}

// CloseOutput closes the output file. Call via defer after InitOutput.
func CloseOutput() {
	if outFile != nil {
		outFile.Close()
		outFile = nil
	}
}

// WriteLine writes plain text to stdout and to the output file if -o is set
func WriteLine(line string) {
	fmt.Println(line)
	if outFile != nil {
		outFile.WriteString(line + "\n")
	}
}

// WriteLineColored writes colored text to stdout and plain text to file
func WriteLineColored(colored, plain string) {
	if isColorEnabled() {
		fmt.Println(colored)
	} else {
		fmt.Println(plain)
	}
	if outFile != nil {
		outFile.WriteString(plain + "\n")
	}
}

// banner is built at startup rather than at package-var init so it picks up
// the version resolved from ldflags or build info.
func banner() string {
	return yellow + `
 ___  ___  _  __
/ __|| __|| |/ /
\__ \| _| | ' <
|___/|___||_|\_\
` + reset + `
Cloud CLI Kit — by Chris Karabinis
Version ` + version + `

Available commands:
  sek sub      — Subdomain enumeration
  sek dns      — DNS record lookup
  sek cert     — SSL/TLS certificate info
  sek whois    — WHOIS domain lookup
  sek scan     — Port scanner
  sek headers  — HTTP security headers checker
  sek ip       — IP geolocation lookup
  sek tf       — Technology fingerprinting
  sek update     — Update to the latest version
  sek uninstall  — Remove sek from your system
  sek version    — Show current version`
}

var rootCmd = &cobra.Command{
	Use:   "sek",
	Short: "sek — Cloud CLI Kit",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sek version %s\n", version)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	version = resolveVersion()
	rootCmd.Long = banner()
	rootCmd.PersistentFlags().StringVarP(&globalOutput, "output", "o", "", "Save results to file (e.g. -o results.txt)")
	rootCmd.PersistentFlags().BoolVar(&globalNoColor, "no-color", false, "Disable colored output")
	rootCmd.AddCommand(versionCmd)
}
