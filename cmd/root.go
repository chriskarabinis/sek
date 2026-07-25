package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/output"
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

// Global flags available to all commands.
var (
	globalOutput  string
	globalNoColor bool
	globalFormat  string
)

// newWriter builds the output writer from the global flags. Callers must Close
// it, which is what flushes and closes any -o file.
func newWriter() (*output.Writer, error) {
	format, err := output.ParseFormat(globalFormat)
	if err != nil {
		return nil, err
	}
	return output.New(output.Options{
		OutputFile: globalOutput,
		NoColor:    globalNoColor,
		Format:     format,
	})
}

// commandContext returns a context cancelled on interrupt, so a long scan stops
// on Ctrl+C instead of being killed mid-render with the output file half
// written.
func commandContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// banner is built at startup rather than at package-var init so it picks up
// the version resolved from ldflags or build info.
func banner() string {
	return "\033[93m" + `
 ___  ___  _  __
/ __|| __|| |/ /
\__ \| _| | ' <
|___/|___||_|\_\
` + "\033[0m" + `
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
	Use:           "sek",
	Short:         "sek — Cloud CLI Kit",
	SilenceUsage:  true,
	SilenceErrors: true,
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

// Execute runs the CLI, reporting errors on stderr with a non-zero exit code so
// the tool composes properly in scripts.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}
}

func init() {
	version = resolveVersion()
	rootCmd.Long = banner()
	rootCmd.PersistentFlags().StringVarP(&globalOutput, "output", "o", "", "Save results to file (e.g. -o results.txt)")
	rootCmd.PersistentFlags().BoolVar(&globalNoColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().StringVarP(&globalFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(versionCmd)
}
