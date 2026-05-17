package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	yellow  = "\033[93m"
	reset   = "\033[0m"
	version = "0.1.2"
)

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

var rootCmd = &cobra.Command{
	Use:   "sek",
	Short: "sek — Cloud CLI Kit",
	Long: yellow + `
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
  sek update   — Update to the latest version
  sek version  — Show current version`,
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
	rootCmd.PersistentFlags().StringVarP(&globalOutput, "output", "o", "", "Save results to file (e.g. -o results.txt)")
	rootCmd.PersistentFlags().BoolVar(&globalNoColor, "no-color", false, "Disable colored output")
	rootCmd.AddCommand(versionCmd)
}
