package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	yellow  = "\033[93m"
	reset   = "\033[0m"
	version = "0.1.0"
)

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
	rootCmd.AddCommand(versionCmd)
}
