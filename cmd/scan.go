package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/output"
	"github.com/chriskarabinis/sek/internal/scanx"
)

var (
	scanTarget      string
	scanPorts       string
	scanTimeout     int
	scanAll         bool
	scanShowFilter  bool
	scanConcurrency int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Port scanner",
	Long:  `Scan a host for open ports. Detects services, banners, and firewall filtering.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ports, err := selectPorts()
		if err != nil {
			return err
		}

		ctx, stop := commandContext()
		defer stop()

		ip, err := scanx.Resolve(scanTarget)
		if err != nil {
			return err
		}

		label := scanTarget
		if ip != scanTarget {
			label = fmt.Sprintf("%s (%s)", scanTarget, ip)
		}
		w.Header("Port scan for: %s", label)
		w.Section("Scanning %d ports...", len(ports))
		w.Blank()

		res, err := scanx.Scan(ctx, scanTarget, ports, scanx.Options{
			Timeout:     time.Duration(scanTimeout) * time.Millisecond,
			Concurrency: scanConcurrency,
		})
		if err != nil {
			return err
		}

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderScan(w, res)
		return nil
	},
}

// selectPorts resolves --all, -p or the built-in default set.
func selectPorts() ([]int, error) {
	switch {
	case scanAll:
		return scanx.AllPorts(), nil
	case scanPorts != "":
		return scanx.ParsePorts(scanPorts)
	default:
		return scanx.DefaultPorts, nil
	}
}

func renderScan(w *output.Writer, res *scanx.Result) {
	const ruleWidth = 66

	w.Highlightf("  %-12s %-10s %-20s %s", "PORT", "STATE", "SERVICE", "VERSION")
	w.Rule(ruleWidth)

	for _, p := range res.OpenPorts() {
		w.Highlightf("  %-12s %-10s %-20s %s",
			fmt.Sprintf("%d/tcp", p.Port), p.State, orDash(p.Service), orDash(p.Version))
	}

	// Filtered ports are hidden by default: on a wide scan they are the bulk of
	// the output and say little on their own.
	if scanShowFilter {
		if filtered := res.FilteredPorts(); len(filtered) > 0 {
			w.Blank()
			w.Highlightf("  %-12s %-10s %-20s", "PORT", "STATE", "SERVICE")
			w.Rule(ruleWidth)
			for _, p := range filtered {
				w.Highlightf("  %-12s %-10s %-20s",
					fmt.Sprintf("%d/tcp", p.Port), p.State, orDash(p.Service))
			}
		}
	}

	if res.Open == 0 && res.Filtered == 0 {
		w.Note("No open or filtered ports found.")
	}

	w.Blank()
	w.Highlightf("[*] Done. %d open  |  %d filtered  |  %d closed", res.Open, res.Filtered, res.Closed)
	w.Blank()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	scanCmd.Flags().StringVarP(&scanTarget, "domain", "d", "", "Target domain or IP (e.g. example.com or 1.2.3.4)")
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "", "Ports: comma-separated or range (e.g. 80,443 or 1-1000)")
	scanCmd.Flags().IntVarP(&scanTimeout, "timeout", "t", 2000, "Connection timeout in milliseconds")
	scanCmd.Flags().BoolVar(&scanAll, "all", false, "Scan all 65535 ports")
	scanCmd.Flags().BoolVar(&scanShowFilter, "filter", false, "Also show filtered (firewalled) ports")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 300, "Number of ports probed in parallel")
	scanCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(scanCmd)
}
