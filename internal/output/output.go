// Package output renders command results to the terminal and, optionally, to a
// file. It owns every decision about colour and formatting so the commands can
// hand it plain strings, and it is the one place that knows whether the run is
// producing human-readable text or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	yellow = "\033[93m"
	reset  = "\033[0m"
)

// Format selects how results are rendered.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText, "":
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unknown format %q (want text or json)", s)
	}
}

// Writer fans output out to stdout and, when -o was given, to a file. The file
// never receives colour escapes.
//
// In JSON mode every text-rendering method is a no-op, so a command can narrate
// its progress unconditionally and still emit a clean document on stdout.
type Writer struct {
	stdout io.Writer
	file   io.WriteCloser
	color  bool
	format Format
}

// Options configures a Writer.
type Options struct {
	// OutputFile is the -o path. Empty means stdout only.
	OutputFile string
	// NoColor forces colour off regardless of whether stdout is a terminal.
	NoColor bool
	// Format selects text or JSON rendering.
	Format Format
}

// New builds a Writer, creating the output file if one was requested.
func New(opts Options) (*Writer, error) {
	w := &Writer{
		stdout: os.Stdout,
		format: opts.Format,
		color:  colorEnabled(os.Stdout, opts.NoColor) && opts.Format == FormatText,
	}

	if opts.OutputFile != "" {
		f, err := os.Create(opts.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("cannot create output file: %w", err)
		}
		w.file = f
	}
	return w, nil
}

// colorEnabled reports whether ANSI colour should be used. Colour is off when
// asked for explicitly or when stdout is not a terminal, so piping stays clean.
// It is evaluated once per run rather than per line, which previously meant a
// stat syscall for every line of output.
func colorEnabled(f *os.File, noColor bool) bool {
	if noColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// IsJSON reports whether the writer is emitting JSON.
func (w *Writer) IsJSON() bool { return w.format == FormatJSON }

// Close releases the output file, if any.
func (w *Writer) Close() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// write sends one line to stdout, coloured if enabled, and the plain text to
// the output file.
func (w *Writer) write(line string, highlight bool) {
	if w.format != FormatText {
		return
	}
	if w.color && highlight && line != "" {
		fmt.Fprintln(w.stdout, yellow+line+reset)
	} else {
		fmt.Fprintln(w.stdout, line)
	}
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

// Line writes plain text.
func (w *Writer) Line(s string) { w.write(s, false) }

// Highlight writes text that should stand out on a colour terminal.
func (w *Writer) Highlight(s string) { w.write(s, true) }

// Highlightf writes formatted text that should stand out.
func (w *Writer) Highlightf(format string, a ...any) { w.write(fmt.Sprintf(format, a...), true) }

// Blank writes an empty line.
func (w *Writer) Blank() { w.write("", false) }

// Header writes the leading "[*] ..." banner of a command, padded with blank
// lines the way every command already presents it.
func (w *Writer) Header(format string, a ...any) {
	w.Blank()
	w.Highlight(fmt.Sprintf("[*] "+format, a...))
	w.Blank()
}

// Section writes an "[*] ..." section title.
func (w *Writer) Section(format string, a ...any) {
	w.Line(fmt.Sprintf("[*] "+format, a...))
}

// Field writes an indented "label  value" pair, aligned to width.
func (w *Writer) Field(width int, label, value string) {
	w.Highlight(fmt.Sprintf("  %-*s  %s", width, label, value))
}

// Note writes an indented informational line without highlighting.
func (w *Writer) Note(format string, a ...any) {
	w.Line("  " + fmt.Sprintf(format, a...))
}

// Warn writes a "[!] ..." line. It goes to stderr in JSON mode so it stays
// visible without corrupting the document on stdout.
func (w *Writer) Warn(format string, a ...any) {
	line := "[!] " + fmt.Sprintf(format, a...)
	if w.format == FormatJSON {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	w.write(line, true)
}

// Rule writes a horizontal separator of the given width.
func (w *Writer) Rule(width int) { w.Line("  " + strings.Repeat("-", width)) }

// JSON encodes v as indented JSON to stdout and to the output file. It is a
// no-op in text mode, so commands can call it unconditionally.
func (w *Writer) JSON(v any) error {
	if w.format != FormatJSON {
		return nil
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode result as JSON: %w", err)
	}
	data = append(data, '\n')

	if _, err := w.stdout.Write(data); err != nil {
		return err
	}
	if w.file != nil {
		if _, err := w.file.Write(data); err != nil {
			return err
		}
	}
	return nil
}
