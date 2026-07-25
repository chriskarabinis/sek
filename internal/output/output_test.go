package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"text", FormatText, false},
		{"json", FormatJSON, false},
		{"JSON", FormatJSON, false},
		{"  json  ", FormatJSON, false},
		{"", FormatText, false},
		{"yaml", "", true},
		{"xml", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFormat(%q) = %q, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestFileOutputHasNoAnsi checks the -o path: colour belongs on the terminal,
// never in the file.
func TestFileOutputHasNoAnsi(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")

	w, err := New(Options{OutputFile: path, Format: FormatText})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	w.color = true // force colour on, as if stdout were a terminal

	w.Highlight("highlighted line")
	w.Line("plain line")
	w.Field(8, "Label", "value")
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "\033") {
		t.Errorf("output file contains ANSI escapes: %q", content)
	}
	for _, want := range []string{"highlighted line", "plain line", "Label", "value"} {
		if !strings.Contains(content, want) {
			t.Errorf("output file is missing %q; got %q", want, content)
		}
	}
}

// TestJSONModeSuppressesText makes sure narration cannot corrupt the document
// on stdout, so commands can call the text helpers unconditionally.
func TestJSONModeSuppressesText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")

	w, err := New(Options{OutputFile: path, Format: FormatJSON})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	w.Header("Scanning %s", "example.com")
	w.Section("Querying...")
	w.Line("progress noise")
	w.Highlight("more noise")

	payload := map[string]any{"domain": "example.com", "count": 2}
	if err := w.JSON(payload); err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\ncontent: %s", err, data)
	}
	if decoded["domain"] != "example.com" {
		t.Errorf("decoded domain = %v, want example.com", decoded["domain"])
	}
	if strings.Contains(string(data), "progress noise") {
		t.Error("text output leaked into the JSON document")
	}
}

// TestJSONIsNoOpInTextMode is the mirror image: a command calling JSON while
// rendering text must not emit a document.
func TestJSONIsNoOpInTextMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")

	w, err := New(Options{OutputFile: path, Format: FormatText})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	w.Line("rendered text")
	if err := w.JSON(map[string]string{"unwanted": "document"}); err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	w.Close()

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "unwanted") {
		t.Errorf("JSON document written while in text mode: %q", data)
	}
}

func TestNewRejectsUnwritablePath(t *testing.T) {
	if _, err := New(Options{OutputFile: filepath.Join(t.TempDir(), "missing-dir", "out.txt")}); err == nil {
		t.Error("New with an unwritable path returned no error")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	w, err := New(Options{OutputFile: filepath.Join(t.TempDir(), "out.txt")})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}

func TestColorDisabledForNonTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatalf("cannot create temp file: %v", err)
	}
	defer f.Close()

	if colorEnabled(f, false) {
		t.Error("colorEnabled() = true for a regular file; piping must stay clean")
	}
	if colorEnabled(f, true) {
		t.Error("colorEnabled() = true despite NoColor")
	}
}
