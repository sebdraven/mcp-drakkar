package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// NativeStringsInput is single-sample only, like --native.
type NativeStringsInput struct {
	Input string `json:"input" jsonschema:"absolute path to one APK, one XAPK (its base and ABI splits are read) or one raw ELF recognised by its magic"`

	OutDir string `json:"out_dir" jsonschema:"absolute directory for this call's output; the whole report is written there as <sha256 of the input>.native_strings.json. Required: a large library yields hundreds of thousands of strings, and they never go to a temporary directory"`

	Patterns  []string `json:"patterns,omitempty" jsonschema:"case-insensitive substrings; only the strings containing one of them are kept in strings, while every count, crates, c_libraries and crypto_constants still cover all strings. Omitted, every string"`
	MinLength *int     `json:"min_length,omitempty" jsonschema:"minimum string length in characters, at least 1; omitted, Drakkar's own default applies"`
	ELF       string   `json:"elf,omitempty" jsonschema:"restrict the analysis to one ELF: its entry path (lib/arm64-v8a/libfoo.so), <split>!<entry> for an XAPK split (config.arm64_v8a!lib/arm64-v8a/libfoo.so), or the file name for a raw ELF. One that names no ELF fails the run after the report is written, with elfs_not_selected filled"`
	Xrefs     bool     `json:"xrefs,omitempty" jsonschema:"for each string and constant, the AArch64 instructions that form its address and the function holding them, over all the code; AArch64 only"`
	Crates    bool     `json:"crates,omitempty" jsonschema:"Rust crates named by the source paths found in the strings, and banners of statically linked C libraries"`

	MaxRows *int `json:"max_rows,omitempty" jsonschema:"how many strings to return inline, across all ELFs in report order; tails.strings.total counts them all, and every string stays in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeStrings runs --native-strings.
func (s *Service) NativeStrings(ctx context.Context, in NativeStringsInput) (*Envelope, error) {
	input, err := s.resolveOne("input", in.Input)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.OutDir) == "" {
		return nil, fmt.Errorf("out_dir is required: the report holds every string of every ELF, so it never goes to a temporary directory")
	}
	if !filepath.IsAbs(in.OutDir) {
		return nil, fmt.Errorf("out_dir must be an absolute path, got %q", in.OutDir)
	}
	if err := checkNativeStrings(in); err != nil {
		return nil, err
	}
	sum, err := sha256File(input)
	if err != nil {
		return nil, fmt.Errorf("hashing the input to name its report <sha256>.native_strings.json: %w", err)
	}
	out, err := s.begin("native_strings", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file(sum + ".native_strings.json")
	if err != nil {
		return nil, err
	}
	// Drakkar fails before creating the report when the input is unreadable or
	// the flag unknown: an earlier run's report must not pass for this one's.
	if err := os.Remove(reportPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("removing the earlier report at %s: %w", reportPath, err)
	}
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeStringsArgs(input, reportPath, in))
	if err != nil {
		return nil, err
	}
	unknownFlagNote(env, "--native-strings", "0.6.0")
	if env.Drakkar.ExitCode != 0 {
		if line := errorLine(env.Stderr.Text); line != "" {
			env.note("Drakkar's message, verbatim: " + line)
		}
	}
	noteNativeStringsStderr(env)
	if err := s.finishNativeStrings(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

func checkNativeStrings(in NativeStringsInput) error {
	if n := in.MinLength; n != nil && *n < 1 {
		return fmt.Errorf("min_length %d is out of bounds: at least 1", *n)
	}
	for i, p := range in.Patterns {
		if p == "" {
			return fmt.Errorf("patterns[%d] is empty: a pattern of zero length matches every string; omit patterns to keep them all", i)
		}
	}
	return nil
}

// nativeStringsArgs puts the patterns right after --native-strings, before any
// other option.
func nativeStringsArgs(input, reportPath string, in NativeStringsInput) *drakkar.Args {
	return drakkar.New().Positional(input).
		Optional("--native-strings", in.Patterns).
		Int("--min-length", in.MinLength).
		ValueIf("--elf", in.ELF).
		SwitchIf("--xrefs", in.Xrefs).
		SwitchIf("--crates", in.Crates).
		JSONReport(reportPath)
}

// noteNativeStringsStderr copies every [AVERT] and [FAIL] line into the notes,
// verbatim: each names the ELF it is about.
func noteNativeStringsStderr(env *Envelope) {
	for _, line := range strings.Split(env.Stderr.Text, "\n") {
		if strings.HasPrefix(line, "[AVERT]") || strings.HasPrefix(line, "[FAIL]") {
			env.note(strings.TrimRight(line, "\r "))
		}
	}
}

// nativeStringsReport is the report read in one pass: the strings past the
// preview are counted and skipped, never held.
type nativeStringsReport struct {
	head         map[string]any
	elfs         []any
	strings      []any
	stringsTotal int
	notSelected  []any
	errors       []any
}

// nativeStringsELFKeys are the per-ELF fields returned; strings is a tail of
// its own.
var nativeStringsELFKeys = map[string]bool{
	"elf": true, "split": true, "elf_sha256": true, "machine": true, "summary": true,
	"crates": true, "c_libraries": true, "crypto_constants": true,
}

// finishNativeStrings puts sha256, input, options and limits in the head, and
// four tails beside it: elfs, elfs_not_selected and errors whole, strings cut
// at maxRows.
func (s *Service) finishNativeStrings(env *Envelope, path string, maxRows int) error {
	f, err := os.Open(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			env.note("no JSON report was produced, which is consistent with the exit code above")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	defer f.Close()
	r, err := readNativeStrings(bufio.NewReader(f), maxRows)
	if err != nil {
		if !env.Drakkar.Complete {
			env.note(fmt.Sprintf("the report at %s could not be parsed, which is consistent with a run that did not complete: %v", path, err))
			return nil
		}
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	preview := Tail{
		Total:     r.stringsTotal,
		Returned:  len(r.strings),
		Truncated: len(r.strings) < r.stringsTotal,
		Items:     r.strings,
	}
	env.Result = r.head
	env.Tails = map[string]Tail{
		"elfs":              makeTail(r.elfs, len(r.elfs)),
		"strings":           preview,
		"elfs_not_selected": makeTail(r.notSelected, len(r.notSelected)),
		"errors":            makeTail(r.errors, len(r.errors)),
	}
	env.ReportPath = path

	if len(r.strings) < r.stringsTotal {
		env.note(fmt.Sprintf("strings: %d of %d shown, in report order (ELF after ELF, by vaddr); every string is in report_path", len(r.strings), r.stringsTotal))
	}
	switch {
	case len(r.elfs) == 0 && len(r.notSelected) > 0:
		env.note("elf named none of the ELFs in this input; elfs_not_selected lists those it could have named")
	case len(r.elfs) == 0:
		env.note("the report lists no ELF: none was found in this input, recognised by content")
	}
	if len(r.errors) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report: what could not be read is absent from every count", len(r.errors)))
	}
	return nil
}

func readNativeStrings(rd io.Reader, maxRows int) (*nativeStringsReport, error) {
	dec := json.NewDecoder(rd)
	r := &nativeStringsReport{head: map[string]any{}, elfs: []any{}, strings: []any{}}
	err := eachKey(dec, func(key string) error {
		switch key {
		case "elfs":
			return eachItem(dec, func() error { return r.readELF(dec, maxRows) })
		case "elfs_not_selected":
			return dec.Decode(&r.notSelected)
		case "errors":
			return dec.Decode(&r.errors)
		default:
			var v any
			if err := dec.Decode(&v); err != nil {
				return err
			}
			r.head[key] = v
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	if r.notSelected == nil {
		r.notSelected = []any{}
	}
	if r.errors == nil {
		r.errors = []any{}
	}
	return r, nil
}

func (r *nativeStringsReport) readELF(dec *json.Decoder, maxRows int) error {
	row := map[string]any{}
	err := eachKey(dec, func(key string) error {
		switch {
		case key == "strings":
			return eachItem(dec, func() error {
				r.stringsTotal++
				if len(r.strings) < maxRows {
					var v any
					if err := dec.Decode(&v); err != nil {
						return err
					}
					r.strings = append(r.strings, v)
					return nil
				}
				var skip json.RawMessage
				return dec.Decode(&skip)
			})
		case nativeStringsELFKeys[key]:
			var v any
			if err := dec.Decode(&v); err != nil {
				return err
			}
			row[key] = v
			return nil
		default:
			var skip json.RawMessage
			return dec.Decode(&skip)
		}
	})
	if err != nil {
		return err
	}
	r.elfs = append(r.elfs, row)
	return nil
}

// eachKey walks one JSON object; fn must consume the value of each key.
func eachKey(dec *json.Decoder, fn func(string) error) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected an object key, got %v", tok)
		}
		if err := fn(key); err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

// eachItem walks one JSON array, null read as empty; fn must consume one item.
func eachItem(dec *json.Decoder, fn func() error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected an array, got %v", tok)
	}
	for dec.More() {
		if err := fn(); err != nil {
			return err
		}
	}
	return expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %v, got %v", want, tok)
	}
	return nil
}
