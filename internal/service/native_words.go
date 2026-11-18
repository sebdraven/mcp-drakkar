package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// Drakkar's MAX_WORDS_RANGES and MAX_WORDS_COUNT.
const (
	maxWordsRanges = 64
	maxWordsCount  = 512
)

// NativeWordsInput is single-sample only, like --native.
type NativeWordsInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF with an allocated section holding the start of the range"`

	Ranges []string `json:"ranges" jsonschema:"1 to 64 ranges <hex address>:<word count>, 0x prefix optional, count decimal from 1 to 512; Drakkar wants the address aligned on 8 and keeps duplicates"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many words to return inline, every range together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeWords runs --native --native-words.
func (s *Service) NativeWords(ctx context.Context, in NativeWordsInput) (*Envelope, error) {
	if err := checkNativeWords(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_words", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file("report.json")
	if err != nil {
		return nil, err
	}
	// A refused run writes no report: an earlier one must not pass for it.
	if err := os.Remove(reportPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("removing the earlier report at %s: %w", reportPath, err)
	}
	// Same class as drakkar_native_xrefs.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeWordsArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeWords(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeWords checks the form only; Drakkar refuses the rest.
func checkNativeWords(in NativeWordsInput) error {
	if len(in.Ranges) == 0 {
		return fmt.Errorf("ranges is empty: give 1 to %d <hex address>:<count>", maxWordsRanges)
	}
	if len(in.Ranges) > maxWordsRanges {
		return fmt.Errorf("%d ranges: give 1 to %d", len(in.Ranges), maxWordsRanges)
	}
	for i, r := range in.Ranges {
		at, count, ok := strings.Cut(r, ":")
		if !ok || !isHexAddress(at) {
			return fmt.Errorf("ranges[%d] %q is not <hex address>:<count>", i, r)
		}
		n, err := strconv.ParseUint(count, 10, 64)
		if err != nil || n < 1 || n > maxWordsCount {
			return fmt.Errorf("ranges[%d] %q: count is a decimal from 1 to %d", i, r, maxWordsCount)
		}
	}
	return nil
}

// nativeWordsArgs builds <elf|*>@<r1>,<r2>,... as Drakkar splits it.
func nativeWordsArgs(apk, reportPath string, in NativeWordsInput) *drakkar.Args {
	return drakkar.New().Positional(apk).Switch("--native").
		Value("--native-words", elfOrStar(in.ELF)+"@"+strings.Join(in.Ranges, ",")).
		JSONReport(reportPath)
}

type nativeWordsReport struct {
	Words  []map[string]any `json:"words"`
	Errors []any            `json:"errors"`
}

// finishNativeWords puts one summary per range in the head, and the words of
// every range in one tail, cut at maxRows.
func (s *Service) finishNativeWords(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-words")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeWordsReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	heads := make([]any, 0, len(r.Words))
	var rows []any
	hint := false
	for _, e := range r.Words {
		heads = append(heads, nativeHead(e, "items"))
		items, _ := e["items"].([]any)
		for _, it := range items {
			rows = append(rows, nativeRow(e, it, "elf", "start"))
		}
		if e["vtable_like"] == true {
			hint = true
		}
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"ranges": heads}
	env.Tails = map[string]Tail{
		"words":  makeTail(nonNil(rows), maxRows),
		"errors": makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Words) == 0 {
		env.note("the report holds no words entry: errors says why")
	}
	if hint {
		env.note("vtable_like is a hint, not a proof: any three words can have the shape of a Rust vtable header")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

func elfOrStar(elf string) string {
	if elf == "" {
		return "*"
	}
	return elf
}

func nonNil(a []any) []any {
	if a == nil {
		return []any{}
	}
	return a
}

// nativeHead copies an entry of the report without its array.
func nativeHead(entry map[string]any, array string) map[string]any {
	head := make(map[string]any, len(entry))
	for k, v := range entry {
		if k != array {
			head[k] = v
		}
	}
	return head
}

// nativeRow copies an item and adds the given keys of its entry, so that rows
// from several entries stay apart.
func nativeRow(entry map[string]any, v any, keys ...string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	row := make(map[string]any, len(m)+len(keys))
	for k, x := range m {
		row[k] = x
	}
	for _, k := range keys {
		if x, ok := entry[k]; ok {
			row[k] = x
		}
	}
	return row
}

// noteNativeModeRefusal relays Drakkar's own message when it wrote no report.
func noteNativeModeRefusal(env *Envelope, flag string) {
	line := errorLine(env.Stderr.Text)
	if strings.Contains(env.Stderr.Text, "unexpected argument '"+flag) {
		env.note("this drakkar does not know " + flag + ": it predates the mode; drakkar_version shows which one is on PATH")
	} else {
		env.note("no JSON report was produced, which is consistent with the exit code above")
	}
	if line == "" {
		return
	}
	env.note("Drakkar's message, verbatim: " + line)
	env.Tails = map[string]Tail{"errors": makeTail([]any{line}, 1)}
}

// checkHexList checks a list of hex addresses, at most maxN distinct, as
// Drakkar drops duplicates before counting.
func checkHexList(name string, list []string, maxN int) error {
	distinct := map[uint64]bool{}
	for i, a := range list {
		if !isHexAddress(a) {
			return fmt.Errorf("%s[%d] %q is not a hex address", name, i, a)
		}
		v, _ := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 64)
		distinct[v] = true
	}
	if len(distinct) > maxN {
		return fmt.Errorf("%s has %d distinct addresses: give 1 to %d", name, len(distinct), maxN)
	}
	return nil
}

// checkNotNegative refuses a negative count.
func checkNotNegative(name string, v *int) error {
	if v != nil && *v < 0 {
		return fmt.Errorf("%s %d is negative", name, *v)
	}
	return nil
}
