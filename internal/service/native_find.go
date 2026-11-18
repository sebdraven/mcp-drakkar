package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// maxFindOffsets and maxFindAddresses are the bounds Drakkar puts on
// --native-find-off and --native-find-in.
const (
	maxFindOffsets   = 16
	maxFindAddresses = 64
)

// NativeFindInput is single-sample only, like --native.
type NativeFindInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF"`

	Offsets []string `json:"offsets" jsonschema:"required: 1 to 16 hex structure offsets, 0x prefix optional, a leading - allowed (--native-find-off, always passed attached with =)"`
	Access  []string `json:"access,omitempty" jsonschema:"subset of load, store, addr (--native-find-access); omitted, Drakkar's default"`
	Size    []int    `json:"size,omitempty" jsonschema:"access widths in bytes among 1, 2, 4, 8, 16 (--native-find-size), no effect on addr; omitted, Drakkar's default"`
	Base    string   `json:"base,omitempty" jsonschema:"base register: any, sp or nosp (--native-find-base); omitted, Drakkar's default, which leaves sp out"`
	In      []string `json:"in,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-find-in): keep the functions containing one of them"`
	Max     *int     `json:"max,omitempty" jsonschema:"matches Drakkar renders per ELF (--native-find-max); matches_total, functions_total and functions stay exact; omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many functions and how many matches to return inline, every ELF together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeFind runs --native --native-find.
func (s *Service) NativeFind(ctx context.Context, in NativeFindInput) (*Envelope, error) {
	if err := checkNativeFind(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_find", in.OutDir)
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
	// Same class as drakkar_native_labels: both walk code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeFindArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeFind(env, reportPath, ClampRows(in.MaxRows), in); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeFind checks the form only; Drakkar refuses the rest.
func checkNativeFind(in NativeFindInput) error {
	if len(in.Offsets) == 0 {
		return errors.New("offsets is required: 1 to 16 hex offsets")
	}
	distinct := map[int64]bool{}
	for i, o := range in.Offsets {
		v, ok := signedHexOffset(o)
		if !ok {
			return fmt.Errorf("offsets[%d] %q is not a hex offset (0x optional, - allowed)", i, o)
		}
		distinct[v] = true
	}
	if len(distinct) > maxFindOffsets {
		return fmt.Errorf("offsets has %d distinct values: give 1 to %d", len(distinct), maxFindOffsets)
	}
	for i, a := range in.Access {
		if a != "load" && a != "store" && a != "addr" {
			return fmt.Errorf("access[%d] %q is not load, store or addr", i, a)
		}
	}
	for i, n := range in.Size {
		if n != 1 && n != 2 && n != 4 && n != 8 && n != 16 {
			return fmt.Errorf("size[%d] %d is not 1, 2, 4, 8 or 16", i, n)
		}
	}
	if in.Base != "" && in.Base != "any" && in.Base != "sp" && in.Base != "nosp" {
		return fmt.Errorf("base %q is not any, sp or nosp", in.Base)
	}
	if err := checkHexList("in", in.In, maxFindAddresses); err != nil {
		return err
	}
	return checkNotNegative("max", in.Max)
}

// signedHexOffset reads an offset as Drakkar does: an optional -, an optional
// 0x, then hex digits within a signed 64-bit integer.
func signedHexOffset(s string) (int64, bool) {
	digits, negative := strings.CutPrefix(s, "-")
	digits = strings.TrimPrefix(digits, "0x")
	if digits == "" || len(digits) > 16 {
		return 0, false
	}
	for _, c := range digits {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(digits, 16, 64)
	if err != nil {
		return 0, false
	}
	if negative {
		v = -v
	}
	return v, true
}

// nativeFindArgs joins each list with commas, as Drakkar splits them; a
// negative offset is safe since every value goes attached with '='.
func nativeFindArgs(apk, reportPath string, in NativeFindInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-find", elfOrStar(in.ELF)).
		Value("--native-find-off", strings.Join(in.Offsets, ","))
	if len(in.Access) > 0 {
		args.Value("--native-find-access", strings.Join(in.Access, ","))
	}
	if len(in.Size) > 0 {
		sizes := make([]string, len(in.Size))
		for i, n := range in.Size {
			sizes[i] = strconv.Itoa(n)
		}
		args.Value("--native-find-size", strings.Join(sizes, ","))
	}
	args.ValueIf("--native-find-base", in.Base)
	if len(in.In) > 0 {
		args.Value("--native-find-in", strings.Join(in.In, ","))
	}
	return args.Int("--native-find-max", in.Max).JSONReport(reportPath)
}

type nativeFindReport struct {
	Find   []map[string]any `json:"find"`
	Errors []any            `json:"errors"`
}

// finishNativeFind puts every ELF-level field in the head, and the functions
// and the matches of every ELF, whole, in two tails, each cut at maxRows.
func (s *Service) finishNativeFind(env *Envelope, path string, maxRows int, in NativeFindInput) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-find")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeFindReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	filters := findFilters(in)
	heads := make([]any, 0, len(r.Find))
	var cut, empty []string
	var functions, matches []any
	for _, e := range r.Find {
		heads = append(heads, headWithout(e, "functions", "matches"))
		fns, _ := e["functions"].([]any)
		for _, it := range fns {
			functions = append(functions, nativeRow(e, it, "elf"))
		}
		ms, _ := e["matches"].([]any)
		for _, it := range ms {
			matches = append(matches, nativeRow(e, it, "elf"))
		}
		if e["truncated"] == true {
			cut = append(cut, fmt.Sprintf("matches of %v: Drakkar kept %d of %v, in %v functions (exact totals, functions whole); %s; max raises Drakkar's cap per ELF", e["elf"], len(ms), e["matches_total"], e["functions_total"], filters))
		}
		if e["matches_total"] == float64(0) {
			empty = append(empty, fmt.Sprintf("no match in %v; %s", e["elf"], filters))
		}
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"find": heads}
	env.Tails = map[string]Tail{
		"functions": makeTail(nonNil(functions), maxRows),
		"matches":   makeTail(nonNil(matches), maxRows),
		"errors":    makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Find) == 0 {
		env.note("the report holds no find entry: errors says why")
	}
	for _, c := range cut {
		env.note(c)
	}
	for _, n := range empty {
		env.note(n + ": the stack pointer is left out as a base by default, base any or sp keeps it; an offset held in a register, or a copy through memcpy, escapes the mode")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// headWithout copies an entry of the report without the given arrays.
func headWithout(entry map[string]any, arrays ...string) map[string]any {
	head := make(map[string]any, len(entry))
	for k, v := range entry {
		if !slices.Contains(arrays, k) {
			head[k] = v
		}
	}
	return head
}

// findFilters recalls the offsets, the filters and max of the call.
func findFilters(in NativeFindInput) string {
	f := []string{"offsets=" + strings.Join(in.Offsets, ",")}
	if len(in.Access) > 0 {
		f = append(f, "access="+strings.Join(in.Access, ","))
	}
	if len(in.Size) > 0 {
		sizes := make([]string, len(in.Size))
		for i, n := range in.Size {
			sizes[i] = strconv.Itoa(n)
		}
		f = append(f, "size="+strings.Join(sizes, ","))
	}
	if in.Base != "" {
		f = append(f, "base="+in.Base)
	}
	if len(in.In) > 0 {
		f = append(f, "in="+strings.Join(in.In, ","))
	}
	return filterRecap(f, in.Max)
}
