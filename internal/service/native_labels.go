package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// maxLabelsAddresses is the bound Drakkar puts on --native-labels-fn.
const maxLabelsAddresses = 64

// NativeLabelsInput is single-sample only, like --native.
type NativeLabelsInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF"`

	Fn             []string `json:"fn,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-labels-fn): keep the functions containing one of them"`
	Match          []string `json:"match,omitempty" jsonschema:"substrings, none empty and none holding a comma (--native-labels-match): keep the functions with a string containing one of them, case ignored"`
	Max            *int     `json:"max,omitempty" jsonschema:"functions Drakkar renders per ELF (--native-labels-max); functions_total and functions_matched stay exact; omitted, Drakkar's default"`
	StringsMax     *int     `json:"strings_max,omitempty" jsonschema:"strings Drakkar renders per function (--native-labels-strings-max); strings_total, label and all_tags stay computed on all of them; omitted, Drakkar's default"`
	FragmentFanout *int     `json:"fragment_fanout,omitempty" jsonschema:"callers above which a string reached through a small fragment is shared, kept out of label, names, all_tags and match (--native-labels-fragment-fanout); omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many functions to return inline, every ELF together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeLabels runs --native --native-labels.
func (s *Service) NativeLabels(ctx context.Context, in NativeLabelsInput) (*Envelope, error) {
	if err := checkNativeLabels(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_labels", in.OutDir)
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
	// Same class as drakkar_native_xrefs: both walk code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeLabelsArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeLabels(env, reportPath, ClampRows(in.MaxRows), in); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeLabels checks the form only; Drakkar refuses the rest.
func checkNativeLabels(in NativeLabelsInput) error {
	if err := checkHexList("fn", in.Fn, maxLabelsAddresses); err != nil {
		return err
	}
	for i, m := range in.Match {
		if m == "" || strings.Contains(m, ",") {
			return fmt.Errorf("match[%d] %q is empty or holds a comma, which Drakkar splits on", i, m)
		}
	}
	if err := checkNotNegative("max", in.Max); err != nil {
		return err
	}
	if err := checkNotNegative("strings_max", in.StringsMax); err != nil {
		return err
	}
	return checkNotNegative("fragment_fanout", in.FragmentFanout)
}

// nativeLabelsArgs joins each list with commas, as Drakkar splits them.
func nativeLabelsArgs(apk, reportPath string, in NativeLabelsInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-labels", elfOrStar(in.ELF))
	if len(in.Fn) > 0 {
		args.Value("--native-labels-fn", strings.Join(in.Fn, ","))
	}
	if len(in.Match) > 0 {
		args.Value("--native-labels-match", strings.Join(in.Match, ","))
	}
	return args.Int("--native-labels-max", in.Max).
		Int("--native-labels-strings-max", in.StringsMax).
		Int("--native-labels-fragment-fanout", in.FragmentFanout).
		JSONReport(reportPath)
}

type nativeLabelsReport struct {
	Labels []map[string]any `json:"labels"`
	Errors []any            `json:"errors"`
}

// finishNativeLabels puts every ELF-level field in the head, and the functions
// of every ELF, whole, in one tail, cut at maxRows.
func (s *Service) finishNativeLabels(env *Envelope, path string, maxRows int, in NativeLabelsInput) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-labels")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeLabelsReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	filters := labelsFilters(in)
	heads := make([]any, 0, len(r.Labels))
	var cut, empty []string
	var functions []any
	for _, e := range r.Labels {
		heads = append(heads, nativeHead(e, "functions"))
		items, _ := e["functions"].([]any)
		for _, it := range items {
			functions = append(functions, nativeRow(e, it, "elf"))
		}
		if e["truncated"] == true {
			cut = append(cut, fmt.Sprintf("functions of %v: Drakkar kept %d of %v matched, %v with an unshared string%s (exact totals); %s; max raises Drakkar's cap per ELF", e["elf"], len(items), e["functions_matched"], e["functions_total"], sharedOnly(e), filters))
		}
		if e["functions_matched"] == float64(0) {
			empty = append(empty, fmt.Sprintf("no function matched in %v, of %v with an unshared string%s; %s", e["elf"], e["functions_total"], sharedOnly(e), filters))
		}
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"labels": heads}
	env.Tails = map[string]Tail{
		"functions": makeTail(nonNil(functions), maxRows),
		"errors":    makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Labels) == 0 {
		env.note("the report holds no labels entry: errors says why")
	}
	for _, c := range cut {
		env.note(c)
	}
	for _, n := range empty {
		env.note(n + ": a function whose strings escape the scan, a computed address or an ADRP and its ADD far apart, has none")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// sharedOnly recalls functions_shared_only when the report has it.
func sharedOnly(e map[string]any) string {
	n, present := e["functions_shared_only"]
	if !present {
		return ""
	}
	return fmt.Sprintf(", %v with shared strings only", n)
}

// labelsFilters recalls the filters and max of the call.
func labelsFilters(in NativeLabelsInput) string {
	var f []string
	if len(in.Fn) > 0 {
		f = append(f, "fn="+strings.Join(in.Fn, ","))
	}
	if len(in.Match) > 0 {
		f = append(f, "match="+strings.Join(in.Match, ","))
	}
	return filterRecap(f, in.Max)
}
