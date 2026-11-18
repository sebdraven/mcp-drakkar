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

// maxFieldsAddresses is the bound Drakkar puts on --native-fields-fn.
const maxFieldsAddresses = 64

// NativeFieldsInput is single-sample only, like --native.
type NativeFieldsInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF"`

	Fn             []string `json:"fn,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-fields-fn): only the functions containing one of them, the candidacy condition then not applying"`
	Name           []string `json:"name,omitempty" jsonschema:"exact field names, none empty and none holding a comma, case sensitive (--native-fields-name): only the functions referencing one of them"`
	Min            *int     `json:"min,omitempty" jsonschema:"distinct candidate names a function needs to be a candidate deserializer (--native-fields-min); omitted, Drakkar's default"`
	FragmentFanout *int     `json:"fragment_fanout,omitempty" jsonschema:"callers above which a name reached through a small fragment is neither counted nor rendered (--native-fields-fragment-fanout); omitted, Drakkar's default"`
	Max            *int     `json:"max,omitempty" jsonschema:"functions Drakkar renders per ELF (--native-fields-max); functions_total and functions_matched stay exact; omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many functions to return inline, every ELF together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeFields runs --native --native-fields.
func (s *Service) NativeFields(ctx context.Context, in NativeFieldsInput) (*Envelope, error) {
	if err := checkNativeFields(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_fields", in.OutDir)
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
	// Same class as drakkar_native_labels: both read the strings and walk code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeFieldsArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeFields(env, reportPath, ClampRows(in.MaxRows), in); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeFields checks the form only; Drakkar refuses the rest.
func checkNativeFields(in NativeFieldsInput) error {
	if err := checkHexList("fn", in.Fn, maxFieldsAddresses); err != nil {
		return err
	}
	for i, n := range in.Name {
		if n == "" || strings.Contains(n, ",") {
			return fmt.Errorf("name[%d] %q is empty or holds a comma, which Drakkar splits on", i, n)
		}
	}
	if err := checkNotNegative("min", in.Min); err != nil {
		return err
	}
	if err := checkNotNegative("fragment_fanout", in.FragmentFanout); err != nil {
		return err
	}
	return checkNotNegative("max", in.Max)
}

// nativeFieldsArgs joins each list with commas, as Drakkar splits them.
func nativeFieldsArgs(apk, reportPath string, in NativeFieldsInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-fields", elfOrStar(in.ELF))
	if len(in.Fn) > 0 {
		args.Value("--native-fields-fn", strings.Join(in.Fn, ","))
	}
	if len(in.Name) > 0 {
		args.Value("--native-fields-name", strings.Join(in.Name, ","))
	}
	return args.Int("--native-fields-min", in.Min).
		Int("--native-fields-fragment-fanout", in.FragmentFanout).
		Int("--native-fields-max", in.Max).
		JSONReport(reportPath)
}

type nativeFieldsReport struct {
	Fields []map[string]any `json:"fields"`
	Errors []any            `json:"errors"`
}

// finishNativeFields puts every ELF-level field in the head, and the functions
// of every ELF, whole, in one tail, cut at maxRows.
func (s *Service) finishNativeFields(env *Envelope, path string, maxRows int, in NativeFieldsInput) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-fields")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeFieldsReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	filters := fieldsFilters(in)
	heads := make([]any, 0, len(r.Fields))
	var cut, empty []string
	var functions []any
	for _, e := range r.Fields {
		heads = append(heads, nativeHead(e, "functions"))
		items, _ := e["functions"].([]any)
		for _, it := range items {
			functions = append(functions, nativeRow(e, it, "elf"))
		}
		if e["truncated"] == true {
			cut = append(cut, fmt.Sprintf("functions of %v: Drakkar kept %d of %v matched, %v candidate deserializers (exact totals); %s; max raises Drakkar's cap per ELF", e["elf"], len(items), e["functions_matched"], e["functions_total"], filters))
		}
		if e["functions_matched"] == float64(0) {
			empty = append(empty, fmt.Sprintf("no function matched in %v, of %v candidate deserializers; %s", e["elf"], e["functions_total"], filters))
		}
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"fields": heads}
	env.Tails = map[string]Tail{
		"functions": makeTail(nonNil(functions), maxRows),
		"errors":    makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Fields) == 0 {
		env.note("the report holds no fields entry: errors says why")
	}
	for _, c := range cut {
		env.note(c)
	}
	for _, n := range empty {
		env.note(n + ": a function that reads its names through a data table, not through addresses formed in code, escapes the mode")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// fieldsFilters recalls the filters, the thresholds and max of the call.
func fieldsFilters(in NativeFieldsInput) string {
	var f []string
	if len(in.Fn) > 0 {
		f = append(f, "fn="+strings.Join(in.Fn, ","))
	}
	if len(in.Name) > 0 {
		f = append(f, "name="+strings.Join(in.Name, ","))
	}
	if in.Min != nil {
		f = append(f, fmt.Sprintf("min=%d", *in.Min))
	}
	if in.FragmentFanout != nil {
		f = append(f, fmt.Sprintf("fragment_fanout=%d", *in.FragmentFanout))
	}
	return filterRecap(f, in.Max)
}
