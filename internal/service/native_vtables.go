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

// maxVtablesAddresses is Drakkar's MAX_VTABLES_ADDRESSES.
const maxVtablesAddresses = 64

// NativeVtablesInput is single-sample only, like --native.
type NativeVtablesInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF"`

	Fn   []string `json:"fn,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-vtables-fn): keep the tables whose destructor or a method is one of them; each table then says at which offsets in matched"`
	Slot string   `json:"slot,omitempty" jsonschema:"offset from the table start, 0x hex or decimal (--native-vtables-slot): keep the tables with a method there; Drakkar wants a multiple of 8, at least 0x18"`
	Size string   `json:"size,omitempty" jsonschema:"0x hex or decimal (--native-vtables-size): keep the tables of that size"`
	At   []string `json:"at,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-vtables-at): keep the tables starting at one of them"`
	Max  *int     `json:"max,omitempty" jsonschema:"tables Drakkar renders per ELF (--native-vtables-max); tables_total and tables_matched stay exact; omitted, Drakkar's default"`
	Refs bool     `json:"refs,omitempty" jsonschema:"also search the instructions and data words carrying each rendered table's address (--native-vtables-refs): who builds the table"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many tables to return inline, every ELF together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeVtables runs --native --native-vtables.
func (s *Service) NativeVtables(ctx context.Context, in NativeVtablesInput) (*Envelope, error) {
	if err := checkNativeVtables(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_vtables", in.OutDir)
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
	// Same class as drakkar_native_xrefs: refs walks code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeVtablesArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeVtables(env, reportPath, ClampRows(in.MaxRows), in); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeVtables checks the form only; Drakkar refuses the rest.
func checkNativeVtables(in NativeVtablesInput) error {
	if err := checkHexList("fn", in.Fn, maxVtablesAddresses); err != nil {
		return err
	}
	if err := checkHexList("at", in.At, maxVtablesAddresses); err != nil {
		return err
	}
	if in.Slot != "" && !isHexOrDecimal(in.Slot) {
		return fmt.Errorf("slot %q is neither 0x hex nor decimal", in.Slot)
	}
	if in.Size != "" && !isHexOrDecimal(in.Size) {
		return fmt.Errorf("size %q is neither 0x hex nor decimal", in.Size)
	}
	return checkNotNegative("max", in.Max)
}

// isHexOrDecimal is Drakkar's parse_vtables_number: hex with 0x, else decimal.
func isHexOrDecimal(s string) bool {
	if digits, ok := strings.CutPrefix(s, "0x"); ok {
		_, err := strconv.ParseUint(digits, 16, 64)
		return err == nil
	}
	return isDecimal(s)
}

// nativeVtablesArgs joins each address list with commas, as Drakkar splits them.
func nativeVtablesArgs(apk, reportPath string, in NativeVtablesInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-vtables", elfOrStar(in.ELF))
	if len(in.Fn) > 0 {
		args.Value("--native-vtables-fn", strings.Join(in.Fn, ","))
	}
	args.ValueIf("--native-vtables-slot", in.Slot).
		ValueIf("--native-vtables-size", in.Size)
	if len(in.At) > 0 {
		args.Value("--native-vtables-at", strings.Join(in.At, ","))
	}
	return args.Int("--native-vtables-max", in.Max).
		SwitchIf("--native-vtables-refs", in.Refs).
		JSONReport(reportPath)
}

type nativeVtablesReport struct {
	Vtables []map[string]any `json:"vtables"`
	Errors  []any            `json:"errors"`
}

// finishNativeVtables puts one summary per ELF in the head, and the tables of
// every ELF in one tail, cut at maxRows.
func (s *Service) finishNativeVtables(env *Envelope, path string, maxRows int, in NativeVtablesInput) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-vtables")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeVtablesReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	filters := vtablesFilters(in)
	heads := make([]any, 0, len(r.Vtables))
	var cut, empty []string
	var tables []any
	for _, e := range r.Vtables {
		heads = append(heads, nativeHead(e, "tables"))
		items, _ := e["tables"].([]any)
		for _, it := range items {
			tables = append(tables, nativeRow(e, it, "elf"))
		}
		if e["truncated"] == true {
			cut = append(cut, fmt.Sprintf("tables of %v: Drakkar kept %d of %v matched, %v detected (exact totals); %s; max raises Drakkar's cap per ELF", e["elf"], len(items), e["tables_matched"], e["tables_total"], filters))
		}
		if e["tables_matched"] == float64(0) {
			empty = append(empty, fmt.Sprintf("no table matched in %v, of %v detected; %s", e["elf"], e["tables_total"], filters))
		}
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"vtables": heads}
	env.Tails = map[string]Tail{
		"tables": makeTail(nonNil(tables), maxRows),
		"errors": makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Vtables) == 0 {
		env.note("the report holds no vtables entry: errors says why")
	}
	for _, c := range cut {
		env.note(c)
	}
	for _, n := range empty {
		env.note(n + ": detection is structural, a table without method, or relocated other than by a relative relocation, is not found")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// vtablesFilters recalls the filters and max of the call.
func vtablesFilters(in NativeVtablesInput) string {
	var f []string
	if len(in.Fn) > 0 {
		f = append(f, "fn="+strings.Join(in.Fn, ","))
	}
	if in.Slot != "" {
		f = append(f, "slot="+in.Slot)
	}
	if in.Size != "" {
		f = append(f, "size="+in.Size)
	}
	if len(in.At) > 0 {
		f = append(f, "at="+strings.Join(in.At, ","))
	}
	return filterRecap(f, in.Max)
}

func filterRecap(filters []string, limit *int) string {
	s := "filters: none"
	if len(filters) > 0 {
		s = "filters: " + strings.Join(filters, " ")
	}
	if limit == nil {
		return s + ", max: Drakkar's default"
	}
	return s + ", max: " + strconv.Itoa(*limit)
}
