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

// maxSliceQueries is the bound Drakkar puts on --native-slice-at.
const maxSliceQueries = 16

// NativeSliceInput is single-sample only, like --native.
type NativeSliceInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	Function string `json:"function" jsonschema:"required: <elf path|*>@<hex address> of the function (--native-slice), passed as is; elf path is elfs[].path of drakkar_native"`

	At         []string `json:"at" jsonschema:"required: 1 to 16 queries <hex address>:<location>, none holding a comma (--native-slice-at); location is a register (x8, sp) or <register>+<offset>:<length> (x0+0x5a9:1), read with the register's value just before the instruction at the address"`
	Depth      *int     `json:"depth,omitempty" jsonschema:"levels of called functions followed (--native-slice-depth); outlined fragments are always walked through; omitted, Drakkar's default"`
	Follow     []string `json:"follow,omitempty" jsonschema:"hex addresses of bl (or b) followed whatever the depth (--native-slice-follow)"`
	MaxSteps   *int     `json:"max_steps,omitempty" jsonschema:"fixed-point iterations per query (--native-slice-max-steps); omitted, Drakkar's default"`
	MaxSources *int     `json:"max_sources,omitempty" jsonschema:"sources Drakkar renders per query (--native-slice-max-sources); sources_total stays exact; omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many sources to return inline, every query together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeSlice runs --native --native-slice.
func (s *Service) NativeSlice(ctx context.Context, in NativeSliceInput) (*Envelope, error) {
	if err := checkNativeSlice(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_slice", in.OutDir)
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
	// Same class as drakkar_native_labels.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeSliceArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeSlice(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeSlice checks the form only; Drakkar refuses the rest, the
// grammar of a location included.
func checkNativeSlice(in NativeSliceInput) error {
	// Drakkar splits on the last @.
	i := strings.LastIndex(in.Function, "@")
	if i <= 0 || !isHexAddress(in.Function[i+1:]) {
		return fmt.Errorf("function %q is not <elf path|*>@<hex address>", in.Function)
	}
	if len(in.At) == 0 {
		return errors.New("at is required: 1 to 16 queries <hex address>:<location>")
	}
	distinct := map[string]bool{}
	for i, q := range in.At {
		address, location, found := strings.Cut(q, ":")
		if strings.Contains(q, ",") || !found || !isHexAddress(address) || location == "" {
			return fmt.Errorf("at[%d] %q is not <hex address>:<location>", i, q)
		}
		distinct[q] = true
	}
	if len(distinct) > maxSliceQueries {
		return fmt.Errorf("at has %d distinct queries: give 1 to %d", len(distinct), maxSliceQueries)
	}
	for i, a := range in.Follow {
		if !isHexAddress(a) {
			return fmt.Errorf("follow[%d] %q is not a hex address", i, a)
		}
	}
	for _, c := range []struct {
		name string
		v    *int
	}{{"depth", in.Depth}, {"max_steps", in.MaxSteps}, {"max_sources", in.MaxSources}} {
		if err := checkNotNegative(c.name, c.v); err != nil {
			return err
		}
	}
	return nil
}

// nativeSliceArgs joins each list with commas, as Drakkar splits them.
func nativeSliceArgs(apk, reportPath string, in NativeSliceInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-slice", in.Function).
		Value("--native-slice-at", strings.Join(in.At, ","))
	args.Int("--native-slice-depth", in.Depth)
	if len(in.Follow) > 0 {
		args.Value("--native-slice-follow", strings.Join(in.Follow, ","))
	}
	return args.Int("--native-slice-max-steps", in.MaxSteps).
		Int("--native-slice-max-sources", in.MaxSources).
		JSONReport(reportPath)
}

type nativeSliceReport struct {
	Slices []map[string]any `json:"slices"`
	Errors []any            `json:"errors"`
}

// finishNativeSlice puts each function with its queries, without their
// sources, in the head, and every source, whole, in one tail cut at maxRows.
func (s *Service) finishNativeSlice(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-slice")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeSliceReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	heads := make([]any, 0, len(r.Slices))
	var notes []string
	var sources []any
	for _, e := range r.Slices {
		head := headWithout(e, "queries")
		queries, _ := e["queries"].([]any)
		reduced := make([]any, 0, len(queries))
		for _, q := range queries {
			query, ok := q.(map[string]any)
			if !ok {
				reduced = append(reduced, q)
				continue
			}
			reduced = append(reduced, headWithout(query, "sources"))
			items, _ := query["sources"].([]any)
			// Counted over the whole report, before max_rows.
			aliased, cut := 0, 0
			for _, it := range items {
				sources = append(sources, sliceRow(e, query, it))
				src, _ := it.(map[string]any)
				if a, _ := src["aliases"].([]any); len(a) > 0 {
					aliased++
				}
				if src["reason"] == "alias_depth" {
					cut++
				}
			}
			where := fmt.Sprintf("query %v %v in %v@%v", query["at"], query["location"], e["elf"], e["fn_start"])
			if query["complete"] == false {
				notes = append(notes, fmt.Sprintf("%s is incomplete: the max_steps budget or the max_sources cap was reached, so the result is partial (%d of %v sources rendered, %v steps)", where, len(items), query["sources_total"], query["steps"]))
			}
			if query["sources_total"] == float64(0) {
				notes = append(notes, where+" found no source")
			}
			if aliased > 0 {
				notes = append(notes, fmt.Sprintf("%s: %d of %d sources rest on an assumed stack reload (aliases): each holds only if the reloaded register does hold what was spilled", where, aliased, len(items)))
			}
			if cut > 0 {
				notes = append(notes, fmt.Sprintf("%s: %d of %d sources are unknown with reason alias_depth: paths through aliases were cut at 2 assumed reloads", where, cut, len(items)))
			}
		}
		if _, present := e["queries"]; present {
			head["queries"] = reduced
		}
		heads = append(heads, head)
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"slices": heads}
	env.Tails = map[string]Tail{
		"sources": makeTail(nonNil(sources), maxRows),
		"errors":  makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Slices) == 0 {
		env.note("the report holds no slices entry: errors says why")
	}
	for _, n := range notes {
		env.note(n)
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// sliceRow copies a source and adds the elf and fn_start of its entry, and the
// at and location of its query as query_at and query_location, since a source
// has a location of its own.
func sliceRow(entry, query map[string]any, v any) any {
	row, ok := nativeRow(entry, v, "elf", "fn_start").(map[string]any)
	if !ok {
		return v
	}
	for _, k := range []string{"at", "location"} {
		if x, present := query[k]; present {
			row["query_"+k] = x
		}
	}
	return row
}
