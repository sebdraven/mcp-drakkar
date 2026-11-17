package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// NativeSymexInput is single-sample only, like --native.
type NativeSymexInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	Function string `json:"function" jsonschema:"<elf path|*>@<hex address>: the function to propagate through, passed as is to --native-symex; the elf path is elfs[].path of drakkar_native, the file name for a raw ELF, and * takes every AArch64 ELF whose executable code holds the address"`

	Watch       []string `json:"watch,omitempty" jsonschema:"hex addresses of the instructions to watch, 0x prefix optional; Drakkar refuses a run without one"`
	Peek        []string `json:"peek,omitempty" jsonschema:"<watch address>:<register>+<offset>:<length>, each read in the symbolic memory just before that watch; the watch must be in watch, the register x0..x30 or sp"`
	Entry       string   `json:"entry,omitempty" jsonschema:"hex address inside the function to start from, with the initial state of its start"`
	Depth       *int     `json:"depth,omitempty" jsonschema:"how deep direct calls are followed; omitted, Drakkar's default"`
	MaxInsns    *int     `json:"max_insns,omitempty" jsonschema:"instruction budget per path; omitted, Drakkar's default"`
	MaxPaths    *int     `json:"max_paths,omitempty" jsonschema:"path budget per exploration; omitted, Drakkar's default"`
	FragmentMax *int     `json:"fragment_max,omitempty" jsonschema:"largest outlined fragment, in bytes, followed outside the depth; 0 disables; omitted, Drakkar's default"`
	CalleeForks *int     `json:"callee_forks,omitempty" jsonschema:"sibling paths a followed callee may open; omitted, Drakkar's default"`
	Refine      *int     `json:"refine,omitempty" jsonschema:"at most this many refinement reruns, following skipped calls that may write what a watch reads; 0 disables; omitted, Drakkar's default"`
	Follow      []string `json:"follow,omitempty" jsonschema:"hex addresses of bl (or b) instructions whose callee is followed whatever the depth"`
	Undirected  bool     `json:"undirected,omitempty" jsonschema:"neither pruning nor ordering by distance to the watches"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many results per watch, calls and indirect branches to return inline; every watch comes back, and the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeSymex runs --native --native-symex.
func (s *Service) NativeSymex(ctx context.Context, in NativeSymexInput) (*Envelope, error) {
	if err := checkNativeSymex(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_symex", in.OutDir)
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
	// Same class as drakkar_native with disasm: both walk code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeSymexArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeSymex(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeSymex checks the form only; Drakkar refuses the rest.
func checkNativeSymex(in NativeSymexInput) error {
	// Drakkar splits on the last @.
	i := strings.LastIndex(in.Function, "@")
	if i <= 0 || !isHexAddress(in.Function[i+1:]) {
		return fmt.Errorf("function %q is not <elf path|*>@<hex address>", in.Function)
	}
	for name, list := range map[string][]string{"watch": in.Watch, "follow": in.Follow} {
		for i, a := range list {
			if !isHexAddress(a) {
				return fmt.Errorf("%s[%d] %q is not a hex address", name, i, a)
			}
		}
	}
	if in.Entry != "" && !isHexAddress(in.Entry) {
		return fmt.Errorf("entry %q is not a hex address", in.Entry)
	}
	for i, p := range in.Peek {
		parts := strings.Split(p, ":")
		if strings.Contains(p, ",") || len(parts) != 3 || !isHexAddress(parts[0]) || parts[1] == "" || !isDecimal(parts[2]) {
			return fmt.Errorf("peek[%d] %q is not <watch address>:<register>+<offset>:<length>", i, p)
		}
	}
	for name, v := range map[string]*int{
		"depth": in.Depth, "max_insns": in.MaxInsns, "max_paths": in.MaxPaths,
		"fragment_max": in.FragmentMax, "callee_forks": in.CalleeForks, "refine": in.Refine,
	} {
		if v != nil && *v < 0 {
			return fmt.Errorf("%s %d is negative", name, *v)
		}
	}
	return nil
}

func isHexAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if s == "" || len(s) > 16 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 64)
	return err == nil
}

func isDecimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// nativeSymexArgs joins each list with commas, as Drakkar splits them.
func nativeSymexArgs(apk, reportPath string, in NativeSymexInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").Value("--native-symex", in.Function)
	if len(in.Watch) > 0 {
		args.Value("--native-symex-watch", strings.Join(in.Watch, ","))
	}
	if len(in.Peek) > 0 {
		args.Value("--native-symex-peek", strings.Join(in.Peek, ","))
	}
	args.ValueIf("--native-symex-entry", in.Entry).
		Int("--native-symex-depth", in.Depth).
		Int("--native-symex-max-insns", in.MaxInsns).
		Int("--native-symex-max-paths", in.MaxPaths).
		Int("--native-symex-fragment-max", in.FragmentMax).
		Int("--native-symex-callee-forks", in.CalleeForks).
		Int("--native-symex-refine", in.Refine)
	if len(in.Follow) > 0 {
		args.Value("--native-symex-follow", strings.Join(in.Follow, ","))
	}
	return args.SwitchIf("--native-symex-undirected", in.Undirected).JSONReport(reportPath)
}

// nativeSymexHeadKeys are copied from each symex entry when present.
var nativeSymexHeadKeys = []string{
	"elf", "fn_start", "fn_end", "bound", "entry", "directed", "budgets",
	"paths_explored", "paths_cut", "budget_hit", "callees_abandoned",
	"callees_incomplete", "forks_dropped", "rounds",
}

type nativeSymexReport struct {
	Symex  []map[string]any `json:"symex"`
	Errors []any            `json:"errors"`
}

// finishNativeSymex puts one summary per symex entry in the head, and four
// tails beside it: watches whole with their results cut at maxRows, calls and
// indirect_branches cut at maxRows, errors whole.
func (s *Service) finishNativeSymex(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeSymexRefusal(env)
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeSymexReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	heads := make([]any, 0, len(r.Symex))
	var watches, calls, branches []any
	for _, e := range r.Symex {
		head := map[string]any{}
		for _, k := range nativeSymexHeadKeys {
			if v, ok := e[k]; ok {
				head[k] = v
			}
		}
		ws, _ := e["watches"].([]any)
		cs, _ := e["calls"].([]any)
		bs, _ := e["indirect_branches"].([]any)
		head["watches_count"] = len(ws)
		head["calls_count"] = len(cs)
		head["indirect_branches_count"] = len(bs)
		heads = append(heads, head)

		for _, w := range ws {
			watches = append(watches, symexWatchRow(e, w, maxRows))
		}
		for _, c := range cs {
			calls = append(calls, withEntry(e, c))
		}
		for _, b := range bs {
			branches = append(branches, withEntry(e, b))
		}
	}
	errs := r.Errors
	if errs == nil {
		errs = []any{}
	}

	env.Result = map[string]any{"symex": heads}
	env.Tails = map[string]Tail{
		"watches":           makeTail(watches, len(watches)),
		"calls":             makeTail(byPathsDesc(calls), maxRows),
		"indirect_branches": makeTail(branches, maxRows),
		"errors":            makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.Symex) == 0 {
		env.note("the report holds no symex entry: errors says why")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// noteNativeSymexRefusal relays Drakkar's own message when it wrote no report.
func noteNativeSymexRefusal(env *Envelope) {
	line := errorLine(env.Stderr.Text)
	if strings.Contains(env.Stderr.Text, "unexpected argument '--native-symex") {
		env.note("this drakkar does not know --native-symex: it predates the mode; drakkar_version shows which one is on PATH")
	} else {
		env.note("no JSON report was produced, which is consistent with the exit code above")
	}
	if line == "" {
		return
	}
	env.note("Drakkar's message, verbatim: " + line)
	env.Tails = map[string]Tail{"errors": makeTail([]any{line}, 1)}
}

// symexWatchRow keeps a watch whole but its results, sorted by paths
// descending and cut at maxRows.
func symexWatchRow(entry map[string]any, w any, maxRows int) any {
	watch, ok := w.(map[string]any)
	if !ok {
		return w
	}
	row := withEntry(entry, watch).(map[string]any)
	results, _ := watch["results"].([]any)
	sorted := byPathsDesc(results)
	total := len(sorted)
	if len(sorted) > maxRows {
		sorted = sorted[:maxRows]
	}
	row["results"] = sorted
	row["results_total"] = total
	row["results_truncated"] = len(sorted) < total
	return row
}

// withEntry copies a row and adds the elf and fn_start of its symex entry, so
// that rows from several entries stay apart.
func withEntry(entry map[string]any, v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	row := make(map[string]any, len(m)+2)
	for k, x := range m {
		row[k] = x
	}
	for _, k := range []string{"elf", "fn_start"} {
		if x, ok := entry[k]; ok {
			row[k] = x
		}
	}
	return row
}

func byPathsDesc(rows []any) []any {
	sorted := make([]any, len(rows))
	copy(sorted, rows)
	paths := func(v any) float64 {
		m, _ := v.(map[string]any)
		n, _ := m["paths"].(float64)
		return n
	}
	sort.SliceStable(sorted, func(i, j int) bool { return paths(sorted[i]) > paths(sorted[j]) })
	return sorted
}
