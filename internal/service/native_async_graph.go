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

// maxAsyncAddresses is the bound Drakkar puts on --native-async-from and
// --native-async-to.
const maxAsyncAddresses = 64

// NativeAsyncGraphInput is single-sample only, like --native.
type NativeAsyncGraphInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF"`

	From  []string `json:"from,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-async-from): the descendants of the functions containing them"`
	To    []string `json:"to,omitempty" jsonschema:"1 to 64 hex addresses, 0x prefix optional (--native-async-to): the ancestors of the functions containing them"`
	Path  []string `json:"path,omitempty" jsonschema:"pairs <hex a>:<hex b> (--native-async-path): the shortest paths from the function containing a to the one containing b"`
	Depth *int     `json:"depth,omitempty" jsonschema:"maximum depth for from and to, maximum path length for path (--native-async-depth); omitted, Drakkar's defaults"`
	Max   *int     `json:"max,omitempty" jsonschema:"nodes Drakkar renders per query (--native-async-max); the totals stay exact; omitted, Drakkar's default"`
	Kinds []string `json:"kinds,omitempty" jsonschema:"subset of call, makes (--native-async-kinds); omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many nodes, edges, paths and stores to return inline, each tail on its own, every query together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeAsyncGraph runs --native --native-async-graph.
func (s *Service) NativeAsyncGraph(ctx context.Context, in NativeAsyncGraphInput) (*Envelope, error) {
	if err := checkNativeAsyncGraph(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_async_graph", in.OutDir)
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
	env, _, err := s.invoke(ctx, out, timeout, nativeAsyncGraphArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeAsyncGraph(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeAsyncGraph checks the form only; Drakkar refuses the rest.
func checkNativeAsyncGraph(in NativeAsyncGraphInput) error {
	if len(in.From) == 0 && len(in.To) == 0 && len(in.Path) == 0 {
		return errors.New("give at least one query: from, to or path")
	}
	if err := checkHexList("from", in.From, maxAsyncAddresses); err != nil {
		return err
	}
	if err := checkHexList("to", in.To, maxAsyncAddresses); err != nil {
		return err
	}
	for i, p := range in.Path {
		a, b, found := strings.Cut(p, ":")
		if !found || !isHexAddress(a) || !isHexAddress(b) {
			return fmt.Errorf("path[%d] %q is not <hex address>:<hex address>", i, p)
		}
	}
	for i, k := range in.Kinds {
		if k != "call" && k != "makes" {
			return fmt.Errorf("kinds[%d] %q is not call or makes", i, k)
		}
	}
	if err := checkNotNegative("depth", in.Depth); err != nil {
		return err
	}
	return checkNotNegative("max", in.Max)
}

// nativeAsyncGraphArgs joins each list with commas, as Drakkar splits them.
func nativeAsyncGraphArgs(apk, reportPath string, in NativeAsyncGraphInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native").
		Value("--native-async-graph", elfOrStar(in.ELF))
	for _, l := range []struct {
		flag string
		list []string
	}{
		{"--native-async-from", in.From},
		{"--native-async-to", in.To},
		{"--native-async-path", in.Path},
	} {
		if len(l.list) > 0 {
			args.Value(l.flag, strings.Join(l.list, ","))
		}
	}
	args.Int("--native-async-depth", in.Depth).Int("--native-async-max", in.Max)
	if len(in.Kinds) > 0 {
		args.Value("--native-async-kinds", strings.Join(in.Kinds, ","))
	}
	return args.JSONReport(reportPath)
}

type nativeAsyncGraphReport struct {
	AsyncGraph []map[string]any `json:"async_graph"`
	Errors     []any            `json:"errors"`
}

// asyncArrays are the arrays of a query that go to the tails.
var asyncArrays = []string{"nodes", "edges", "paths", "stores"}

// finishNativeAsyncGraph puts each ELF with its queries, without their arrays,
// in the head, and the nodes, edges, paths and stores of every query, whole,
// in four tails, each cut at maxRows.
func (s *Service) finishNativeAsyncGraph(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeModeRefusal(env, "--native-async-graph")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeAsyncGraphReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	heads := make([]any, 0, len(r.AsyncGraph))
	tails := map[string][]any{}
	var notes []string
	for _, e := range r.AsyncGraph {
		head := headWithout(e, "queries")
		queries, _ := e["queries"].([]any)
		reduced := make([]any, 0, len(queries))
		for i, q := range queries {
			query, ok := q.(map[string]any)
			if !ok {
				reduced = append(reduced, q)
				continue
			}
			reduced = append(reduced, headWithout(query, asyncArrays...))
			for _, name := range asyncArrays {
				items, _ := query[name].([]any)
				for _, it := range items {
					tails[name] = append(tails[name], asyncRow(e["elf"], i, it))
				}
			}
			where := fmt.Sprintf("query %d (%v %v) of %v", i, query["kind"], query["requested"], e["elf"])
			if query["truncated"] == true {
				nodes, _ := query["nodes"].([]any)
				edges, _ := query["edges"].([]any)
				notes = append(notes, fmt.Sprintf("%s: Drakkar kept %d of %v nodes and %d of %v edges%s (exact totals); max raises Drakkar's cap per query", where, len(nodes), query["nodes_total"], len(edges), query["edges_total"], pathsKept(query)))
			}
			if query["kind"] == "path" && query["paths_total"] == float64(0) {
				notes = append(notes, where+": no path within the depth; an absent path is not proof that none exists, as a table passed through a structure field or an argument escapes the graph")
			}
		}
		if _, present := e["queries"]; present {
			head["queries"] = reduced
		}
		heads = append(heads, head)
	}
	errs := nonNil(r.Errors)

	env.Result = map[string]any{"async_graph": heads}
	env.Tails = map[string]Tail{"errors": makeTail(errs, len(errs))}
	for _, name := range asyncArrays {
		env.Tails[name] = makeTail(nonNil(tails[name]), maxRows)
	}
	env.ReportPath = path

	if len(r.AsyncGraph) == 0 {
		env.note("the report holds no async_graph entry: errors says why")
	}
	for _, n := range notes {
		env.note(n)
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// asyncRow adds the elf and the index of its query to an item; a path, an
// array of edges, goes whole under edges.
func asyncRow(elf any, query int, v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{"elf": elf, "query": query, "edges": v}
	}
	row := make(map[string]any, len(m)+2)
	for k, x := range m {
		row[k] = x
	}
	row["elf"] = elf
	row["query"] = query
	return row
}

// pathsKept recalls the paths of a path query.
func pathsKept(query map[string]any) string {
	total, present := query["paths_total"]
	if !present {
		return ""
	}
	paths, _ := query["paths"].([]any)
	return fmt.Sprintf(" and %d of %v paths", len(paths), total)
}
