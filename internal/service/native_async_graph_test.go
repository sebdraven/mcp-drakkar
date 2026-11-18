package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-async-graph report over two ELFs: the first
// carries an ELF-level counter this server does not know of, a from query cut
// by Drakkar and a path query without path; the second a path query with its
// edge, path and stored table, the edge holding an unknown field.
const asyncReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "async_graph": [
  {"elf": "lib/arm64-v8a/libfoo.so", "tables_total": 12, "future_counter": 7,
   "queries": [
    {"kind": "from", "requested": ["0x1010"], "resolved": ["0x1000"], "nodes_total": 3, "edges_total": 2, "truncated": true,
     "nodes": [{"fn_start": "0x1000", "fn_end": "0x1100", "bound": "eh_frame", "depth": 0}], "edges": [], "stores": []},
    {"kind": "path", "requested": ["0x1010", "0x1210"], "resolved": ["0x1000", "0x1200"], "nodes_total": 0, "edges_total": 0, "paths_total": 0, "truncated": false,
     "nodes": [], "edges": [], "paths": [], "stores": []}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "tables_total": 3,
   "queries": [
    {"kind": "path", "requested": ["0x1010", "0x1310"], "resolved": ["0x1000", "0x1300"], "nodes_total": 2, "edges_total": 1, "paths_total": 1, "truncated": false,
     "nodes": [{"fn_start": "0x1000", "fn_end": "0x1100", "bound": "symtab", "depth": 0}, {"fn_start": "0x1300", "fn_end": "0x1400", "bound": "symtab", "depth": 1}],
     "edges": [{"from": "0x1000", "to": "0x1300", "kind": "makes", "insn_addr": "0x1020", "adrp_addr": "0x101c", "table": "0x9000", "offset": "0x18", "future_field": {"kept": true}}],
     "paths": [[{"from": "0x1000", "to": "0x1300", "kind": "makes", "insn_addr": "0x1020", "adrp_addr": "0x101c", "table": "0x9000", "offset": "0x18"}]],
     "stores": [{"table": "0x9000", "vaddr": "0xa000"}]}
   ]}
 ],
 "errors": ["async_graph * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeAsyncGraphFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeAsyncGraph(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeAsyncGraphArgv(t *testing.T) {
	four, ten := 4, 10
	head := []string{"/a.apk", "--native", "--native-async-graph=*"}
	with := func(extra ...string) []string { return append(append([]string{}, head...), extra...) }
	for name, c := range map[string]struct {
		in   NativeAsyncGraphInput
		want []string
	}{
		"from":  {NativeAsyncGraphInput{From: []string{"1010", "0x2000"}}, with("--native-async-from=1010,0x2000")},
		"to":    {NativeAsyncGraphInput{To: []string{"0x1210"}}, with("--native-async-to=0x1210")},
		"path":  {NativeAsyncGraphInput{Path: []string{"1010:1210", "0x1010:0x1310"}}, with("--native-async-path=1010:1210,0x1010:0x1310")},
		"depth": {NativeAsyncGraphInput{From: []string{"1010"}, Depth: &four}, with("--native-async-from=1010", "--native-async-depth=4")},
		"max":   {NativeAsyncGraphInput{From: []string{"1010"}, Max: &ten}, with("--native-async-from=1010", "--native-async-max=10")},
		"kinds": {NativeAsyncGraphInput{From: []string{"1010"}, Kinds: []string{"makes"}}, with("--native-async-from=1010", "--native-async-kinds=makes")},
		"everything": {
			NativeAsyncGraphInput{ELF: "lib/arm64-v8a/libfoo.so", From: []string{"1010"}, To: []string{"1210"}, Path: []string{"1010:1210"}, Depth: &four, Max: &ten, Kinds: []string{"call", "makes"}},
			[]string{"/a.apk", "--native", "--native-async-graph=lib/arm64-v8a/libfoo.so",
				"--native-async-from=1010", "--native-async-to=1210", "--native-async-path=1010:1210",
				"--native-async-depth=4", "--native-async-max=10", "--native-async-kinds=call,makes"},
		},
	} {
		argv, err := nativeAsyncGraphArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeAsyncGraphRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxAsyncAddresses; i++ {
		many = append(many, fmt.Sprintf("%x", 0x1000+4*i))
	}
	from := []string{"1010"}

	for name, in := range map[string]NativeAsyncGraphInput{
		"no query":          {APK: apk},
		"from not hex":      {APK: apk, From: []string{"main"}},
		"65 from":           {APK: apk, From: many},
		"to not hex":        {APK: apk, To: []string{"1010,1210"}},
		"65 to":             {APK: apk, To: many},
		"path without pair": {APK: apk, Path: []string{"1010"}},
		"path not hex":      {APK: apk, Path: []string{"1010:main"}},
		"path with a comma": {APK: apk, Path: []string{"1010:1210,1310"}},
		"bad kind":          {APK: apk, From: from, Kinds: []string{"jump"}},
		"negative depth":    {APK: apk, From: from, Depth: &negative},
		"negative max":      {APK: apk, From: from, Max: &negative},
		"relative apk":      {APK: "a.apk", From: from},
	} {
		if _, err := s.NativeAsyncGraph(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}
	if err := checkNativeAsyncGraph(NativeAsyncGraphInput{Path: []string{"0x1010:1210"}}); err != nil {
		t.Errorf("a path alone was refused: %v", err)
	}
}

func TestNativeAsyncGraphShapesTwoELFs(t *testing.T) {
	env := finishNativeAsyncGraphFixture(t, asyncReportBody, 50)
	heads := env.Result.(map[string]any)["async_graph"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["tables_total"] != float64(12) || first["future_counter"] != float64(7) {
		t.Errorf("head[0] = %v", first)
	}
	queries := first["queries"].([]any)
	q0, q1 := queries[0].(map[string]any), queries[1].(map[string]any)
	for _, k := range asyncArrays {
		if _, present := q0[k]; present {
			t.Errorf("%s came back in the head", k)
		}
	}
	if len(q0) != 6 || q0["kind"] != "from" || q0["nodes_total"] != float64(3) || q0["truncated"] != true {
		t.Errorf("queries[0] = %v", q0)
	}
	if _, present := q0["paths_total"]; present {
		t.Error("paths_total is absent from a from query and was made up")
	}
	if q1["paths_total"] != float64(0) {
		t.Errorf("queries[1] = %v", q1)
	}

	nodes := env.Tails["nodes"]
	if nodes.Total != 3 || nodes.Truncated {
		t.Fatalf("nodes tail = %+v", nodes)
	}
	n2 := nodes.Items[2].(map[string]any)
	if n2["fn_start"] != "0x1300" || n2["elf"] != "lib/arm64-v8a/libbar.so" || n2["query"] != 0 || n2["depth"] != float64(1) {
		t.Errorf("nodes[2] = %v", n2)
	}
	edges := env.Tails["edges"]
	if edges.Total != 1 {
		t.Fatalf("edges tail = %+v", edges)
	}
	e0 := edges.Items[0].(map[string]any)
	if e0["table"] != "0x9000" || e0["offset"] != "0x18" || e0["elf"] != "lib/arm64-v8a/libbar.so" || e0["query"] != 0 {
		t.Errorf("edges[0] = %v", e0)
	}
	if future, ok := e0["future_field"].(map[string]any); !ok || future["kept"] != true {
		t.Errorf("an unknown edge field was dropped or changed: %v", e0)
	}
	if _, present := e0["via_fragment"]; present {
		t.Error("via_fragment is absent from the report and was made up")
	}
	paths := env.Tails["paths"]
	if paths.Total != 1 {
		t.Fatalf("paths tail = %+v", paths)
	}
	p0 := paths.Items[0].(map[string]any)
	if steps, ok := p0["edges"].([]any); !ok || len(steps) != 1 || p0["elf"] != "lib/arm64-v8a/libbar.so" || p0["query"] != 0 {
		t.Errorf("paths[0] = %v", p0)
	}
	if stores := env.Tails["stores"]; stores.Total != 1 || stores.Items[0].(map[string]any)["vaddr"] != "0xa000" {
		t.Errorf("stores tail = %+v", stores)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "async_graph * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "query 0 (from [0x1010]) of lib/arm64-v8a/libfoo.so: Drakkar kept 1 of 3 nodes and 0 of 2 edges (exact totals); max raises Drakkar's cap per query") {
		t.Errorf("no note for the query Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "query 1 (path [0x1010 0x1210]) of lib/arm64-v8a/libfoo.so: no path within the depth; an absent path is not proof that none exists, as a table passed through a structure field or an argument escapes the graph") {
		t.Errorf("no note for the path query without path: %q", env.Notes)
	}
	if strings.Contains(notes, "of lib/arm64-v8a/libbar.so") {
		t.Errorf("a whole query with a path got a note: %q", env.Notes)
	}
}

func TestNativeAsyncGraphTailsAreCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeAsyncGraphFixture(t, asyncReportBody, 1)
	nodes := env.Tails["nodes"]
	if nodes.Total != 3 || nodes.Returned != 1 || !nodes.Truncated {
		t.Fatalf("nodes tail = %+v; total counts the nodes in the report", nodes)
	}
	if edges := env.Tails["edges"]; edges.Total != 1 || edges.Truncated {
		t.Errorf("edges tail = %+v", edges)
	}
	q0 := env.Result.(map[string]any)["async_graph"].([]any)[0].(map[string]any)["queries"].([]any)[0].(map[string]any)
	if q0["nodes_total"] != float64(3) || q0["edges_total"] != float64(2) {
		t.Errorf("max_rows changed Drakkar's totals: %v", q0)
	}
}

func TestNativeAsyncGraphReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["async_graph * (lib/arm64-v8a/libfoo.so) : élément 0x9999 : adresse hors de toute fonction bornée"]}`
	env := finishNativeAsyncGraphFixture(t, body, 50)
	if heads := env.Result.(map[string]any)["async_graph"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	for _, name := range asyncArrays {
		if tail := env.Tails[name]; tail.Total != 0 || len(tail.Items) != 0 {
			t.Errorf("%s tail = %+v", name, tail)
		}
	}
	if e := env.Tails["errors"]; e.Total != 1 || !strings.Contains(e.Items[0].(string), "0x9999") {
		t.Errorf("errors = %+v", e)
	}
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "no async_graph entry") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func asyncCall(s *Service, apk, out string) (*Envelope, error) {
	in := NativeAsyncGraphInput{APK: apk, Path: []string{"1010:1210"}, Kinds: []string{"makes"}, OutDir: out}
	return s.NativeAsyncGraph(context.Background(), in)
}

func TestNativeAsyncGraphUnknownModeQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-async-graph' found", 2, asyncReportBody, asyncCall)
	if !strings.Contains(notes, "does not know --native-async-graph: it predates the mode") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeAsyncGraphUnknownOptionQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-async-kinds' found", 2, asyncReportBody, asyncCall)
	if !strings.Contains(notes, "does not know --native-async-kinds: it knows the --native-async-graph mode but not this option") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeAsyncGraphDrakkarRefusalComesBackInErrors(t *testing.T) {
	notes := refusedBy(t, "Error: --native-async-depth vaut au plus 12", 1, asyncReportBody, asyncCall)
	if strings.Contains(notes, "does not know") {
		t.Errorf("notes = %q", notes)
	}
}
