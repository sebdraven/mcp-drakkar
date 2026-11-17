package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func symexShown(text string) string {
	return `{"text": "` + text + `", "expr": {"op": "const", "value": "` + text + `"}}`
}

// The shape of a --native --native-symex report: one entry, two watches, the
// first with three results; fn_end is absent to check it stays absent.
var symexReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "symex": [
  {"elf": "lib/arm64-v8a/libfoo.so", "fn_start": "0x1a00", "bound": "none", "entry": "0x1a00",
   "budgets": {"depth": 0, "max_insns": 20000, "max_paths": 256, "fragment_max": 64, "callee_forks": 2, "refine": 4},
   "directed": false, "rounds": [{"round": 0, "follow": [], "paths": 7}],
   "paths_explored": 7, "paths_cut": {"cut_loop": 2}, "budget_hit": false,
   "callees_abandoned": 0, "callees_incomplete": 1, "forks_dropped": 0,
   "watches": [
    {"insn_addr": "0x1a40", "instruction": "ldr x0, [x1, #0x10]", "reached": true, "results": [
     {"kind": "load", "address": ` + symexShown("init(x1) + 0x10") + `, "value": ` + symexShown("load(8, init(x1) + 0x10)") + `, "sp": ` + symexShown("init(sp)") + `, "paths": 1, "trace": ["0x1a3c"]},
     {"kind": "load", "address": ` + symexShown("global(0x5000)") + `, "value": ` + symexShown("0x112") + `, "sp": ` + symexShown("init(sp)") + `, "paths": 5, "trace": ["0x1a20", "0x1a3c"], "trace_truncated": true,
      "peeks": [{"reg": "x1", "offset": "0x10", "len": 2, "address": ` + symexShown("global(0x5010)") + `, "bytes": [` + symexShown("0x41") + `, ` + symexShown("0x42") + `]}]},
     {"kind": "load", "address": ` + symexShown("init(x2)") + `, "value": ` + symexShown("load(8, init(x2))") + `, "sp": ` + symexShown("init(sp)") + `, "paths": 3, "trace": []}
    ]},
    {"insn_addr": "0x1a58", "instruction": null, "reached": false, "results": []}
   ],
   "calls": [
    {"insn_addr": "0x1a10", "kind": "direct", "target": ` + symexShown("global(0x2000)") + `, "args": ["init(x0)"], "paths": 2},
    {"insn_addr": "0x1a30", "kind": "import", "target": ` + symexShown("global(0x3000)") + `, "import": "strlen", "args": ["init(x0)"], "paths": 7},
    {"insn_addr": "0x1a50", "kind": "indirect", "target": ` + symexShown("load(8, init(x3))") + `, "args": [], "paths": 4}
   ],
   "indirect_branches": [
    {"insn_addr": "0x1a60", "target": ` + symexShown("load(8, init(x4))") + `, "paths": 1},
    {"insn_addr": "0x1a64", "target": ` + symexShown("load(8, init(x5))") + `, "paths": 2},
    {"insn_addr": "0x1a68", "target": ` + symexShown("load(8, init(x6))") + `, "paths": 3}
   ]}
 ],
 "errors": ["symex libbar.so@0x10 : aucun ELF de ce chemin"]}
`

func finishNativeSymexFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeSymex(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeSymexArgv(t *testing.T) {
	zero, two, ninety := 0, 2, 90
	argv, err := nativeSymexArgs("/corpus/A sample.apk", "/out/report.json", NativeSymexInput{
		Function:    "lib/arm64-v8a/libfoo.so@1a00",
		Watch:       []string{"1a40", "0x1a58"},
		Peek:        []string{"1a40:x1+0x10:8", "1a58:sp-8:4"},
		Entry:       "1a20",
		Depth:       &two,
		MaxInsns:    &ninety,
		MaxPaths:    &ninety,
		FragmentMax: &zero,
		CalleeForks: &zero,
		Refine:      &two,
		Follow:      []string{"1a10", "1a30"},
		Undirected:  true,
	}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/corpus/A sample.apk", "--native", "--native-symex=lib/arm64-v8a/libfoo.so@1a00",
		"--native-symex-watch=1a40,0x1a58", "--native-symex-peek=1a40:x1+0x10:8,1a58:sp-8:4",
		"--native-symex-entry=1a20", "--native-symex-depth=2", "--native-symex-max-insns=90",
		"--native-symex-max-paths=90", "--native-symex-fragment-max=0", "--native-symex-callee-forks=0",
		"--native-symex-refine=2", "--native-symex-follow=1a10,1a30", "--native-symex-undirected",
		"--format=json", "--json-out=/out/report.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}

	// Omitted parameters add no option: Drakkar keeps its defaults.
	argv, err = nativeSymexArgs("/a.so", "/out/report.json", NativeSymexInput{Function: "*@1a00"}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"/a.so", "--native", "--native-symex=*@1a00", "--format=json", "--json-out=/out/report.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestNativeSymexRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1

	for name, in := range map[string]NativeSymexInput{
		"no function":        {APK: apk},
		"no @":               {APK: apk, Function: "libfoo.so"},
		"empty elf":          {APK: apk, Function: "@1a00"},
		"address not hex":    {APK: apk, Function: "*@main"},
		"range":              {APK: apk, Function: "*@1a00-1a80"},
		"watch not hex":      {APK: apk, Function: "*@1a00", Watch: []string{"1a40", "zz"}},
		"empty watch":        {APK: apk, Function: "*@1a00", Watch: []string{""}},
		"follow not hex":     {APK: apk, Function: "*@1a00", Follow: []string{"bl"}},
		"entry not hex":      {APK: apk, Function: "*@1a00", Entry: "start"},
		"peek two parts":     {APK: apk, Function: "*@1a00", Peek: []string{"1a40:x1+0"}},
		"peek with a comma":  {APK: apk, Function: "*@1a00", Peek: []string{"1a40:x1+0:8,1a40:x2+0:8"}},
		"peek length not N":  {APK: apk, Function: "*@1a00", Peek: []string{"1a40:x1+0:all"}},
		"negative depth":     {APK: apk, Function: "*@1a00", Depth: &negative},
		"negative max_paths": {APK: apk, Function: "*@1a00", MaxPaths: &negative},
		"relative apk":       {APK: "a.apk", Function: "*@1a00"},
	} {
		if _, err := s.NativeSymex(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}
}

func TestNativeSymexHeadCountsAndKeepsAbsentFieldsAbsent(t *testing.T) {
	env := finishNativeSymexFixture(t, symexReportBody, 50)
	heads := env.Result.(map[string]any)["symex"].([]any)
	if len(heads) != 1 {
		t.Fatalf("head = %v", env.Result)
	}
	head := heads[0].(map[string]any)
	if head["fn_start"] != "0x1a00" || head["bound"] != "none" || head["paths_explored"] != float64(7) {
		t.Errorf("head = %v", head)
	}
	if head["watches_count"] != 2 || head["calls_count"] != 3 || head["indirect_branches_count"] != 3 {
		t.Errorf("counts = %v, %v, %v", head["watches_count"], head["calls_count"], head["indirect_branches_count"])
	}
	if _, present := head["fn_end"]; present {
		t.Error("fn_end is absent from the report and was made up")
	}
	for _, k := range []string{"watches", "calls", "indirect_branches"} {
		if _, present := head[k]; present {
			t.Errorf("%s stayed in the head", k)
		}
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "symex libbar.so@0x10 : aucun ELF de ce chemin" {
		t.Errorf("errors = %+v", e)
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeSymexWatchResultsAreSortedAndCutPerWatch(t *testing.T) {
	env := finishNativeSymexFixture(t, symexReportBody, 2)
	watches := env.Tails["watches"]
	if watches.Total != 2 || watches.Returned != 2 || watches.Truncated {
		t.Fatalf("watches tail = %+v; max_rows cuts results, not watches", watches)
	}
	first := watches.Items[0].(map[string]any)
	if first["insn_addr"] != "0x1a40" || first["elf"] != "lib/arm64-v8a/libfoo.so" || first["fn_start"] != "0x1a00" {
		t.Errorf("watches[0] = %v", first)
	}
	results := first["results"].([]any)
	if len(results) != 2 || first["results_total"] != 3 || first["results_truncated"] != true {
		t.Fatalf("results = %d shown, total %v, truncated %v", len(results), first["results_total"], first["results_truncated"])
	}
	top := results[0].(map[string]any)
	if top["paths"] != float64(5) || results[1].(map[string]any)["paths"] != float64(3) {
		t.Errorf("results are not sorted by paths descending: %v", results)
	}
	// Expressions, peeks and trace_truncated come back whole.
	if top["value"].(map[string]any)["text"] != "0x112" || top["trace_truncated"] != true {
		t.Errorf("results[0] = %v", top)
	}
	if peeks := top["peeks"].([]any); len(peeks) != 1 || len(peeks[0].(map[string]any)["bytes"].([]any)) != 2 {
		t.Errorf("peeks = %v", top["peeks"])
	}
	if _, present := top["value2"]; present {
		t.Error("value2 is absent from the report and was made up")
	}
	second := watches.Items[1].(map[string]any)
	if second["reached"] != false || second["instruction"] != nil || second["results_total"] != 0 || second["results_truncated"] != false {
		t.Errorf("watches[1] = %v", second)
	}
}

func TestNativeSymexCallsAndIndirectBranchesAreCutAtMaxRows(t *testing.T) {
	env := finishNativeSymexFixture(t, symexReportBody, 2)
	calls := env.Tails["calls"]
	if calls.Total != 3 || calls.Returned != 2 || !calls.Truncated {
		t.Fatalf("calls tail = %+v", calls)
	}
	c0, c1 := calls.Items[0].(map[string]any), calls.Items[1].(map[string]any)
	if c0["import"] != "strlen" || c0["paths"] != float64(7) || c1["paths"] != float64(4) {
		t.Errorf("calls are not sorted by paths descending: %v", calls.Items)
	}
	if _, present := c1["import"]; present {
		t.Error("an import was made up for an indirect call")
	}
	branches := env.Tails["indirect_branches"]
	if branches.Total != 3 || branches.Returned != 2 || !branches.Truncated {
		t.Errorf("indirect_branches tail = %+v", branches)
	}
	if b := branches.Items[0].(map[string]any); b["insn_addr"] != "0x1a60" {
		t.Errorf("indirect_branches keep the report's order: %v", branches.Items)
	}
}

// End to end against a stub drakkar that refuses the mode, as one predating
// --native-symex does; a report left by an earlier run must not be read.
func TestNativeSymexUnknownModeQuotesDrakkar(t *testing.T) {
	const clap = "error: unexpected argument '--native-symex' found"
	stubDrakkar(t, `echo "`+clap+`" >&2
echo >&2
echo 'Usage: drakkar [OPTIONS] [APK]' >&2
exit 2
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(out, "report.json")
	if err := os.WriteFile(stale, []byte(symexReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeSymex(context.Background(), NativeSymexInput{APK: apk, Function: "*@1a00", Watch: []string{"1a40"}, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if env.Drakkar.ExitCode != 2 || env.Drakkar.Complete {
		t.Errorf("exit = %d, complete = %v", env.Drakkar.ExitCode, env.Drakkar.Complete)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != clap {
		t.Errorf("errors = %+v, want Drakkar's message as is", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "does not know --native-symex") || !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestNativeSymexDrakkarRefusalComesBackInErrors(t *testing.T) {
	const refusal = "Error: --native-symex-peek : élément \"1a40:x31+0:8\" : registre \"x31\" : x0..x30 ou sp"
	stubDrakkar(t, `echo '`+refusal+`' >&2
exit 1
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := s.NativeSymex(context.Background(), NativeSymexInput{
		APK: apk, Function: "*@1a00", Watch: []string{"1a40"}, Peek: []string{"1a40:x31+0:8"}, OutDir: filepath.Join(base, "out"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != refusal {
		t.Errorf("errors = %+v", e)
	}
	if strings.Contains(strings.Join(env.Notes, "\n"), "does not know") {
		t.Errorf("a refused argument was taken for an unknown mode: %q", env.Notes)
	}
}
