package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-slice report over two ELFs: the first
// function carries an entry-level counter and a source field this server does
// not know of, a query cut by the budget and a query without source.
const sliceReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "slices": [
  {"elf": "lib/arm64-v8a/libfoo.so", "fn_start": "0x2f000", "fn_end": "0x2f400", "bound": "symbol", "future_counter": 7,
   "queries": [
    {"at": "0x2f3c0", "location": "x0+0x5a9:1", "complete": false, "steps": 200000, "sources_total": 3, "sources_truncated": true,
     "sources": [
      {"kind": "init_mem", "location": "x0+0x5a9:1", "insn_addr": "0x2f000", "bytes": [0, 1],
       "chain": [{"insn_addr": "0x2f3b0", "mnemonic": "ldrb", "operands": "w8, [x0, #0x5a9]"}], "chain_truncated": false,
       "future_field": {"kept": true}}
     ]},
    {"at": "0x2f3d4", "location": "x8", "complete": true, "steps": 12, "sources_total": 0, "sources_truncated": false, "sources": []}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "fn_start": "0x1000", "fn_end": "0x1100", "bound": "eh_frame",
   "queries": [
    {"at": "0x1010", "location": "x0", "complete": true, "steps": 4, "sources_total": 1, "sources_truncated": false,
     "sources": [{"kind": "const", "value": "0x5", "insn_addr": "0x1000", "bytes": [0, 8], "chain": [], "chain_truncated": false}]}
   ]}
 ],
 "errors": ["slice *@0x2f000 (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeSliceFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeSlice(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeSliceArgv(t *testing.T) {
	one, steps, sources := 1, 5000, 20
	base := []string{"/a.apk", "--native", "--native-slice=lib/arm64-v8a/libfoo.so@0x2f000", "--native-slice-at=0x2f3c0:x0+0x5a9:1"}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }
	query := NativeSliceInput{Function: "lib/arm64-v8a/libfoo.so@0x2f000", At: []string{"0x2f3c0:x0+0x5a9:1"}}
	for name, c := range map[string]struct {
		tune func(*NativeSliceInput)
		want []string
	}{
		"function and at": {func(*NativeSliceInput) {}, base},
		"star and two queries": {
			func(in *NativeSliceInput) {
				in.Function = "*@2f000"
				in.At = []string{"2f3c0:x8", "0x2f3d4:sp+0x1c61:1"}
			},
			[]string{"/a.apk", "--native", "--native-slice=*@2f000", "--native-slice-at=2f3c0:x8,0x2f3d4:sp+0x1c61:1"},
		},
		"depth":       {func(in *NativeSliceInput) { in.Depth = &one }, with("--native-slice-depth=1")},
		"follow":      {func(in *NativeSliceInput) { in.Follow = []string{"2f100", "0x2f200"} }, with("--native-slice-follow=2f100,0x2f200")},
		"max_steps":   {func(in *NativeSliceInput) { in.MaxSteps = &steps }, with("--native-slice-max-steps=5000")},
		"max_sources": {func(in *NativeSliceInput) { in.MaxSources = &sources }, with("--native-slice-max-sources=20")},
		"everything": {
			func(in *NativeSliceInput) {
				in.Depth, in.Follow, in.MaxSteps, in.MaxSources = &one, []string{"2f100"}, &steps, &sources
			},
			with("--native-slice-depth=1", "--native-slice-follow=2f100", "--native-slice-max-steps=5000", "--native-slice-max-sources=20"),
		},
	} {
		in := query
		c.tune(&in)
		argv, err := nativeSliceArgs("/a.apk", "/out/report.json", in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeSliceRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxSliceQueries; i++ {
		many = append(many, fmt.Sprintf("%x:x0", 0x1000+4*i))
	}
	fn, at := "*@1000", []string{"1004:x0"}

	for name, in := range map[string]NativeSliceInput{
		"no function":          {APK: apk, At: at},
		"function without @":   {APK: apk, Function: "libfoo.so", At: at},
		"function without elf": {APK: apk, Function: "@1000", At: at},
		"function not hex":     {APK: apk, Function: "*@main", At: at},
		"no at":                {APK: apk, Function: fn},
		"at without colon":     {APK: apk, Function: fn, At: []string{"1004"}},
		"at not hex":           {APK: apk, Function: fn, At: []string{"zz:x0"}},
		"at without location":  {APK: apk, Function: fn, At: []string{"1004:"}},
		"at with a comma":      {APK: apk, Function: fn, At: []string{"1004:x0,1008:x1"}},
		"17 at":                {APK: apk, Function: fn, At: many},
		"follow not hex":       {APK: apk, Function: fn, At: at, Follow: []string{"memcpy"}},
		"negative depth":       {APK: apk, Function: fn, At: at, Depth: &negative},
		"negative max_steps":   {APK: apk, Function: fn, At: at, MaxSteps: &negative},
		"negative max_sources": {APK: apk, Function: fn, At: at, MaxSources: &negative},
		"relative apk":         {APK: "a.apk", Function: fn, At: at},
	} {
		if _, err := s.NativeSlice(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// The grammar of a location is Drakkar's to judge; duplicates are dropped.
	if err := checkNativeSlice(NativeSliceInput{Function: fn, At: append(many[:maxSliceQueries-1], many[0], "1004:q99")}); err != nil {
		t.Errorf("16 distinct queries were refused: %v", err)
	}
}

func TestNativeSliceShapesTwoFunctions(t *testing.T) {
	env := finishNativeSliceFixture(t, sliceReportBody, 50)
	heads := env.Result.(map[string]any)["slices"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["fn_start"] != "0x2f000" || first["fn_end"] != "0x2f400" || first["bound"] != "symbol" || first["future_counter"] != float64(7) {
		t.Errorf("head[0] = %v", first)
	}
	queries := first["queries"].([]any)
	q0 := queries[0].(map[string]any)
	if _, present := q0["sources"]; present {
		t.Error("the sources came back in the head")
	}
	for _, k := range []string{"at", "location", "complete", "steps", "sources_total", "sources_truncated"} {
		if _, present := q0[k]; !present {
			t.Errorf("query field %s was dropped", k)
		}
	}
	if len(q0) != 6 || q0["complete"] != false || q0["sources_total"] != float64(3) {
		t.Errorf("queries[0] = %v", q0)
	}

	sources := env.Tails["sources"]
	if sources.Total != 2 || sources.Truncated {
		t.Fatalf("sources tail = %+v", sources)
	}
	s0 := sources.Items[0].(map[string]any)
	if s0["kind"] != "init_mem" || s0["location"] != "x0+0x5a9:1" || s0["elf"] != "lib/arm64-v8a/libfoo.so" || s0["fn_start"] != "0x2f000" || s0["query_at"] != "0x2f3c0" || s0["query_location"] != "x0+0x5a9:1" {
		t.Errorf("sources[0] = %v", s0)
	}
	if chain := s0["chain"].([]any); len(chain) != 1 || chain[0].(map[string]any)["mnemonic"] != "ldrb" {
		t.Errorf("the chain did not come back whole: %v", s0["chain"])
	}
	if future, ok := s0["future_field"].(map[string]any); !ok || future["kept"] != true {
		t.Errorf("an unknown source field was dropped or changed: %v", s0)
	}
	s1 := sources.Items[1].(map[string]any)
	if _, present := s1["location"]; present {
		t.Error("a const source has no location and one was made up")
	}
	if s1["value"] != "0x5" || s1["query_location"] != "x0" || s1["elf"] != "lib/arm64-v8a/libbar.so" {
		t.Errorf("sources[1] = %v", s1)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "slice *@0x2f000 (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "query 0x2f3c0 x0+0x5a9:1 in lib/arm64-v8a/libfoo.so@0x2f000 is incomplete: the max_steps budget or the max_sources cap was reached, so the result is partial (1 of 3 sources rendered, 200000 steps)") {
		t.Errorf("no note for the incomplete query: %q", env.Notes)
	}
	if !strings.Contains(notes, "query 0x2f3d4 x8 in lib/arm64-v8a/libfoo.so@0x2f000 found no source") {
		t.Errorf("no note for the query without source: %q", env.Notes)
	}
	if strings.Contains(notes, "0x1010 x0 in lib/arm64-v8a/libbar.so") {
		t.Errorf("a complete query with a source got a note: %q", env.Notes)
	}
}

func TestNativeSliceTailIsCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeSliceFixture(t, sliceReportBody, 1)
	sources := env.Tails["sources"]
	if sources.Total != 2 || sources.Returned != 1 || !sources.Truncated {
		t.Fatalf("sources tail = %+v; total counts the sources in the report", sources)
	}
	q0 := env.Result.(map[string]any)["slices"].([]any)[0].(map[string]any)["queries"].([]any)[0].(map[string]any)
	if q0["sources_total"] != float64(3) {
		t.Errorf("max_rows changed Drakkar's totals: %v", q0)
	}
}

func TestNativeSliceReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["slice *@0x2f000 : aucun ELF AArch64 n'a de code exécutable en 0x2f000"]}`
	env := finishNativeSliceFixture(t, body, 50)
	if heads := env.Result.(map[string]any)["slices"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	if sources := env.Tails["sources"]; sources.Total != 0 || len(sources.Items) != 0 {
		t.Errorf("sources tail = %+v", sources)
	}
	if e := env.Tails["errors"]; e.Total != 1 {
		t.Errorf("errors = %+v", e)
	}
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "no slices entry") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func sliceCall(s *Service, apk, out string) (*Envelope, error) {
	steps := 10
	in := NativeSliceInput{APK: apk, Function: "*@2f000", At: []string{"2f3c0:x8"}, MaxSteps: &steps, OutDir: out}
	return s.NativeSlice(context.Background(), in)
}

func TestNativeSliceUnknownModeQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-slice' found", 2, sliceReportBody, sliceCall)
	if !strings.Contains(notes, "does not know --native-slice: it predates the mode") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeSliceUnknownOptionQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-slice-max-steps' found", 2, sliceReportBody, sliceCall)
	if !strings.Contains(notes, "does not know --native-slice-max-steps: it knows the --native-slice mode but not this option") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeSliceDrakkarRefusalComesBackInErrors(t *testing.T) {
	notes := refusedBy(t, "Error: --native-slice-at (obligatoire) : élément 2f3c0:x31 : registre x31 : x0..x30 ou sp", 1, sliceReportBody, sliceCall)
	if strings.Contains(notes, "does not know") {
		t.Errorf("notes = %q", notes)
	}
}
