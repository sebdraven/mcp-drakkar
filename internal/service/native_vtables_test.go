package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-vtables report over two ELFs: the first had
// its tables cut by Drakkar, one with matched and refs, one with neither and
// no destructor; the second has no table matching.
const vtablesReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "vtables": [
  {"elf": "lib/arm64-v8a/libfoo.so", "tables_total": 40, "tables_matched": 3, "truncated": true,
   "tables": [
    {"vaddr": "0x2000", "section": ".data.rel.ro", "drop": "0x1040", "size": "0x18", "align": "0x8", "methods_count": 2,
     "methods": [
      {"offset": "0x18", "value": "0x1080", "function": {"fn_start": "0x1080", "fn_end": "0x10c0", "bound": "eh_frame"}},
      {"offset": "0x20", "value": "0x10c0", "function": {"fn_start": "0x10c0", "fn_end": null, "bound": "none"}}
     ],
     "matched": ["0x18"],
     "addr_refs": {"total": 1, "truncated": false, "items": [{"insn_addr": "0x1104", "adrp_addr": "0x1100", "kind": "address"}]},
     "data_refs": {"total": 0, "truncated": false, "items": []}},
    {"vaddr": "0x2040", "section": ".data.rel.ro", "drop": null, "size": "0x0", "align": "0x1", "methods_count": 1,
     "methods": [
      {"offset": "0x18", "value": "0x1080", "function": {"fn_start": "0x1080", "fn_end": "0x10c0", "bound": "eh_frame"}}
     ]}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "tables_total": 12, "tables_matched": 0, "truncated": false, "tables": []}
 ],
 "errors": ["vtables * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeVtablesFixture(t *testing.T, body string, maxRows int, in NativeVtablesInput) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeVtables(env, writeReport(t, body), maxRows, in); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeVtablesArgv(t *testing.T) {
	two, zero := 2, 0
	for name, c := range map[string]struct {
		in   NativeVtablesInput
		want []string
	}{
		"elf omitted, no filter": {
			NativeVtablesInput{},
			[]string{"/a.apk", "--native", "--native-vtables=*"},
		},
		"elf named": {
			NativeVtablesInput{ELF: "lib/arm64-v8a/libfoo.so"},
			[]string{"/a.apk", "--native", "--native-vtables=lib/arm64-v8a/libfoo.so"},
		},
		"fn": {
			NativeVtablesInput{Fn: []string{"1080", "0x10c0"}},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-fn=1080,0x10c0"},
		},
		"slot": {
			NativeVtablesInput{Slot: "0x38"},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-slot=0x38"},
		},
		"size": {
			NativeVtablesInput{Size: "24"},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-size=24"},
		},
		"at": {
			NativeVtablesInput{At: []string{"2000"}},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-at=2000"},
		},
		"max": {
			NativeVtablesInput{Max: &two},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-max=2"},
		},
		"max zero": {
			NativeVtablesInput{Max: &zero},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-max=0"},
		},
		"refs": {
			NativeVtablesInput{Refs: true},
			[]string{"/a.apk", "--native", "--native-vtables=*", "--native-vtables-refs"},
		},
		"everything": {
			NativeVtablesInput{ELF: "lib/arm64-v8a/libfoo.so", Fn: []string{"1080"}, Slot: "24", Size: "0x18", At: []string{"2000", "2040"}, Max: &two, Refs: true},
			[]string{"/a.apk", "--native", "--native-vtables=lib/arm64-v8a/libfoo.so",
				"--native-vtables-fn=1080", "--native-vtables-slot=24", "--native-vtables-size=0x18",
				"--native-vtables-at=2000,2040", "--native-vtables-max=2", "--native-vtables-refs"},
		},
	} {
		argv, err := nativeVtablesArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeVtablesRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxVtablesAddresses; i++ {
		many = append(many, fmt.Sprintf("%x", 0x1000+4*i))
	}

	for name, in := range map[string]NativeVtablesInput{
		"fn not hex":          {APK: apk, Fn: []string{"main"}},
		"fn empty item":       {APK: apk, Fn: []string{"1080", ""}},
		"fn two in one item":  {APK: apk, Fn: []string{"1080,10c0"}},
		"65 fn":               {APK: apk, Fn: many},
		"at not hex":          {APK: apk, At: []string{"zz"}},
		"65 at":               {APK: apk, At: many},
		"slot not a number":   {APK: apk, Slot: "abc"},
		"slot bare 0x":        {APK: apk, Slot: "0x"},
		"slot negative":       {APK: apk, Slot: "-8"},
		"slot hex without 0x": {APK: apk, Slot: "1a"},
		"size uppercase 0X":   {APK: apk, Size: "0X18"},
		"size fractional":     {APK: apk, Size: "1.5"},
		"size double prefix":  {APK: apk, Size: "0x0x18"},
		"negative max":        {APK: apk, Max: &negative},
		"relative apk":        {APK: "a.apk"},
	} {
		if _, err := s.NativeVtables(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// Drakkar drops duplicates before counting; slot's multiple of 8 is its to refuse.
	ok := NativeVtablesInput{Fn: append(many[:maxVtablesAddresses], "0x"+many[0]), Slot: "0x1c", Size: "24"}
	if err := checkNativeVtables(ok); err != nil {
		t.Errorf("64 distinct addresses, a duplicate and an odd slot were refused: %v", err)
	}
}

func TestNativeVtablesShapesTwoELFs(t *testing.T) {
	two := 2
	in := NativeVtablesInput{Fn: []string{"0x1080"}, Slot: "0x18", Max: &two}
	env := finishNativeVtablesFixture(t, vtablesReportBody, 50, in)
	heads := env.Result.(map[string]any)["vtables"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["tables_total"] != float64(40) || first["tables_matched"] != float64(3) || first["truncated"] != true {
		t.Errorf("head[0] = %v", first)
	}
	if _, present := first["tables"]; present {
		t.Error("the tables came back in the head")
	}

	tables := env.Tails["tables"]
	if tables.Total != 2 || tables.Truncated {
		t.Fatalf("tables tail = %+v", tables)
	}
	t0, t1 := tables.Items[0].(map[string]any), tables.Items[1].(map[string]any)
	if t0["vaddr"] != "0x2000" || t0["drop"] != "0x1040" || t0["methods_count"] != float64(2) || t0["elf"] != "lib/arm64-v8a/libfoo.so" {
		t.Errorf("tables[0] = %v", t0)
	}
	if m := t0["methods"].([]any); len(m) != 2 || m[1].(map[string]any)["offset"] != "0x20" {
		t.Errorf("tables[0].methods = %v, want them whole", m)
	}
	if m := t0["matched"].([]any); len(m) != 1 || m[0] != "0x18" {
		t.Errorf("tables[0].matched = %v", m)
	}
	if a := t0["addr_refs"].(map[string]any); a["total"] != float64(1) || len(a["items"].([]any)) != 1 {
		t.Errorf("tables[0].addr_refs = %v, want it whole", a)
	}
	if _, present := t0["data_refs"]; !present {
		t.Error("data_refs is in the report and was dropped")
	}
	for _, k := range []string{"matched", "addr_refs", "data_refs"} {
		if _, present := t1[k]; present {
			t.Errorf("%s is absent from the report and was made up", k)
		}
	}
	if drop, present := t1["drop"]; !present || drop != nil {
		t.Errorf("drop is null in the report: %v, %v", drop, present)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "vtables * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "tables of lib/arm64-v8a/libfoo.so: Drakkar kept 2 of 3 matched, 40 detected (exact totals); filters: fn=0x1080 slot=0x18, max: 2") {
		t.Errorf("no note for the list Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "no table matched in lib/arm64-v8a/libbar.so, of 12 detected; filters: fn=0x1080 slot=0x18, max: 2") {
		t.Errorf("no note for the ELF without match: %q", env.Notes)
	}
	if strings.Contains(notes, "no table matched in lib/arm64-v8a/libfoo.so") {
		t.Errorf("an ELF with tables was called empty: %q", env.Notes)
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeVtablesNoteWithoutFilter(t *testing.T) {
	env := finishNativeVtablesFixture(t, vtablesReportBody, 50, NativeVtablesInput{})
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "filters: none, max: Drakkar's default") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func TestNativeVtablesTailIsCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeVtablesFixture(t, vtablesReportBody, 1, NativeVtablesInput{})
	tables := env.Tails["tables"]
	if tables.Total != 2 || tables.Returned != 1 || !tables.Truncated {
		t.Fatalf("tables tail = %+v; total counts the tables in the report", tables)
	}
	if t0 := tables.Items[0].(map[string]any); t0["vaddr"] != "0x2000" {
		t.Errorf("tables keep the report's order: %v", tables.Items)
	}
	head := env.Result.(map[string]any)["vtables"].([]any)[0].(map[string]any)
	if head["tables_matched"] != float64(3) || head["tables_total"] != float64(40) {
		t.Errorf("max_rows changed Drakkar's totals: %v", head)
	}
}

func TestNativeVtablesReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["vtables * : aucun ELF AArch64"]}`
	env := finishNativeVtablesFixture(t, body, 50, NativeVtablesInput{})
	if heads := env.Result.(map[string]any)["vtables"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	if tables := env.Tails["tables"]; tables.Total != 0 || len(tables.Items) != 0 {
		t.Errorf("tables tail = %+v", tables)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "vtables * : aucun ELF AArch64" {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "no vtables entry") || strings.Contains(notes, "no table matched") {
		t.Errorf("notes = %q", env.Notes)
	}
}

// End to end against a stub drakkar that refuses the mode, as one predating
// --native-vtables does; a report left by an earlier run must not be read.
func TestNativeVtablesUnknownModeQuotesDrakkar(t *testing.T) {
	const clap = "error: unexpected argument '--native-vtables' found"
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
	if err := os.WriteFile(stale, []byte(vtablesReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeVtables(context.Background(), NativeVtablesInput{APK: apk, Refs: true, OutDir: out})
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
	if !strings.Contains(notes, "does not know --native-vtables") || !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestNativeVtablesDrakkarRefusalComesBackInErrors(t *testing.T) {
	const refusal = `Error: --native-vtables-slot : élément "0x1c" : multiple de 8, au moins 0x18`
	stubDrakkar(t, `echo 'Error: --native-vtables-slot : élément "0x1c" : multiple de 8, au moins 0x18' >&2
exit 1
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := s.NativeVtables(context.Background(), NativeVtablesInput{APK: apk, Slot: "0x1c", OutDir: filepath.Join(base, "out")})
	if err != nil {
		t.Fatal(err)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != refusal {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if strings.Contains(notes, "does not know") || !strings.Contains(notes, "Drakkar's message, verbatim: "+refusal) {
		t.Errorf("notes = %q", env.Notes)
	}
}
