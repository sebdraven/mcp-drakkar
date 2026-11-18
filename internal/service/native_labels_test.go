package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-labels report over two ELFs: the first had
// its functions cut by Drakkar and carries an ELF-level counter and a function
// field this server does not know of; the second has no function matching.
const labelsReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "labels": [
  {"elf": "lib/arm64-v8a/libfoo.so", "functions_total": 120, "functions_shared_only": 7, "functions_matched": 3, "truncated": true,
   "functions": [
    {"fn_start": "0x1000", "fn_end": "0x1200", "bound": "symtab", "label": "connect", "label_kind": "fn_name",
     "names": ["connect"], "module": "net", "all_tags": ["net"], "strings_total": 2, "strings_shared": 0, "strings_truncated": false,
     "strings": [
      {"vaddr": "0x5000", "value": "[net] connect to {}", "value_truncated": false, "boundary": "rust_fatptr", "insn_addr": "0x1010", "shared": false},
      {"vaddr": "0x5100", "value": "src/net.rs", "value_truncated": false, "boundary": "nul", "insn_addr": "0x1f04", "via_fragment": "0x1f00", "shared": false}
     ],
     "future_field": {"kept": true}},
    {"fn_start": "0x2000", "fn_end": null, "bound": "eh_frame", "label": null, "label_kind": "none",
     "names": [], "all_tags": [], "strings_total": 1, "strings_shared": 1, "strings_truncated": false,
     "strings": [
      {"vaddr": "0x5200", "value": "connect", "value_truncated": false, "boundary": "heuristic", "insn_addr": "0x2f04", "via_fragment": "0x2f00", "shared": true, "fragment_callers": 12}
     ]}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "functions_total": 30, "functions_shared_only": 0, "functions_matched": 0, "truncated": false, "functions": []}
 ],
 "errors": ["labels * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeLabelsFixture(t *testing.T, body string, maxRows int, in NativeLabelsInput) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeLabels(env, writeReport(t, body), maxRows, in); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeLabelsArgv(t *testing.T) {
	two, fifty, zero, eight := 2, 50, 0, 8
	for name, c := range map[string]struct {
		in   NativeLabelsInput
		want []string
	}{
		"elf omitted, no filter": {
			NativeLabelsInput{},
			[]string{"/a.apk", "--native", "--native-labels=*"},
		},
		"elf named": {
			NativeLabelsInput{ELF: "lib/arm64-v8a/libfoo.so"},
			[]string{"/a.apk", "--native", "--native-labels=lib/arm64-v8a/libfoo.so"},
		},
		"fn": {
			NativeLabelsInput{Fn: []string{"1010", "0x2f04"}},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-fn=1010,0x2f04"},
		},
		"match": {
			NativeLabelsInput{Match: []string{"connect", "[net]"}},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-match=connect,[net]"},
		},
		"max": {
			NativeLabelsInput{Max: &two},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-max=2"},
		},
		"strings_max": {
			NativeLabelsInput{StringsMax: &fifty},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-strings-max=50"},
		},
		"fragment_fanout": {
			NativeLabelsInput{FragmentFanout: &eight},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-fragment-fanout=8"},
		},
		"zeros": {
			NativeLabelsInput{Max: &zero, StringsMax: &zero, FragmentFanout: &zero},
			[]string{"/a.apk", "--native", "--native-labels=*", "--native-labels-max=0", "--native-labels-strings-max=0", "--native-labels-fragment-fanout=0"},
		},
		"everything": {
			NativeLabelsInput{ELF: "lib/arm64-v8a/libfoo.so", Fn: []string{"1010"}, Match: []string{"connect"}, Max: &two, StringsMax: &fifty, FragmentFanout: &eight},
			[]string{"/a.apk", "--native", "--native-labels=lib/arm64-v8a/libfoo.so",
				"--native-labels-fn=1010", "--native-labels-match=connect",
				"--native-labels-max=2", "--native-labels-strings-max=50", "--native-labels-fragment-fanout=8"},
		},
	} {
		argv, err := nativeLabelsArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeLabelsRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxLabelsAddresses; i++ {
		many = append(many, fmt.Sprintf("%x", 0x1000+4*i))
	}

	for name, in := range map[string]NativeLabelsInput{
		"fn not hex":               {APK: apk, Fn: []string{"main"}},
		"fn empty item":            {APK: apk, Fn: []string{"1010", ""}},
		"fn two in one item":       {APK: apk, Fn: []string{"1010,2f04"}},
		"65 fn":                    {APK: apk, Fn: many},
		"empty pattern":            {APK: apk, Match: []string{"connect", ""}},
		"pattern with a comma":     {APK: apk, Match: []string{"a,b"}},
		"negative max":             {APK: apk, Max: &negative},
		"negative strings_max":     {APK: apk, StringsMax: &negative},
		"negative fragment_fanout": {APK: apk, FragmentFanout: &negative},
		"relative apk":             {APK: "a.apk"},
	} {
		if _, err := s.NativeLabels(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// Drakkar drops duplicates before counting.
	if err := checkNativeLabels(NativeLabelsInput{Fn: append(many[:maxLabelsAddresses], "0x"+many[0]), Match: []string{" ", "[net]"}}); err != nil {
		t.Errorf("64 distinct addresses and a duplicate were refused: %v", err)
	}
}

func TestNativeLabelsShapesTwoELFs(t *testing.T) {
	two := 2
	in := NativeLabelsInput{Match: []string{"connect"}, Max: &two}
	env := finishNativeLabelsFixture(t, labelsReportBody, 50, in)
	heads := env.Result.(map[string]any)["labels"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["functions_total"] != float64(120) || first["functions_matched"] != float64(3) || first["truncated"] != true {
		t.Errorf("head[0] = %v", first)
	}
	if _, present := first["functions"]; present {
		t.Error("the functions came back in the head")
	}

	functions := env.Tails["functions"]
	if functions.Total != 2 || functions.Truncated {
		t.Fatalf("functions tail = %+v", functions)
	}
	f0, f1 := functions.Items[0].(map[string]any), functions.Items[1].(map[string]any)
	if f0["fn_start"] != "0x1000" || f0["label"] != "connect" || f0["label_kind"] != "fn_name" || f0["module"] != "net" || f0["elf"] != "lib/arm64-v8a/libfoo.so" {
		t.Errorf("functions[0] = %v", f0)
	}
	if s := f0["strings"].([]any); len(s) != 2 || s[1].(map[string]any)["via_fragment"] != "0x1f00" {
		t.Errorf("functions[0].strings = %v, want them whole", s)
	}
	if _, present := f1["module"]; present {
		t.Error("module is absent from the report and was made up")
	}
	if label, present := f1["label"]; !present || label != nil {
		t.Errorf("label is null in the report: %v, %v", label, present)
	}
	if s := f1["strings"].([]any)[0].(map[string]any); s["shared"] != true || s["fragment_callers"] != float64(12) {
		t.Errorf("functions[1].strings[0] = %v", s)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "labels * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "functions of lib/arm64-v8a/libfoo.so: Drakkar kept 2 of 3 matched, 120 with an unshared string, 7 with shared strings only (exact totals); filters: match=connect, max: 2") {
		t.Errorf("no note for the list Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "no function matched in lib/arm64-v8a/libbar.so, of 30 with an unshared string, 0 with shared strings only; filters: match=connect, max: 2") {
		t.Errorf("no note for the ELF without match: %q", env.Notes)
	}
	if strings.Contains(notes, "no function matched in lib/arm64-v8a/libfoo.so") {
		t.Errorf("an ELF with functions was called empty: %q", env.Notes)
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

// The mode's report evolves: a field this server does not know of, at either
// level, comes back as Drakkar wrote it.
func TestNativeLabelsUnknownFieldsComeBackAsIs(t *testing.T) {
	env := finishNativeLabelsFixture(t, labelsReportBody, 50, NativeLabelsInput{})
	head := env.Result.(map[string]any)["labels"].([]any)[0].(map[string]any)
	if head["functions_shared_only"] != float64(7) {
		t.Errorf("an ELF-level counter was dropped: %v", head)
	}
	f0 := env.Tails["functions"].Items[0].(map[string]any)
	future, ok := f0["future_field"].(map[string]any)
	if !ok || future["kept"] != true {
		t.Errorf("an unknown function field was dropped or changed: %v", f0)
	}
	for _, k := range []string{"fn_start", "fn_end", "bound", "label", "label_kind", "names", "module", "all_tags", "strings_total", "strings_shared", "strings_truncated", "strings"} {
		if _, present := f0[k]; !present {
			t.Errorf("%s was dropped", k)
		}
	}
	if len(f0) != 14 {
		t.Errorf("functions[0] has %d fields, want the report's 13 and elf: %v", len(f0), f0)
	}
}

func TestNativeLabelsTailIsCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeLabelsFixture(t, labelsReportBody, 1, NativeLabelsInput{})
	functions := env.Tails["functions"]
	if functions.Total != 2 || functions.Returned != 1 || !functions.Truncated {
		t.Fatalf("functions tail = %+v; total counts the functions in the report", functions)
	}
	if f := functions.Items[0].(map[string]any); f["fn_start"] != "0x1000" {
		t.Errorf("functions keep the report's order: %v", functions.Items)
	}
	head := env.Result.(map[string]any)["labels"].([]any)[0].(map[string]any)
	if head["functions_matched"] != float64(3) || head["functions_total"] != float64(120) {
		t.Errorf("max_rows changed Drakkar's totals: %v", head)
	}
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "filters: none, max: Drakkar's default") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func TestNativeLabelsReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["labels * : aucun ELF AArch64"]}`
	env := finishNativeLabelsFixture(t, body, 50, NativeLabelsInput{})
	if heads := env.Result.(map[string]any)["labels"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	if functions := env.Tails["functions"]; functions.Total != 0 || len(functions.Items) != 0 {
		t.Errorf("functions tail = %+v", functions)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "labels * : aucun ELF AArch64" {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "no labels entry") || strings.Contains(notes, "no function matched") {
		t.Errorf("notes = %q", env.Notes)
	}
}

// End to end against a stub drakkar that refuses the mode, as one predating
// --native-labels does; a report left by an earlier run must not be read.
func TestNativeLabelsUnknownModeQuotesDrakkar(t *testing.T) {
	const clap = "error: unexpected argument '--native-labels' found"
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
	if err := os.WriteFile(stale, []byte(labelsReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeLabels(context.Background(), NativeLabelsInput{APK: apk, Match: []string{"connect"}, OutDir: out})
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
	if !strings.Contains(notes, "does not know --native-labels") || !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestNativeLabelsDrakkarRefusalComesBackInErrors(t *testing.T) {
	const refusal = "Error: archive illisible : invalid Zip archive: Could not find EOCD"
	stubDrakkar(t, `echo '`+refusal+`' >&2
exit 1
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := s.NativeLabels(context.Background(), NativeLabelsInput{APK: apk, OutDir: filepath.Join(base, "out")})
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
