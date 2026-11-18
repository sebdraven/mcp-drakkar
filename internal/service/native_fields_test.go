package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-fields report over two ELFs: the first had
// its functions cut by Drakkar and carries an ELF-level counter and a function
// field this server does not know of; the second has no function matching.
const fieldsReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "fields": [
  {"elf": "lib/arm64-v8a/libfoo.so", "functions_total": 40, "functions_matched": 3, "truncated": true, "future_counter": 7,
   "functions": [
    {"fn_start": "0x1000", "fn_end": "0x1400", "bound": "symtab", "struct_names": ["BabaAccountPb"], "fields_count": 2,
     "fields": [
      {"name": "user_id", "vaddr": "0x5000", "boundary": "rust_fatptr", "sites": ["0x1010", "0x1040"], "sites_count": 2},
      {"name": "token", "vaddr": "0x5010", "boundary": "rust_code", "sites": ["0x2204"], "sites_count": 1, "via_fragment": "0x2200"}
     ],
     "callers": [{"insn_addr": "0x3010", "function": {"fn_start": "0x3000", "fn_end": "0x3100", "bound": "eh_frame"}}, {"insn_addr": "0x9000", "function": null}],
     "future_field": {"kept": true}},
    {"fn_start": "0x4000", "fn_end": null, "bound": "eh_frame", "struct_names": [], "fields_count": 0, "fields": [], "callers": []}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "functions_total": 0, "functions_matched": 0, "truncated": false, "functions": []}
 ],
 "errors": ["fields * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeFieldsFixture(t *testing.T, body string, maxRows int, in NativeFieldsInput) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeFields(env, writeReport(t, body), maxRows, in); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeFieldsArgv(t *testing.T) {
	two, three, eight := 2, 3, 8
	head := []string{"/a.apk", "--native", "--native-fields=*"}
	with := func(extra ...string) []string { return append(append([]string{}, head...), extra...) }
	for name, c := range map[string]struct {
		in   NativeFieldsInput
		want []string
	}{
		"elf omitted, no filter": {NativeFieldsInput{}, head},
		"elf named": {
			NativeFieldsInput{ELF: "lib/arm64-v8a/libfoo.so"},
			[]string{"/a.apk", "--native", "--native-fields=lib/arm64-v8a/libfoo.so"},
		},
		"fn":              {NativeFieldsInput{Fn: []string{"1010", "0x2f04"}}, with("--native-fields-fn=1010,0x2f04")},
		"name":            {NativeFieldsInput{Name: []string{"user_id", "Token"}}, with("--native-fields-name=user_id,Token")},
		"min":             {NativeFieldsInput{Min: &three}, with("--native-fields-min=3")},
		"fragment_fanout": {NativeFieldsInput{FragmentFanout: &eight}, with("--native-fields-fragment-fanout=8")},
		"max":             {NativeFieldsInput{Max: &two}, with("--native-fields-max=2")},
		"everything": {
			NativeFieldsInput{ELF: "lib/arm64-v8a/libfoo.so", Fn: []string{"1010"}, Name: []string{"token"}, Min: &three, FragmentFanout: &eight, Max: &two},
			[]string{"/a.apk", "--native", "--native-fields=lib/arm64-v8a/libfoo.so",
				"--native-fields-fn=1010", "--native-fields-name=token", "--native-fields-min=3",
				"--native-fields-fragment-fanout=8", "--native-fields-max=2"},
		},
	} {
		argv, err := nativeFieldsArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeFieldsRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxFieldsAddresses; i++ {
		many = append(many, fmt.Sprintf("%x", 0x1000+4*i))
	}

	for name, in := range map[string]NativeFieldsInput{
		"fn not hex":               {APK: apk, Fn: []string{"main"}},
		"fn two in one item":       {APK: apk, Fn: []string{"1010,2f04"}},
		"65 fn":                    {APK: apk, Fn: many},
		"empty name":               {APK: apk, Name: []string{"token", ""}},
		"name with a comma":        {APK: apk, Name: []string{"a,b"}},
		"negative min":             {APK: apk, Min: &negative},
		"negative fragment_fanout": {APK: apk, FragmentFanout: &negative},
		"negative max":             {APK: apk, Max: &negative},
		"relative apk":             {APK: "a.apk"},
	} {
		if _, err := s.NativeFields(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}
	if err := checkNativeFields(NativeFieldsInput{Fn: append(many[:maxFieldsAddresses], "0x"+many[0]), Name: []string{"Token", "token"}}); err != nil {
		t.Errorf("64 distinct addresses and a duplicate were refused: %v", err)
	}
}

func TestNativeFieldsShapesTwoELFs(t *testing.T) {
	two := 2
	in := NativeFieldsInput{Name: []string{"token"}, Max: &two}
	env := finishNativeFieldsFixture(t, fieldsReportBody, 50, in)
	heads := env.Result.(map[string]any)["fields"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["functions_total"] != float64(40) || first["functions_matched"] != float64(3) || first["truncated"] != true || first["future_counter"] != float64(7) {
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
	if f0["fn_start"] != "0x1000" || f0["elf"] != "lib/arm64-v8a/libfoo.so" || f0["fields_count"] != float64(2) {
		t.Errorf("functions[0] = %v", f0)
	}
	fields := f0["fields"].([]any)
	if len(fields) != 2 || fields[1].(map[string]any)["via_fragment"] != "0x2200" {
		t.Errorf("functions[0].fields = %v, want them whole", fields)
	}
	if _, present := fields[0].(map[string]any)["via_fragment"]; present {
		t.Error("via_fragment is absent for a direct name and was made up")
	}
	if names := f0["struct_names"].([]any); len(names) != 1 || names[0] != "BabaAccountPb" {
		t.Errorf("struct_names = %v", names)
	}
	callers := f0["callers"].([]any)
	if len(callers) != 2 || callers[1].(map[string]any)["function"] != nil {
		t.Errorf("callers = %v", callers)
	}
	if future, ok := f0["future_field"].(map[string]any); !ok || future["kept"] != true {
		t.Errorf("an unknown function field was dropped or changed: %v", f0)
	}
	if end, present := f1["fn_end"]; !present || end != nil {
		t.Errorf("fn_end is null in the report: %v, %v", end, present)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "fields * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "functions of lib/arm64-v8a/libfoo.so: Drakkar kept 2 of 3 matched, 40 candidate deserializers (exact totals); filters: name=token, max: 2") {
		t.Errorf("no note for the list Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "no function matched in lib/arm64-v8a/libbar.so, of 0 candidate deserializers; filters: name=token, max: 2") {
		t.Errorf("no note for the ELF without result: %q", env.Notes)
	}
	if strings.Contains(notes, "no function matched in lib/arm64-v8a/libfoo.so") {
		t.Errorf("an ELF with functions was called empty: %q", env.Notes)
	}
}

func TestNativeFieldsTailIsCutAtMaxRowsWithExactTotals(t *testing.T) {
	three := 3
	env := finishNativeFieldsFixture(t, fieldsReportBody, 1, NativeFieldsInput{Min: &three})
	functions := env.Tails["functions"]
	if functions.Total != 2 || functions.Returned != 1 || !functions.Truncated {
		t.Fatalf("functions tail = %+v; total counts the functions in the report", functions)
	}
	head := env.Result.(map[string]any)["fields"].([]any)[0].(map[string]any)
	if head["functions_matched"] != float64(3) || head["functions_total"] != float64(40) {
		t.Errorf("max_rows changed Drakkar's totals: %v", head)
	}
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "filters: min=3, max: Drakkar's default") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func TestNativeFieldsReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["fields * : aucun ELF AArch64"]}`
	env := finishNativeFieldsFixture(t, body, 50, NativeFieldsInput{})
	if heads := env.Result.(map[string]any)["fields"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	if functions := env.Tails["functions"]; functions.Total != 0 || len(functions.Items) != 0 {
		t.Errorf("functions tail = %+v", functions)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "fields * : aucun ELF AArch64" {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "no fields entry") || strings.Contains(notes, "no function matched") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func fieldsCall(s *Service, apk, out string) (*Envelope, error) {
	eight := 8
	in := NativeFieldsInput{APK: apk, Name: []string{"token"}, FragmentFanout: &eight, OutDir: out}
	return s.NativeFields(context.Background(), in)
}

func TestNativeFieldsUnknownModeQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-fields' found", 2, fieldsReportBody, fieldsCall)
	if !strings.Contains(notes, "does not know --native-fields: it predates the mode") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeFieldsUnknownOptionQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-fields-fragment-fanout' found", 2, fieldsReportBody, fieldsCall)
	if !strings.Contains(notes, "does not know --native-fields-fragment-fanout: it knows the --native-fields mode but not this option") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeFieldsDrakkarRefusalComesBackInErrors(t *testing.T) {
	notes := refusedBy(t, "Error: archive illisible : invalid Zip archive: Could not find EOCD", 1, fieldsReportBody, fieldsCall)
	if strings.Contains(notes, "does not know") {
		t.Errorf("notes = %q", notes)
	}
}
