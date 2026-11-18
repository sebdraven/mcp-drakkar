package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-find report over two ELFs: the first had
// its matches cut by Drakkar and carries an ELF-level counter and a function
// field this server does not know of; the second has no match.
const findReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "find": [
  {"elf": "lib/arm64-v8a/libfoo.so", "matches_total": 3, "functions_total": 2, "truncated": true, "future_counter": 7,
   "functions": [
    {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "symtab", "counts": [{"offset": "0x16a", "loads": 1, "stores": 0, "addrs": 1}], "future_field": {"kept": true}},
    {"fn_start": "0x1040", "fn_end": null, "bound": "eh_frame", "counts": [{"offset": "-0x8", "loads": 1, "stores": 0, "addrs": 0}]}
   ],
   "matches": [
    {"insn_addr": "0x1000", "mnemonic": "ldrb", "operands": "w1, [x0, #0x16a]", "access": "load", "size": 1, "base": "x0", "offset": "0x16a", "function": {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "symtab"}},
    {"insn_addr": "0x2000", "mnemonic": "add", "operands": "x11, x12, #0x16a", "access": "addr", "base": "x12", "offset": "0x16a", "function": null}
   ]},
  {"elf": "lib/arm64-v8a/libbar.so", "matches_total": 0, "functions_total": 0, "truncated": false, "functions": [], "matches": []}
 ],
 "errors": ["find * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement"]}
`

func finishNativeFindFixture(t *testing.T, body string, maxRows int, in NativeFindInput) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeFind(env, writeReport(t, body), maxRows, in); err != nil {
		t.Fatal(err)
	}
	return env
}

// refusedBy runs call against a stub drakkar that writes line, free of double
// quotes, to stderr and exits with code, with the report of an earlier run
// left in out_dir. It
// checks that the line comes back verbatim and that the earlier report was
// neither read nor kept, and returns the notes.
func refusedBy(t *testing.T, line string, code int, stale string, call func(s *Service, apk, out string) (*Envelope, error)) string {
	t.Helper()
	stubDrakkar(t, fmt.Sprintf("echo \"%s\" >&2\necho >&2\necho 'Usage: drakkar [OPTIONS] [APK]' >&2\nexit %d\n", line, code))
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	earlier := filepath.Join(out, "report.json")
	if err := os.WriteFile(earlier, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := call(s, apk, out)
	if err != nil {
		t.Fatal(err)
	}
	if env.Drakkar.ExitCode != code || env.Drakkar.Complete {
		t.Errorf("exit = %d, complete = %v", env.Drakkar.ExitCode, env.Drakkar.Complete)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != line {
		t.Errorf("errors = %+v, want Drakkar's message as is", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "Drakkar's message, verbatim: "+line) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(earlier); err == nil {
		t.Error("the stale report is still there")
	}
	return notes
}

func TestNativeFindArgv(t *testing.T) {
	two := 2
	for name, c := range map[string]struct {
		in   NativeFindInput
		want []string
	}{
		"offsets only, elf omitted": {
			NativeFindInput{Offsets: []string{"0x16a"}},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=0x16a"},
		},
		"negative offset": {
			NativeFindInput{Offsets: []string{"-0x8", "1bc"}},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=-0x8,1bc"},
		},
		"elf named": {
			NativeFindInput{ELF: "lib/arm64-v8a/libfoo.so", Offsets: []string{"16a"}},
			[]string{"/a.apk", "--native", "--native-find=lib/arm64-v8a/libfoo.so", "--native-find-off=16a"},
		},
		"access": {
			NativeFindInput{Offsets: []string{"16a"}, Access: []string{"load", "store"}},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=16a", "--native-find-access=load,store"},
		},
		"size": {
			NativeFindInput{Offsets: []string{"16a"}, Size: []int{1, 8}},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=16a", "--native-find-size=1,8"},
		},
		"base": {
			NativeFindInput{Offsets: []string{"16a"}, Base: "any"},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=16a", "--native-find-base=any"},
		},
		"in": {
			NativeFindInput{Offsets: []string{"16a"}, In: []string{"1000", "0x2000"}},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=16a", "--native-find-in=1000,0x2000"},
		},
		"max": {
			NativeFindInput{Offsets: []string{"16a"}, Max: &two},
			[]string{"/a.apk", "--native", "--native-find=*", "--native-find-off=16a", "--native-find-max=2"},
		},
		"everything": {
			NativeFindInput{ELF: "lib/arm64-v8a/libfoo.so", Offsets: []string{"0x16a", "-0x8"}, Access: []string{"addr"}, Size: []int{4}, Base: "nosp", In: []string{"1000"}, Max: &two},
			[]string{"/a.apk", "--native", "--native-find=lib/arm64-v8a/libfoo.so", "--native-find-off=0x16a,-0x8",
				"--native-find-access=addr", "--native-find-size=4", "--native-find-base=nosp",
				"--native-find-in=1000", "--native-find-max=2"},
		},
	} {
		argv, err := nativeFindArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeFindRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many, manyIn []string
	for i := 0; i <= maxFindOffsets; i++ {
		many = append(many, fmt.Sprintf("%x", 8*i))
	}
	for i := 0; i <= maxFindAddresses; i++ {
		manyIn = append(manyIn, fmt.Sprintf("%x", 0x1000+4*i))
	}
	off := []string{"16a"}

	for name, in := range map[string]NativeFindInput{
		"no offsets":        {APK: apk},
		"offset not hex":    {APK: apk, Offsets: []string{"zz"}},
		"offset two signs":  {APK: apk, Offsets: []string{"--8"}},
		"offset sign after": {APK: apk, Offsets: []string{"0x-8"}},
		"two in one offset": {APK: apk, Offsets: []string{"8,10"}},
		"17 offsets":        {APK: apk, Offsets: many},
		"bad access":        {APK: apk, Offsets: off, Access: []string{"read"}},
		"bad size":          {APK: apk, Offsets: off, Size: []int{3}},
		"bad base":          {APK: apk, Offsets: off, Base: "stack"},
		"in not hex":        {APK: apk, Offsets: off, In: []string{"main"}},
		"65 in":             {APK: apk, Offsets: off, In: manyIn},
		"negative max":      {APK: apk, Offsets: off, Max: &negative},
		"relative apk":      {APK: "a.apk", Offsets: off},
	} {
		if _, err := s.NativeFind(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// Drakkar drops duplicates before counting: -8 and -0x8 are one offset.
	if err := checkNativeFind(NativeFindInput{Offsets: append(many[1:maxFindOffsets], "-8", "-0x8")}); err != nil {
		t.Errorf("16 distinct offsets were refused: %v", err)
	}
}

func TestNativeFindShapesTwoELFs(t *testing.T) {
	two := 2
	in := NativeFindInput{Offsets: []string{"16a", "-8"}, Access: []string{"load", "addr"}, Max: &two}
	env := finishNativeFindFixture(t, findReportBody, 50, in)
	heads := env.Result.(map[string]any)["find"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first := heads[0].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["matches_total"] != float64(3) || first["functions_total"] != float64(2) || first["truncated"] != true || first["future_counter"] != float64(7) {
		t.Errorf("head[0] = %v", first)
	}
	for _, k := range []string{"functions", "matches"} {
		if _, present := first[k]; present {
			t.Errorf("%s came back in the head", k)
		}
	}

	functions := env.Tails["functions"]
	if functions.Total != 2 || functions.Truncated {
		t.Fatalf("functions tail = %+v", functions)
	}
	f0 := functions.Items[0].(map[string]any)
	if f0["fn_start"] != "0x1000" || f0["elf"] != "lib/arm64-v8a/libfoo.so" || len(f0["counts"].([]any)) != 1 {
		t.Errorf("functions[0] = %v", f0)
	}
	if future, ok := f0["future_field"].(map[string]any); !ok || future["kept"] != true {
		t.Errorf("an unknown function field was dropped or changed: %v", f0)
	}
	matches := env.Tails["matches"]
	if matches.Total != 2 || matches.Truncated {
		t.Fatalf("matches tail = %+v", matches)
	}
	m1 := matches.Items[1].(map[string]any)
	if _, present := m1["size"]; present {
		t.Error("size is absent for addr and was made up")
	}
	if fn, present := m1["function"]; !present || fn != nil {
		t.Errorf("function is null in the report: %v, %v", fn, present)
	}
	if m1["elf"] != "lib/arm64-v8a/libfoo.so" {
		t.Errorf("matches[1] = %v", m1)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "find * (lib/x86_64/libfoo.so) : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "matches of lib/arm64-v8a/libfoo.so: Drakkar kept 2 of 3, in 2 functions (exact totals, functions whole); filters: offsets=16a,-8 access=load,addr, max: 2") {
		t.Errorf("no note for the matches Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "no match in lib/arm64-v8a/libbar.so; filters: offsets=16a,-8 access=load,addr, max: 2: the stack pointer is left out as a base by default") {
		t.Errorf("no note for the ELF without match: %q", env.Notes)
	}
	if strings.Contains(notes, "no match in lib/arm64-v8a/libfoo.so") {
		t.Errorf("an ELF with matches was called empty: %q", env.Notes)
	}
}

func TestNativeFindTailsAreCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeFindFixture(t, findReportBody, 1, NativeFindInput{Offsets: []string{"16a"}})
	for _, name := range []string{"functions", "matches"} {
		tail := env.Tails[name]
		if tail.Total != 2 || tail.Returned != 1 || !tail.Truncated {
			t.Errorf("%s tail = %+v; total counts the report's items", name, tail)
		}
	}
	head := env.Result.(map[string]any)["find"].([]any)[0].(map[string]any)
	if head["matches_total"] != float64(3) || head["functions_total"] != float64(2) {
		t.Errorf("max_rows changed Drakkar's totals: %v", head)
	}
}

func TestNativeFindReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["find * : aucun ELF AArch64"]}`
	env := finishNativeFindFixture(t, body, 50, NativeFindInput{Offsets: []string{"16a"}})
	if heads := env.Result.(map[string]any)["find"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	for _, name := range []string{"functions", "matches"} {
		if tail := env.Tails[name]; tail.Total != 0 || len(tail.Items) != 0 {
			t.Errorf("%s tail = %+v", name, tail)
		}
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "find * : aucun ELF AArch64" {
		t.Errorf("errors = %+v", e)
	}
	if notes := strings.Join(env.Notes, "\n"); !strings.Contains(notes, "no find entry") || strings.Contains(notes, "no match in") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func findCall(s *Service, apk, out string) (*Envelope, error) {
	return s.NativeFind(context.Background(), NativeFindInput{APK: apk, Offsets: []string{"16a"}, Base: "any", OutDir: out})
}

func TestNativeFindUnknownModeQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-find' found", 2, findReportBody, findCall)
	if !strings.Contains(notes, "does not know --native-find: it predates the mode") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeFindUnknownOptionQuotesDrakkar(t *testing.T) {
	notes := refusedBy(t, "error: unexpected argument '--native-find-base' found", 2, findReportBody, findCall)
	if !strings.Contains(notes, "does not know --native-find-base: it knows the --native-find mode but not this option") {
		t.Errorf("notes = %q", notes)
	}
}

func TestNativeFindDrakkarRefusalComesBackInErrors(t *testing.T) {
	notes := refusedBy(t, "Error: archive illisible : invalid Zip archive: Could not find EOCD", 1, findReportBody, findCall)
	if strings.Contains(notes, "does not know") {
		t.Errorf("notes = %q", notes)
	}
}
