package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-words report with two ranges: the first
// has the shape of a vtable header; the second, not vtable_like, has no size
// nor align, a data word with its text, and words without bytes in the file.
const wordsReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "words": [
  {"elf": "lib/arm64-v8a/libfoo.so", "start": "0x2000", "count": 3, "vtable_like": true, "size": "0x18", "align": "0x8",
   "items": [
    {"index": 0, "offset": "0x0", "vaddr": "0x2000", "section": ".data.rel.ro", "raw": "0x0", "value": "0x1040", "relocated": true, "kind": "code",
     "function": {"fn_start": "0x1040", "fn_end": "0x1050", "bound": "eh_frame"}, "at_start": true},
    {"index": 1, "offset": "0x8", "vaddr": "0x2008", "section": ".data.rel.ro", "raw": "0x18", "value": "0x18", "relocated": false, "kind": "int"},
    {"index": 2, "offset": "0x10", "vaddr": "0x2010", "section": ".data.rel.ro", "raw": "0x8", "value": "0x8", "relocated": false, "kind": "int"}
   ]},
  {"elf": "lib/arm64-v8a/libfoo.so", "start": "0x2038", "count": 3, "vtable_like": false,
   "items": [
    {"index": 0, "offset": "0x0", "vaddr": "0x2038", "section": ".data.rel.ro", "raw": "0x0", "value": "0x1800", "relocated": true, "kind": "data",
     "target_section": ".rodata", "text": "hello", "text_truncated": false},
    {"index": 1, "offset": "0x8", "vaddr": "0x2040", "section": ".bss", "relocated": false, "kind": "none"},
    {"index": 2, "offset": "0x10", "vaddr": "0x2050", "section": null, "relocated": false, "kind": "none"}
   ]}
 ],
 "errors": ["words *@0x9000:1 : aucun ELF AArch64 n'a de section qui contient 0x9000"]}
`

func finishNativeWordsFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeWords(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeWordsArgv(t *testing.T) {
	for name, c := range map[string]struct {
		in   NativeWordsInput
		want []string
	}{
		"elf omitted": {
			NativeWordsInput{Ranges: []string{"2000:3"}},
			[]string{"/a.apk", "--native", "--native-words=*@2000:3"},
		},
		"elf named, several ranges": {
			NativeWordsInput{ELF: "lib/arm64-v8a/libfoo.so", Ranges: []string{"36ffbd0:4", "0x1040:1", "36ffbd0:4"}},
			[]string{"/a.apk", "--native", "--native-words=lib/arm64-v8a/libfoo.so@36ffbd0:4,0x1040:1,36ffbd0:4"},
		},
		"star": {
			NativeWordsInput{ELF: "*", Ranges: []string{"2000:512"}},
			[]string{"/a.apk", "--native", "--native-words=*@2000:512"},
		},
	} {
		argv, err := nativeWordsArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeWordsRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	var many []string
	for i := 0; i <= maxWordsRanges; i++ {
		many = append(many, fmt.Sprintf("%x:1", 0x1000+8*i))
	}

	for name, in := range map[string]NativeWordsInput{
		"no ranges":           {APK: apk},
		"empty range":         {APK: apk, Ranges: []string{"2000:1", ""}},
		"no count":            {APK: apk, Ranges: []string{"2000"}},
		"empty count":         {APK: apk, Ranges: []string{"2000:"}},
		"address not hex":     {APK: apk, Ranges: []string{"main:1"}},
		"empty address":       {APK: apk, Ranges: []string{":1"}},
		"count zero":          {APK: apk, Ranges: []string{"2000:0"}},
		"count over 512":      {APK: apk, Ranges: []string{"2000:513"}},
		"count in hex":        {APK: apk, Ranges: []string{"2000:0x10"}},
		"negative count":      {APK: apk, Ranges: []string{"2000:-1"}},
		"two in one item":     {APK: apk, Ranges: []string{"2000:1,2008:1"}},
		"three fields":        {APK: apk, Ranges: []string{"2000:1:2"}},
		"65 ranges":           {APK: apk, Ranges: many},
		"relative apk":        {APK: "a.apk", Ranges: []string{"2000:1"}},
		"uppercase 0X prefix": {APK: apk, Ranges: []string{"0X2000:1"}},
	} {
		if _, err := s.NativeWords(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// Alignment is Drakkar's to refuse; 64 ranges and 512 words pass.
	if err := checkNativeWords(NativeWordsInput{Ranges: append(many[:maxWordsRanges-1], "0x2004:512")}); err != nil {
		t.Errorf("64 ranges, one unaligned, were refused: %v", err)
	}
}

func TestNativeWordsShapesTwoRanges(t *testing.T) {
	env := finishNativeWordsFixture(t, wordsReportBody, 50)
	heads := env.Result.(map[string]any)["ranges"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first, second := heads[0].(map[string]any), heads[1].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["start"] != "0x2000" || first["count"] != float64(3) ||
		first["vtable_like"] != true || first["size"] != "0x18" || first["align"] != "0x8" {
		t.Errorf("head[0] = %v", first)
	}
	if _, present := first["items"]; present {
		t.Error("the words came back in the head")
	}
	if second["vtable_like"] != false {
		t.Errorf("head[1] = %v", second)
	}
	for _, k := range []string{"size", "align"} {
		if _, present := second[k]; present {
			t.Errorf("%s is absent from the report and was made up", k)
		}
	}

	words := env.Tails["words"]
	if words.Total != 6 || words.Truncated {
		t.Fatalf("words tail = %+v", words)
	}
	w0 := words.Items[0].(map[string]any)
	if w0["vaddr"] != "0x2000" || w0["kind"] != "code" || w0["at_start"] != true || w0["elf"] != "lib/arm64-v8a/libfoo.so" || w0["start"] != "0x2000" {
		t.Errorf("words[0] = %v", w0)
	}
	if f := w0["function"].(map[string]any); f["fn_start"] != "0x1040" || f["bound"] != "eh_frame" {
		t.Errorf("words[0].function = %v", f)
	}
	w3 := words.Items[3].(map[string]any)
	if w3["kind"] != "data" || w3["text"] != "hello" || w3["target_section"] != ".rodata" || w3["start"] != "0x2038" {
		t.Errorf("words[3] = %v", w3)
	}
	w5 := words.Items[5].(map[string]any)
	for _, k := range []string{"raw", "value", "function", "at_start", "text"} {
		if _, present := w5[k]; present {
			t.Errorf("%s is absent from the report and was made up: %v", k, w5)
		}
	}
	if section, present := w5["section"]; !present || section != nil {
		t.Errorf("section is null in the report: %v, %v", section, present)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "words *@0x9000:1 : aucun ELF AArch64 n'a de section qui contient 0x9000" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "vtable_like is a hint, not a proof") || !strings.Contains(notes, "1 error(s)") {
		t.Errorf("notes = %q", env.Notes)
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeWordsTailIsCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeWordsFixture(t, wordsReportBody, 4)
	words := env.Tails["words"]
	if words.Total != 6 || words.Returned != 4 || !words.Truncated {
		t.Fatalf("words tail = %+v; total counts the words in the report", words)
	}
	if w := words.Items[3].(map[string]any); w["vaddr"] != "0x2038" || w["start"] != "0x2038" {
		t.Errorf("words keep the report's order: %v", words.Items)
	}
	if heads := env.Result.(map[string]any)["ranges"].([]any); heads[1].(map[string]any)["count"] != float64(3) {
		t.Errorf("max_rows changed Drakkar's count: %v", heads[1])
	}
}

func TestNativeWordsReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["words *@0x9000:1 : aucun ELF AArch64 n'a de section qui contient 0x9000"]}`
	env := finishNativeWordsFixture(t, body, 50)
	if heads := env.Result.(map[string]any)["ranges"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	if words := env.Tails["words"]; words.Total != 0 || len(words.Items) != 0 {
		t.Errorf("words tail = %+v", words)
	}
	if e := env.Tails["errors"]; e.Total != 1 {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "no words entry") || strings.Contains(notes, "vtable_like") {
		t.Errorf("notes = %q", env.Notes)
	}
}

// End to end against a stub drakkar that refuses the mode, as one predating
// --native-words does; a report left by an earlier run must not be read.
func TestNativeWordsUnknownModeQuotesDrakkar(t *testing.T) {
	const clap = "error: unexpected argument '--native-words' found"
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
	if err := os.WriteFile(stale, []byte(wordsReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeWords(context.Background(), NativeWordsInput{APK: apk, Ranges: []string{"2000:3"}, OutDir: out})
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
	if !strings.Contains(notes, "does not know --native-words") || !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestNativeWordsDrakkarRefusalComesBackInErrors(t *testing.T) {
	const refusal = `Error: --native-words "*@2004:1" : élément "2004:1" : 0x2004 n'est pas alignée sur 8`
	stubDrakkar(t, `echo "Error: --native-words \"*@2004:1\" : élément \"2004:1\" : 0x2004 n'est pas alignée sur 8" >&2
exit 1
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := s.NativeWords(context.Background(), NativeWordsInput{APK: apk, Ranges: []string{"2004:1"}, OutDir: filepath.Join(base, "out")})
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
