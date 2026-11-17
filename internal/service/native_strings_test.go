package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	nsInputSHA = "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9"
	nsLibSHA   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	nsSplitSHA = "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a"
)

func nsString(elf, sha, vaddr, value, boundary string) string {
	return `{"elf": "` + elf + `", "elf_sha256": "` + sha + `", "vaddr": "` + vaddr + `", "file_offset": "` + vaddr + `",
	 "section": ".rodata", "length": ` + strconv.Itoa(len(value)) + `, "encoding": "ascii", "value": "` + value + `", "boundary": "` + boundary + `"}`
}

// format_arrays of Drakkar 0.6.1: two in the base's ELF, one in the split's.
const (
	nsArraysLib = `,
   "format_arrays": [
    {"array_vaddr": "0x4000", "section": ".data.rel.ro", "len": 2, "propagated": true, "pieces": ["SECRET_ONE", "!"]},
    {"array_vaddr": "0x4020", "section": ".data.rel.ro", "len": 1, "propagated": true, "pieces": ["SECRET_TWO"]}]`
	nsArraysSplit = `,
   "format_arrays": [
    {"array_vaddr": "0x1800", "section": ".data.rel.ro", "len": 3, "propagated": true, "pieces": ["a", "b", "c"]}]`
)

// The shape of a --native-strings report: one ELF of the base with three
// strings and --crates, one ELF of an ABI split with two.
var nsReportBody = `{"sha256": "` + nsInputSHA + `", "input": "/corpus/a.xapk!base.apk",
 "options": {"patterns": [], "min_length": 4, "elf": null, "xrefs": false, "crates": true},
 "limits": {"min_length": 4, "max_string_len": 1048576, "code_window": 8, "sections_not_scanned": [".eh_frame"]},
 "elfs": [
  {"elf": "lib/arm64-v8a/libfoo.so", "split": null, "elf_sha256": "` + nsLibSHA + `", "machine": "aarch64",
   "summary": {"areas": "sections", "strings_found": 3, "strings_emitted": 3,
               "by_boundary": {"nul": 1, "rust_fatptr": 1, "rust_code": 0, "heuristic": 1},
               "by_encoding": {"ascii": 3, "utf8": 0, "utf16le": 0},
               "fatptr_pairs": 1, "rust_code_dropped_prefixes": 0, "blocks_split": 0, "pieces_from_split": 0,
               "code_scan": "aarch64",
               "functions": {"symtab": 12, "eh_frame": 3, "eh_frame_present": true, "eh_frame_unread": 0},
               "xrefs": null, "crypto_constants": 1, "anomalies": []},
   "strings": [
` + nsString("lib/arm64-v8a/libfoo.so", nsLibSHA, "0x2000", "https://c2.example/a", "nul") + `,
` + nsString("lib/arm64-v8a/libfoo.so", nsLibSHA, "0x2040", "SECRET_ONE", "rust_fatptr") + `,
` + nsString("lib/arm64-v8a/libfoo.so", nsLibSHA, "0x2080", "SECRET_TWO", "heuristic") + `
   ],
   "crates": [{"crate": "ring", "version": "0.17.8", "registry": "index.crates.io-6f17d22bba15001f", "occurrences": 2}],
   "c_libraries": [{"library": "OpenSSL", "banner": "OpenSSL 3.0.13", "vaddr": "0x2100"}],
   "crypto_constants": [{"name": "aes_sbox", "byte_order": null, "length": 256, "vaddr": "0x3000", "file_offset": "0x3000", "section": ".rodata"}]` + nsArraysLib + `},
  {"elf": "lib/arm64-v8a/libbar.so", "split": "config.arm64_v8a", "elf_sha256": "` + nsSplitSHA + `", "machine": "aarch64",
   "summary": {"areas": "sections", "strings_found": 2, "strings_emitted": 2,
               "by_boundary": {"nul": 2, "rust_fatptr": 0, "rust_code": 0, "heuristic": 0},
               "by_encoding": {"ascii": 2, "utf8": 0, "utf16le": 0},
               "fatptr_pairs": 0, "rust_code_dropped_prefixes": 0, "blocks_split": 0, "pieces_from_split": 0,
               "code_scan": "aarch64",
               "functions": {"symtab": 0, "eh_frame": 0, "eh_frame_present": false, "eh_frame_unread": 0},
               "xrefs": null, "crypto_constants": 0, "anomalies": []},
   "strings": [
` + nsString("config.arm64_v8a!lib/arm64-v8a/libbar.so", nsSplitSHA, "0x1000", "SECRET_THREE", "nul") + `,
` + nsString("config.arm64_v8a!lib/arm64-v8a/libbar.so", nsSplitSHA, "0x1010", "SECRET_FOUR", "nul") + `
   ],
   "crates": [], "c_libraries": [], "crypto_constants": []` + nsArraysSplit + `}
 ],
 "elfs_not_selected": [], "errors": []}
`

func finishNativeStringsFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeStrings(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func writeNativeStringsInput(t *testing.T, dir string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "a.apk")
	content := []byte("not really an apk")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}

func TestNativeStringsArgv(t *testing.T) {
	two := 2
	argv, err := nativeStringsArgs("/corpus/A sample.apk", "/out/x.native_strings.json", NativeStringsInput{
		Patterns:  []string{"http", "-key"},
		MinLength: &two,
		ELF:       "config.arm64_v8a!lib/arm64-v8a/libfoo.so",
		Xrefs:     true,
		Crates:    true,
	}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/corpus/A sample.apk", "--native-strings=http", "--native-strings=-key",
		"--min-length=2", "--elf=config.arm64_v8a!lib/arm64-v8a/libfoo.so", "--xrefs", "--crates",
		"--format=json", "--json-out=/out/x.native_strings.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}

	// No pattern: a bare --native-strings, and no option Drakkar has a default for.
	argv, err = nativeStringsArgs("/a.so", "/out/x.native_strings.json", NativeStringsInput{}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"/a.so", "--native-strings", "--format=json", "--json-out=/out/x.native_strings.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestNativeStringsRefusesBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	input, _ := writeNativeStringsInput(t, base)
	out := filepath.Join(base, "out")
	zero, negative := 0, -3

	for name, in := range map[string]NativeStringsInput{
		"relative out_dir": {Input: input, OutDir: "relative/out"},
		"omitted out_dir":  {Input: input},
		"min_length 0":     {Input: input, OutDir: out, MinLength: &zero},
		"negative length":  {Input: input, OutDir: out, MinLength: &negative},
		"relative input":   {Input: "a.apk", OutDir: out},
		"empty pattern":    {Input: input, OutDir: out, Patterns: []string{"http", ""}},
	} {
		if _, err := s.NativeStrings(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}
}

func TestNativeStringsRefusalsSayWhy(t *testing.T) {
	zero := 0
	if err := checkNativeStrings(NativeStringsInput{MinLength: &zero}); err == nil || !strings.Contains(err.Error(), "at least 1") {
		t.Errorf("min_length 0 gave %v", err)
	}
	s, _ := testService(t)
	_, err := s.NativeStrings(context.Background(), NativeStringsInput{Input: "/abs/a.apk", OutDir: "rel"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("a relative out_dir gave %v", err)
	}
}

func TestNativeStringsPreviewIsCutAtMaxRowsAndCounted(t *testing.T) {
	env := finishNativeStringsFixture(t, nsReportBody, 4)
	tail := env.Tails["strings"]
	if tail.Total != 5 || tail.Returned != 4 || !tail.Truncated {
		t.Fatalf("strings tail = total %d, returned %d, truncated %v; want 5, 4, true", tail.Total, tail.Returned, tail.Truncated)
	}
	// The preview crosses into the second ELF, in report order.
	last := tail.Items[3].(map[string]any)
	if last["value"] != "SECRET_THREE" || last["elf_sha256"] != nsSplitSHA {
		t.Errorf("strings[3] = %v", last)
	}
	if !strings.Contains(strings.Join(env.Notes, "\n"), "strings: 4 of 5 shown") {
		t.Errorf("no note declares the cut: %q", env.Notes)
	}

	whole := finishNativeStringsFixture(t, nsReportBody, 50)
	if w := whole.Tails["strings"]; w.Total != 5 || w.Returned != 5 || w.Truncated {
		t.Errorf("strings tail = %+v, want all five", w)
	}
	for _, n := range whole.Notes {
		if strings.HasPrefix(n, "strings:") {
			t.Errorf("a whole preview was declared cut: %s", n)
		}
	}
}

func TestNativeStringsFormatArraysAreCutAtMaxRowsApartFromStrings(t *testing.T) {
	env := finishNativeStringsFixture(t, nsReportBody, 2)
	arrays := env.Tails["format_arrays"]
	if arrays.Total != 3 || arrays.Returned != 2 || !arrays.Truncated {
		t.Fatalf("format_arrays tail = total %d, returned %d, truncated %v; want 3, 2, true", arrays.Total, arrays.Returned, arrays.Truncated)
	}
	if a := arrays.Items[1].(map[string]any); a["array_vaddr"] != "0x4020" {
		t.Errorf("format_arrays[1] = %v", a)
	}
	if s := env.Tails["strings"]; s.Total != 5 || s.Returned != 2 || !s.Truncated {
		t.Errorf("strings tail = %+v; max_rows applies to it on its own", s)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "format_arrays: 2 of 3 shown") {
		t.Errorf("no note declares the cut: %q", env.Notes)
	}
	if strings.Contains(notes, "0.6.1") {
		t.Errorf("a report with format_arrays was taken for an older Drakkar's: %q", env.Notes)
	}

	// Four strings shown do not eat into the arrays: all three come back.
	apart := finishNativeStringsFixture(t, nsReportBody, 4)
	if a := apart.Tails["format_arrays"]; a.Total != 3 || a.Returned != 3 || a.Truncated {
		t.Errorf("format_arrays tail = %+v, want all three", a)
	}
	if s := apart.Tails["strings"]; s.Returned != 4 || !s.Truncated {
		t.Errorf("strings tail = %+v", s)
	}
	for _, n := range apart.Notes {
		if strings.HasPrefix(n, "format_arrays:") {
			t.Errorf("a whole preview was declared cut: %s", n)
		}
	}
}

func TestNativeStringsWithoutFormatArraysIsDrakkar060(t *testing.T) {
	body := strings.Replace(nsReportBody, nsArraysLib, "", 1)
	body = strings.Replace(body, nsArraysSplit, "", 1)
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeStrings(env, writeReport(t, body), 50); err != nil {
		t.Fatalf("a Drakkar 0.6.0 report was refused: %v", err)
	}
	arrays := env.Tails["format_arrays"]
	if arrays.Total != 0 || arrays.Returned != 0 || arrays.Truncated || arrays.Items == nil || len(arrays.Items) != 0 {
		t.Errorf("format_arrays tail = %+v, want empty", arrays)
	}
	if !strings.Contains(strings.Join(env.Notes, "\n"), "format_arrays requires Drakkar 0.6.1") {
		t.Errorf("no note names Drakkar 0.6.1: %q", env.Notes)
	}
	if st := env.Tails["strings"]; st.Total != 5 {
		t.Errorf("strings tail = %+v", st)
	}
}

func TestNativeStringsHeadAndELFRows(t *testing.T) {
	env := finishNativeStringsFixture(t, nsReportBody, 1)
	head := env.Result.(map[string]any)
	if head["sha256"] != nsInputSHA || head["input"] != "/corpus/a.xapk!base.apk" {
		t.Errorf("head = %v", head)
	}
	if _, ok := head["limits"].(map[string]any); !ok {
		t.Errorf("limits = %T", head["limits"])
	}
	if _, present := head["elfs"]; present {
		t.Error("elfs stayed in the head")
	}

	elfs := env.Tails["elfs"]
	if elfs.Total != 2 || elfs.Returned != 2 || elfs.Truncated {
		t.Fatalf("elfs tail = %+v; max_rows must not cut it", elfs)
	}
	lib := elfs.Items[0].(map[string]any)
	if lib["elf_sha256"] != nsLibSHA || lib["machine"] != "aarch64" || lib["split"] != nil {
		t.Errorf("elfs[0] = %v", lib)
	}
	if _, present := lib["strings"]; present {
		t.Error("strings reached an elfs row; they are a tail of their own")
	}
	if _, present := lib["format_arrays"]; present {
		t.Error("format_arrays reached an elfs row; they are a tail of their own")
	}
	summary := lib["summary"].(map[string]any)
	if summary["strings_found"] != float64(3) || summary["by_boundary"].(map[string]any)["rust_fatptr"] != float64(1) {
		t.Errorf("summary = %v", summary)
	}
	if c := lib["crates"].([]any); len(c) != 1 || c[0].(map[string]any)["crate"] != "ring" {
		t.Errorf("crates = %v", lib["crates"])
	}
	if c := lib["c_libraries"].([]any); len(c) != 1 {
		t.Errorf("c_libraries = %v", lib["c_libraries"])
	}
	if c := lib["crypto_constants"].([]any); len(c) != 1 || c[0].(map[string]any)["name"] != "aes_sbox" {
		t.Errorf("crypto_constants = %v", lib["crypto_constants"])
	}
	if split := elfs.Items[1].(map[string]any); split["split"] != "config.arm64_v8a" {
		t.Errorf("elfs[1].split = %v", split["split"])
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeStringsWithoutCratesHasNoCratesKey(t *testing.T) {
	body := strings.Replace(nsReportBody, `"crates": [{"crate": "ring"`, `"crates_absent": [{"crate": "ring"`, 1)
	env := finishNativeStringsFixture(t, body, 50)
	if _, present := env.Tails["elfs"].Items[0].(map[string]any)["crates"]; present {
		t.Error("a crates key appeared although the report has none")
	}
}

func TestNativeStringsUnmatchedELFKeepsElfsNotSelected(t *testing.T) {
	const body = `{"sha256": "` + nsInputSHA + `", "input": "/a.apk", "options": {}, "limits": {},
 "elfs": [
 ],
 "elfs_not_selected": ["lib/arm64-v8a/libfoo.so", "lib/armeabi-v7a/libfoo.so"],
 "errors": ["--elf libnope.so : aucun ELF de ce chemin"]}`
	env := finishNativeStringsFixture(t, body, 50)
	if ns := env.Tails["elfs_not_selected"]; ns.Total != 2 || ns.Items[0] != "lib/arm64-v8a/libfoo.so" {
		t.Errorf("elfs_not_selected = %+v", ns)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "--elf libnope.so : aucun ELF de ce chemin" {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "elfs_not_selected lists") || !strings.Contains(notes, "1 error(s)") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func TestNativeStringsCutReportAfterAnIncompleteRunIsANote(t *testing.T) {
	cut := nsReportBody[:len(nsReportBody)/2]
	s, _ := testService(t)
	env := &Envelope{}
	env.Drakkar.ExitCode = -1
	env.Drakkar.TimedOut = true
	if err := s.finishNativeStrings(env, writeReport(t, cut), 50); err != nil {
		t.Fatal(err)
	}
	if env.Result != nil || !strings.Contains(strings.Join(env.Notes, "\n"), "could not be parsed") {
		t.Errorf("result = %v, notes = %q", env.Result, env.Notes)
	}
}

// End to end against a stub drakkar that writes the report where --json-out
// says and warns on stderr.
func TestNativeStringsWarningLineBecomesANote(t *testing.T) {
	const warning = "[AVERT] lib/arm64-v8a/libbar.so — ni symboles ni .eh_frame : xrefs sans bornes de fonction, fn_start toujours null"
	stubDrakkar(t, `for a in "$@"; do case "$a" in --json-out=*) out="${a#--json-out=}";; esac; done
cat > "$out" <<'EOF'
`+nsReportBody+`EOF
echo '[OK]    lib/arm64-v8a/libbar.so — 2 chaînes rendues sur 2 extraites' >&2
echo '`+warning+`' >&2
echo "JSON écrit dans $out" >&2
`)
	s, base := testService(t)
	input, sum := writeNativeStringsInput(t, base)
	out := filepath.Join(base, "out")

	env, err := s.NativeStrings(context.Background(), NativeStringsInput{Input: input, OutDir: out, Patterns: []string{"secret"}, Xrefs: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(out, sum+".native_strings.json"); env.ReportPath != want {
		t.Errorf("report_path = %q, want %q", env.ReportPath, want)
	}
	argv := env.Drakkar.Argv[1:]
	if len(argv) < 2 || argv[0] != input || argv[1] != "--native-strings=secret" {
		t.Errorf("argv = %q: the input first, then the patterns right after --native-strings", argv)
	}
	if env.Stderr.Warned != 1 || env.Stderr.OK != 1 {
		t.Errorf("stderr counts = ok %d, warned %d", env.Stderr.OK, env.Stderr.Warned)
	}
	found := false
	for _, n := range env.Notes {
		if n == warning {
			found = true
		}
	}
	if !found {
		t.Errorf("the [AVERT] line is not a note, verbatim: %q", env.Notes)
	}
	if !env.Drakkar.Complete || env.Tails["strings"].Total != 5 {
		t.Errorf("complete = %v, strings tail = %+v", env.Drakkar.Complete, env.Tails["strings"])
	}
}

func TestNativeStringsOlderDrakkarsRefusalComesBackAsIs(t *testing.T) {
	const clap = "error: unexpected argument '--native-strings' found"
	stubDrakkar(t, `echo "`+clap+`" >&2
echo >&2
echo 'Usage: drakkar [OPTIONS] [APK]' >&2
exit 2
`)
	s, base := testService(t)
	input, sum := writeNativeStringsInput(t, base)
	out := filepath.Join(base, "out")
	// A report left by an earlier run must not be read as this one's.
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(out, sum+".native_strings.json")
	if err := os.WriteFile(stale, []byte(nsReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeStrings(context.Background(), NativeStringsInput{Input: input, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if env.Drakkar.ExitCode != 2 || env.Drakkar.Complete {
		t.Errorf("exit = %d, complete = %v", env.Drakkar.ExitCode, env.Drakkar.Complete)
	}
	if !strings.Contains(env.Stderr.Text, clap) {
		t.Errorf("stderr.text = %q", env.Stderr.Text)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) || !strings.Contains(notes, "0.6.0") {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil || len(env.Tails) != 0 {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestLegendNativeStrings(t *testing.T) {
	stubDrakkar(t, "echo 'NATIVE STRINGS LEGEND'\n")
	s, _ := testService(t)
	env, err := s.Legend(context.Background(), LegendInput{Topic: "native_strings"})
	if err != nil {
		t.Fatal(err)
	}
	argv := env.Drakkar.Argv[1:]
	if strings.Join(argv, " ") != "--legend --native-strings" {
		t.Errorf("argv = %q", argv)
	}
	if text := env.Result.(map[string]any)["text"]; !strings.Contains(text.(string), "NATIVE STRINGS LEGEND") {
		t.Errorf("text = %v", text)
	}
}
