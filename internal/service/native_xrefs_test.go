package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a --native --native-xrefs report with two targets: the first,
// in code, has its code_refs cut by Drakkar; the second, in data, has no
// function, no adrp_addr and no reference at all.
const xrefsReportBody = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "xrefs": [
  {"elf": "lib/arm64-v8a/libfoo.so", "target": "0x1a00", "section": ".text",
   "function": {"fn_start": "0x1a00", "fn_end": "0x1a80", "bound": "eh_frame"},
   "code_refs": {"total": 2500, "truncated": true, "items": [
    {"insn_addr": "0x1000", "mnemonic": "bl", "kind": "call", "function": {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "eh_frame"}},
    {"insn_addr": "0x1004", "mnemonic": "b", "kind": "jump", "function": {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "eh_frame"}},
    {"insn_addr": "0x1008", "mnemonic": "b.eq", "kind": "cond_jump", "function": {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "eh_frame"}}
   ]},
   "addr_refs": {"total": 2, "truncated": false, "items": [
    {"insn_addr": "0x1014", "adrp_addr": "0x1010", "kind": "address", "function": {"fn_start": "0x1000", "fn_end": "0x1040", "bound": "eh_frame"}},
    {"insn_addr": "0x1020", "kind": "address", "function": {"fn_start": "0x1000", "fn_end": null, "bound": "none"}}
   ]},
   "data_refs": {"total": 1, "truncated": false, "items": [
    {"vaddr": "0x2028", "section": ".data.rel.ro", "relocated": true}
   ]}},
  {"elf": "lib/arm64-v8a/libfoo.so", "target": "0x5010", "section": null,
   "code_refs": {"total": 0, "truncated": false, "items": []},
   "addr_refs": {"total": 0, "truncated": false, "items": []},
   "data_refs": {"total": 0, "truncated": false, "items": []}}
 ],
 "errors": ["xrefs lib/x86_64/libfoo.so@0x1a00 : machine x86_64 : AArch64 seulement"]}
`

func finishNativeXrefsFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNativeXrefs(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeXrefsArgv(t *testing.T) {
	five, zero := 5, 0
	for name, c := range map[string]struct {
		in   NativeXrefsInput
		want []string
	}{
		"elf omitted": {
			NativeXrefsInput{Addresses: []string{"1a00"}},
			[]string{"/a.apk", "--native", "--native-xrefs=*@1a00"},
		},
		"elf named, several addresses": {
			NativeXrefsInput{ELF: "lib/arm64-v8a/libfoo.so", Addresses: []string{"1a00", "0x5010", "36ffbd0"}},
			[]string{"/a.apk", "--native", "--native-xrefs=lib/arm64-v8a/libfoo.so@1a00,0x5010,36ffbd0"},
		},
		"star and max": {
			NativeXrefsInput{ELF: "*", Addresses: []string{"1a00", "1a40"}, Max: &five},
			[]string{"/a.apk", "--native", "--native-xrefs=*@1a00,1a40", "--native-xrefs-max=5"},
		},
		"max zero": {
			NativeXrefsInput{Addresses: []string{"1a00"}, Max: &zero},
			[]string{"/a.apk", "--native", "--native-xrefs=*@1a00", "--native-xrefs-max=0"},
		},
	} {
		argv, err := nativeXrefsArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := append(c.want, "--format=json", "--json-out=/out/report.json")
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: argv = %q, want %q", name, argv, want)
		}
	}
}

func TestNativeXrefsRefusesBadFormsBeforeDrakkarRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	stubDrakkar(t, "touch '"+marker+"'\nexit 1\n")
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	negative := -1
	var many []string
	for i := 0; i <= maxXrefsAddresses; i++ {
		many = append(many, fmt.Sprintf("%x", 0x1000+4*i))
	}

	for name, in := range map[string]NativeXrefsInput{
		"no addresses":        {APK: apk},
		"empty address":       {APK: apk, Addresses: []string{"1a00", ""}},
		"address not hex":     {APK: apk, Addresses: []string{"main"}},
		"two in one item":     {APK: apk, Addresses: []string{"1a00,1a40"}},
		"range":               {APK: apk, Addresses: []string{"1a00-1a80"}},
		"65 addresses":        {APK: apk, Addresses: many},
		"negative max":        {APK: apk, Addresses: []string{"1a00"}, Max: &negative},
		"relative apk":        {APK: "a.apk", Addresses: []string{"1a00"}},
		"uppercase 0X prefix": {APK: apk, Addresses: []string{"0X1a00"}},
		"address over 64 bit": {APK: apk, Addresses: []string{"1" + strings.Repeat("0", 16)}},
	} {
		if _, err := s.NativeXrefs(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("drakkar ran although every call should have been refused first")
	}

	// Drakkar drops duplicates before counting: 64 distinct addresses pass.
	if err := checkNativeXrefs(NativeXrefsInput{Addresses: append(many[:maxXrefsAddresses], "0x"+many[0])}); err != nil {
		t.Errorf("64 distinct addresses and a duplicate were refused: %v", err)
	}
}

func TestNativeXrefsShapesTwoTargets(t *testing.T) {
	env := finishNativeXrefsFixture(t, xrefsReportBody, 50)
	heads := env.Result.(map[string]any)["xrefs"].([]any)
	if len(heads) != 2 {
		t.Fatalf("head = %v", env.Result)
	}
	first, second := heads[0].(map[string]any), heads[1].(map[string]any)
	if first["elf"] != "lib/arm64-v8a/libfoo.so" || first["target"] != "0x1a00" || first["section"] != ".text" {
		t.Errorf("head[0] = %v", first)
	}
	if f := first["function"].(map[string]any); f["fn_start"] != "0x1a00" || f["bound"] != "eh_frame" {
		t.Errorf("head[0].function = %v", f)
	}
	code := first["code_refs"].(map[string]any)
	if code["total"] != float64(2500) || code["truncated"] != true || len(code) != 2 {
		t.Errorf("head[0].code_refs = %v, want the totals without items", code)
	}
	if _, present := second["function"]; present {
		t.Error("function is absent from the report and was made up")
	}
	if section, present := second["section"]; !present || section != nil {
		t.Errorf("section is null in the report: %v, %v", section, present)
	}

	addr := env.Tails["addr_refs"]
	if addr.Total != 2 || addr.Truncated {
		t.Fatalf("addr_refs tail = %+v", addr)
	}
	a0, a1 := addr.Items[0].(map[string]any), addr.Items[1].(map[string]any)
	if a0["insn_addr"] != "0x1014" || a0["adrp_addr"] != "0x1010" || a0["elf"] != "lib/arm64-v8a/libfoo.so" || a0["target"] != "0x1a00" {
		t.Errorf("addr_refs[0] = %v", a0)
	}
	if _, present := a1["adrp_addr"]; present {
		t.Error("adrp_addr is absent from the report and was made up")
	}
	if d := env.Tails["data_refs"]; d.Total != 1 || d.Items[0].(map[string]any)["relocated"] != true {
		t.Errorf("data_refs tail = %+v", d)
	}
	if e := env.Tails["errors"]; e.Total != 1 || e.Items[0] != "xrefs lib/x86_64/libfoo.so@0x1a00 : machine x86_64 : AArch64 seulement" {
		t.Errorf("errors = %+v", e)
	}

	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "code_refs for 0x1a00 in lib/arm64-v8a/libfoo.so: Drakkar kept 3 of 2500") || !strings.Contains(notes, "max raises") {
		t.Errorf("no note for the list Drakkar cut: %q", env.Notes)
	}
	if !strings.Contains(notes, "no static reference to 0x5010 in lib/arm64-v8a/libfoo.so: not a proof of absence") {
		t.Errorf("no note for the target without reference: %q", env.Notes)
	}
	if strings.Contains(notes, "no static reference to 0x1a00") {
		t.Errorf("a target with references was called empty: %q", env.Notes)
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeXrefsTailsAreCutAtMaxRowsWithExactTotals(t *testing.T) {
	env := finishNativeXrefsFixture(t, xrefsReportBody, 2)
	code := env.Tails["code_refs"]
	if code.Total != 3 || code.Returned != 2 || !code.Truncated {
		t.Fatalf("code_refs tail = %+v; total counts the items in the report", code)
	}
	if c := code.Items[1].(map[string]any); c["insn_addr"] != "0x1004" || c["kind"] != "jump" {
		t.Errorf("code_refs keep the report's order: %v", code.Items)
	}
	if addr := env.Tails["addr_refs"]; addr.Total != 2 || addr.Returned != 2 || addr.Truncated {
		t.Errorf("addr_refs tail = %+v", addr)
	}
	head := env.Result.(map[string]any)["xrefs"].([]any)[0].(map[string]any)
	if head["code_refs"].(map[string]any)["total"] != float64(2500) {
		t.Errorf("max_rows changed Drakkar's total: %v", head["code_refs"])
	}
}

func TestNativeXrefsReportWithoutEntry(t *testing.T) {
	const body = `{"sha256": "abc", "elfs": [], "binding": [], "summary": {},
 "errors": ["xrefs *@0x9999 : aucun ELF AArch64 n'a de section qui contient 0x9999"]}`
	env := finishNativeXrefsFixture(t, body, 50)
	if heads := env.Result.(map[string]any)["xrefs"].([]any); len(heads) != 0 {
		t.Errorf("head = %v", heads)
	}
	for _, name := range nativeXrefsLists {
		if tail := env.Tails[name]; tail.Total != 0 || len(tail.Items) != 0 {
			t.Errorf("%s tail = %+v", name, tail)
		}
	}
	if e := env.Tails["errors"]; e.Total != 1 {
		t.Errorf("errors = %+v", e)
	}
	notes := strings.Join(env.Notes, "\n")
	if !strings.Contains(notes, "no xrefs entry") || strings.Contains(notes, "no static reference") {
		t.Errorf("notes = %q", env.Notes)
	}
}

// End to end against a stub drakkar that refuses the mode, as one predating
// --native-xrefs does; a report left by an earlier run must not be read.
func TestNativeXrefsUnknownModeQuotesDrakkar(t *testing.T) {
	const clap = "error: unexpected argument '--native-xrefs' found"
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
	if err := os.WriteFile(stale, []byte(xrefsReportBody), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := s.NativeXrefs(context.Background(), NativeXrefsInput{APK: apk, Addresses: []string{"1a00", "5010"}, OutDir: out})
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
	if !strings.Contains(notes, "does not know --native-xrefs") || !strings.Contains(notes, "Drakkar's message, verbatim: "+clap) {
		t.Errorf("notes = %q", env.Notes)
	}
	if env.Result != nil {
		t.Errorf("a stale report was read: result = %v", env.Result)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale report is still there")
	}
}

func TestNativeXrefsDrakkarRefusalComesBackInErrors(t *testing.T) {
	const refusal = "Error: archive illisible : invalid Zip archive: Could not find EOCD"
	stubDrakkar(t, `echo '`+refusal+`' >&2
exit 1
`)
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")
	if err := os.WriteFile(apk, []byte("not really an apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := s.NativeXrefs(context.Background(), NativeXrefsInput{
		APK: apk, ELF: "lib/arm64-v8a/libfoo.so", Addresses: []string{"1a00"}, OutDir: filepath.Join(base, "out"),
	})
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
	if env.Result != nil {
		t.Errorf("result = %v without a report", env.Result)
	}
}
