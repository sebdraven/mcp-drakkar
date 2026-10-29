package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nativeAPKSHA   = "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9"
	nativeLibSHA   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	nativeAssetSHA = "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a"
)

// The shape of a --native report, binding rows deliberately out of order.
const nativeReportBody = `{
  "sha256": "` + nativeAPKSHA + `",
  "elfs": [
    {"path": "lib/arm64-v8a/libfoo.so", "origin": "lib", "sha256": "` + nativeLibSHA + `", "size": 4096,
     "machine": "aarch64", "bits": 64, "endian": "little", "declared_abi": "arm64-v8a", "abi_mismatch": false,
     "elf_type": "dyn", "pie": true, "stripped": true, "interp": null,
     "sections": [{"name": ".text", "size": 1024, "flags": "rx", "entropy": 6.1}],
     "segments": [], "needed": ["libc.so"], "soname": "libfoo.so", "init": null, "init_array_count": 0,
     "imports": {"process": [], "injection": [], "dynload": ["dlopen"], "memory": [], "network": [], "crypto": [],
                 "anti_analysis": [], "file": [], "jni": ["JNI_OnLoad"], "other_count": 3},
     "exports_count": 3,
     "jni": {"jni_onload": true, "registernatives_string": true, "jni_registration": "tables_found",
             "static_exports": [{"symbol": "Java_com_a_Main_hello", "class": "Lcom/a/Main;", "method": "hello", "signature": null}],
             "registered": [
               {"name": "run", "signature": "()V", "fn_offset": "0x1200", "table_offset": "0x3000", "thumb": false},
               {"name": "stop", "signature": "()V", "fn_offset": "0x1300", "table_offset": "0x3018", "thumb": false}
             ]},
     "strings": {}, "anomalies": []},
    {"path": "assets/payload.bin", "origin": "assets", "sha256": "` + nativeAssetSHA + `", "size": 8192,
     "machine": "arm", "bits": 32, "endian": "little", "declared_abi": null, "abi_mismatch": false,
     "elf_type": "dyn", "pie": true, "stripped": false, "interp": null,
     "sections": [], "segments": [], "needed": [], "soname": null, "init": null, "init_array_count": 0,
     "imports": {}, "exports_count": 0,
     "jni": {"jni_onload": false, "registernatives_string": false, "jni_registration": "none",
             "static_exports": [], "registered": []},
     "strings": {}, "anomalies": ["elf_outside_lib: assets"]}
  ],
  "binding": [
    {"java": "Lcom/a/Z;->orphan()V", "status": "native_unclaimed", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `", "fn_offset": "0x900", "candidates": []},
    {"java": "Lcom/a/Main;->stop()V", "status": "registered", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `", "fn_offset": "0x1300", "candidates": []},
    {"java": "Lcom/a/B;->gone()V", "status": "declared_unbound", "elf": null, "elf_sha256": null, "fn_offset": null, "candidates": []},
    {"java": "Lcom/a/Main;->run()V", "status": "registered", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `", "fn_offset": "0x1200", "candidates": []},
    {"java": "Lcom/a/C;->twice()V", "status": "registered_ambiguous", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `", "fn_offset": "0x1400", "candidates": ["0x1400", "0x1500"]},
    {"java": "Lcom/a/Main;->hello()V", "status": "static", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `", "fn_offset": "0x1000", "candidates": []}
  ],
  "summary": {"elf_count": 2, "native_methods_declared": 5, "bound_static": 1, "bound_registered": 2,
              "ambiguous": 1, "unbound": 1, "unclaimed": 1},
  "errors": []
}`

func finishNativeFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNative(env, writeReport(t, body), maxRows, false); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeArgv(t *testing.T) {
	argv, err := nativeArgs("/corpus/A sample.apk", "/out/report.json", NativeInput{}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/corpus/A sample.apk", "--native", "--format=json", "--json-out=/out/report.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestNativeHeadIsTheSummary(t *testing.T) {
	env := finishNativeFixture(t, nativeReportBody, 50)
	head, ok := env.Result.(map[string]any)
	if !ok {
		t.Fatalf("head is %T, want an object", env.Result)
	}
	for k, want := range map[string]float64{
		"elf_count": 2, "native_methods_declared": 5, "bound_static": 1, "bound_registered": 2,
		"ambiguous": 1, "unbound": 1, "unclaimed": 1,
	} {
		if head[k] != want {
			t.Errorf("%s = %v, want %v", k, head[k], want)
		}
	}
	if head["sha256"] != nativeAPKSHA {
		t.Errorf("sha256 = %v, want it whole", head["sha256"])
	}
	if _, present := head["elfs"]; present {
		t.Error("elfs stayed in the head")
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestNativeELFRows(t *testing.T) {
	env := finishNativeFixture(t, nativeReportBody, 50)
	tail := env.Tails["elfs"]
	if tail.Total != 2 || tail.Returned != 2 || tail.Truncated {
		t.Fatalf("elfs tail = %+v", tail)
	}
	lib := tail.Items[0].(map[string]any)
	if lib["sha256"] != nativeLibSHA {
		t.Errorf("sha256 = %v, want it whole", lib["sha256"])
	}
	if lib["machine"] != "aarch64" || lib["bits"] != 64 || lib["elf_type"] != "dyn" || lib["stripped"] != true {
		t.Errorf("lib row = %v", lib)
	}
	if lib["jni_onload"] != true || lib["jni_registration"] != "tables_found" {
		t.Errorf("jni = %v / %v", lib["jni_onload"], lib["jni_registration"])
	}
	if lib["static_exports_count"] != 1 || lib["registered_count"] != 2 {
		t.Errorf("counts = %v / %v", lib["static_exports_count"], lib["registered_count"])
	}
	if _, present := lib["sections"]; present {
		t.Error("sections reached the row; they stay in report.json")
	}
	asset := tail.Items[1].(map[string]any)
	if asset["origin"] != "assets" {
		t.Errorf("origin = %v", asset["origin"])
	}
	if a, _ := asset["anomalies"].([]string); len(a) != 1 || a[0] != "elf_outside_lib: assets" {
		t.Errorf("anomalies = %v", asset["anomalies"])
	}
}

func TestNativeBindingIsSortedByStatusThenJava(t *testing.T) {
	env := finishNativeFixture(t, nativeReportBody, 50)
	tail := env.Tails["binding"]
	if tail.Total != 6 || tail.Truncated {
		t.Fatalf("binding tail = %+v", tail)
	}
	want := []string{
		"Lcom/a/Main;->hello()V",
		"Lcom/a/Main;->run()V",
		"Lcom/a/Main;->stop()V",
		"Lcom/a/C;->twice()V",
		"Lcom/a/B;->gone()V",
		"Lcom/a/Z;->orphan()V",
	}
	for i, w := range want {
		if got := tail.Items[i].(map[string]any)["java"]; got != w {
			t.Errorf("binding[%d] = %v, want %v", i, got, w)
		}
	}
	if got := tail.Items[0].(map[string]any)["elf_sha256"]; got != nativeLibSHA {
		t.Errorf("elf_sha256 = %v, want it whole", got)
	}
}

func TestNativeMaxRowsCapsBindingOnly(t *testing.T) {
	env := finishNativeFixture(t, nativeReportBody, 2)
	b := env.Tails["binding"]
	if b.Total != 6 || b.Returned != 2 || !b.Truncated {
		t.Errorf("binding tail = %+v", b)
	}
	if got := b.Items[1].(map[string]any)["status"]; got != "registered" {
		t.Errorf("the preview should keep the head of the sorted rows, got %v", got)
	}
	if e := env.Tails["elfs"]; e.Total != 2 || e.Returned != 2 || e.Truncated {
		t.Errorf("elfs was cut: %+v", e)
	}
}

func TestNativeWithoutELF(t *testing.T) {
	const body = `{
  "sha256": "` + nativeAPKSHA + `",
  "elfs": [],
  "binding": [{"java": "Lcom/a/B;->gone()V", "status": "declared_unbound", "elf": null, "elf_sha256": null, "fn_offset": null, "candidates": []}],
  "summary": {"elf_count": 0, "native_methods_declared": 1, "bound_static": 0, "bound_registered": 0,
              "ambiguous": 0, "unbound": 1, "unclaimed": 0},
  "errors": []
}`
	env := finishNativeFixture(t, body, 50)
	e := env.Tails["elfs"]
	if e.Total != 0 || e.Returned != 0 || e.Truncated || e.Items == nil {
		t.Errorf("elfs tail = %+v", e)
	}
	if env.Tails["binding"].Total != 1 {
		t.Errorf("binding tail = %+v", env.Tails["binding"])
	}
	if !strings.Contains(strings.Join(env.Notes, " "), "no ELF") {
		t.Errorf("notes = %v", env.Notes)
	}
}

func TestNativeErrorsAreATailAndANote(t *testing.T) {
	const body = `{
  "sha256": "` + nativeAPKSHA + `",
  "elfs": [],
  "binding": [],
  "summary": {"elf_count": 0, "native_methods_declared": 0, "bound_static": 0, "bound_registered": 0,
              "ambiguous": 0, "unbound": 0, "unclaimed": 0},
  "errors": ["classes2.dex: DEX illisible", "lib/x86/libbar.so: ELF tronqué"]
}`
	env := finishNativeFixture(t, body, 50)
	errs := env.Tails["errors"]
	if errs.Total != 2 || errs.Returned != 2 || errs.Truncated {
		t.Fatalf("errors tail = %+v", errs)
	}
	if errs.Items[0] != "classes2.dex: DEX illisible" {
		t.Errorf("errors[0] = %v", errs.Items[0])
	}
	if !strings.Contains(strings.Join(env.Notes, " "), "2 error(s)") {
		t.Errorf("notes = %v", env.Notes)
	}
	if b := env.Tails["binding"]; b.Total != 0 || b.Items == nil {
		t.Errorf("binding tail = %+v", b)
	}
}

func TestNativeMissingReportAfterAFailureIsANote(t *testing.T) {
	s, base := testService(t)
	env := &Envelope{}
	env.Drakkar.ExitCode = 2
	if err := s.finishNative(env, filepath.Join(base, "report.json"), 50, false); err != nil {
		t.Fatal(err)
	}
	if env.Result != nil || len(env.Notes) != 1 {
		t.Errorf("result = %v, notes = %v", env.Result, env.Notes)
	}
}

func nativeStringRefs(n int) string {
	refs := make([]string, n)
	for i := range refs {
		refs[i] = fmt.Sprintf(`{"address": "0x%x", "target": "0x%x", "value": "s%d", "encoding": "utf8"}`,
			0x1000+4*i, 0x4000+8*i, i)
	}
	return "[" + strings.Join(refs, ", ") + "]"
}

// The shape of a --native --native-disasm report as Drakkar's serde types write
// it: three functions over two ELFs, and a registered_ambiguous pair lifted by
// a RegisterNatives whose class comes from FindClass.
var nativeDisasmReportBody = `{
  "sha256": "` + nativeAPKSHA + `",
  "elfs": [
    {"path": "lib/arm64-v8a/libfoo.so", "origin": "lib", "sha256": "` + nativeLibSHA + `",
     "machine": "aarch64", "bits": 64, "elf_type": "dyn", "stripped": true, "anomalies": [],
     "jni": {"jni_onload": true, "jni_registration": "none", "static_exports": [], "registered": []},
     "disasm": {
       "functions": [
         {"origin": "jni_onload", "address": "0x1000", "disasm_status": "ok", "truncated": false, "truncated_reason": null,
          "instructions": [
            {"address": "0x1000", "bytes": "fd7bbfa9", "mnemonic": "stp", "operands": "x29, x30, [sp, #-0x10]!"},
            {"address": "0x1004", "bytes": "ff030094", "mnemonic": "bl", "operands": "$+0xffc"},
            {"address": "0x1008", "bytes": "c0035fd6", "mnemonic": "ret", "operands": ""}
          ],
          "calls": [
            {"target": "0x2000", "import": "dlopen", "symbol": null, "kind": "plt"},
            {"target": "0x2010", "import": "dlsym", "symbol": null, "kind": "plt"},
            {"target": null, "import": "dlopen", "symbol": null, "kind": "plt"},
            {"target": "0x1800", "import": null, "symbol": "helper", "kind": "internal"}
          ],
          "string_refs": ` + nativeStringRefs(25) + `,
          "jni_calls": [
            {"name": "FindClass", "index": 6, "resolved": true, "class": "Lcom/a/Main;"},
            {"name": "GetMethodID", "index": 33, "resolved": true, "class": "Lcom/a/Main;", "method": "onReady", "signature": "()V"},
            {"name": "RegisterNatives", "index": 215, "resolved": false}
          ],
          "syscalls": []},
         {"origin": "jni_registered", "address": "0x1200", "disasm_status": "truncated", "truncated": true,
          "truncated_reason": "max_insns",
          "instructions": [{"address": "0x1200", "bytes": "010000d4", "mnemonic": "svc", "operands": "#0x0"}],
          "calls": [{"target": null, "import": null, "symbol": null, "kind": "indirect"}], "string_refs": [],
          "jni_calls": [{"name": "CallVoidMethod", "index": 61, "resolved": false}],
          "syscalls": [{"address": "0x1200", "number": 56}]}
       ],
       "upcalls": [
         {"class": "Lcom/a/Main;", "name": "onReady", "signature": "()V"},
         {"class": "Lcom/a/Main;", "name": "onFail", "signature": "(I)V"}
       ],
       "registered_by_code": [{"class": "Lcom/a/Main;", "name": "run", "signature": "()V"}],
       "imports_called": {"dynload": ["dlopen", "dlsym"]}
     }},
    {"path": "assets/payload.bin", "origin": "assets", "sha256": "` + nativeAssetSHA + `",
     "machine": "arm", "bits": 32, "elf_type": "dyn", "stripped": false, "anomalies": ["elf_outside_lib: assets"],
     "jni": {"jni_onload": false, "jni_registration": "none", "static_exports": [], "registered": []},
     "disasm": {
       "functions": [
         {"origin": "init_array", "address": "0x800", "disasm_status": "ok", "truncated": false, "truncated_reason": null,
          "instructions": [{"address": "0x800", "bytes": "7047", "mnemonic": "bx", "operands": "lr"}],
          "calls": [], "string_refs": [], "jni_calls": [], "syscalls": []}
       ],
       "upcalls": [{"class": "Lcom/a/Main;", "name": "onReady", "signature": "()V"}],
       "registered_by_code": [],
       "imports_called": {}
     }}
  ],
  "binding": [
    {"java": "Lcom/b/Other;->run()V", "status": "registered_ambiguous", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `",
     "fn_offset": "0x1200", "candidates": ["Lcom/a/Main;->run()V", "Lcom/b/Other;->run()V"],
     "disambiguated_by": "find_class", "class": "Lcom/a/Main;"},
    {"java": "Lcom/a/Main;->run()V", "status": "registered_ambiguous", "elf": "lib/arm64-v8a/libfoo.so", "elf_sha256": "` + nativeLibSHA + `",
     "fn_offset": "0x1200", "candidates": ["Lcom/a/Main;->run()V", "Lcom/b/Other;->run()V"],
     "disambiguated_by": "find_class", "class": "Lcom/a/Main;"},
    {"java": "Lcom/a/B;->gone()V", "status": "declared_unbound", "elf": null, "elf_sha256": null, "fn_offset": null, "candidates": []}
  ],
  "summary": {"elf_count": 2, "native_methods_declared": 3, "bound_static": 0, "bound_registered": 0,
              "ambiguous": 2, "unbound": 1, "unclaimed": 0},
  "errors": []
}`

func finishNativeDisasmFixture(t *testing.T, body string, maxRows int) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishNative(env, writeReport(t, body), maxRows, true); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeArgvWithDisasm(t *testing.T) {
	depth, insns := 2, 5000
	for _, c := range []struct {
		in   NativeInput
		want []string
	}{
		{NativeInput{Disasm: true},
			[]string{"/a.apk", "--native", "--native-disasm", "--format=json", "--json-out=/out/report.json"}},
		{NativeInput{Disasm: true, DisasmDepth: &depth},
			[]string{"/a.apk", "--native", "--native-disasm", "--disasm-depth=2", "--format=json", "--json-out=/out/report.json"}},
		{NativeInput{Disasm: true, DisasmDepth: &depth, DisasmMaxInsns: &insns},
			[]string{"/a.apk", "--native", "--native-disasm", "--disasm-depth=2", "--disasm-max-insns=5000", "--format=json", "--json-out=/out/report.json"}},
	} {
		argv, err := nativeArgs("/a.apk", "/out/report.json", c.in).Argv()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(argv, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("argv = %q, want %q", argv, c.want)
		}
	}
}

func TestNativeDisasmBoundsNeedDisasm(t *testing.T) {
	depth, insns := 1, 100
	for _, in := range []NativeInput{
		{DisasmDepth: &depth},
		{DisasmMaxInsns: &insns},
	} {
		err := checkNativeDisasm(in)
		if err == nil || !strings.Contains(err.Error(), "disasm=true") {
			t.Errorf("%+v: err = %v", in, err)
		}
	}

	s, base := testService(t)
	_, err := s.Native(context.Background(), NativeInput{APK: filepath.Join(base, "a.apk"), DisasmDepth: &depth})
	if err == nil || !strings.Contains(err.Error(), "disasm=true") {
		t.Errorf("Native should refuse before running Drakkar, err = %v", err)
	}
}

func TestNativeDisasmBounds(t *testing.T) {
	for _, c := range []struct {
		depth, insns *int
		ok           bool
	}{
		{depth: intRef(0), ok: true},
		{depth: intRef(3), ok: true},
		{depth: intRef(-1)},
		{depth: intRef(4)},
		{insns: intRef(1), ok: true},
		{insns: intRef(20000), ok: true},
		{insns: intRef(0)},
		{insns: intRef(20001)},
	} {
		err := checkNativeDisasm(NativeInput{Disasm: true, DisasmDepth: c.depth, DisasmMaxInsns: c.insns})
		if c.ok && err != nil {
			t.Errorf("depth=%v insns=%v refused: %v", deref(c.depth), deref(c.insns), err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "out of bounds")) {
			t.Errorf("depth=%v insns=%v: err = %v", deref(c.depth), deref(c.insns), err)
		}
	}
}

func intRef(n int) *int { return &n }

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestNativeDisasmHeadCounters(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeDisasmReportBody, 50)
	head := env.Result.(map[string]any)
	for k, want := range map[string]int{
		"disasm_functions_total": 3, "disasm_truncated": 1, "jni_calls_resolved": 2, "jni_calls_unresolved": 2,
	} {
		if head[k] != want {
			t.Errorf("%s = %v, want %d", k, head[k], want)
		}
	}
	if head["ambiguous"] != float64(2) {
		t.Errorf("the summary should still be the head, ambiguous = %v", head["ambiguous"])
	}
}

func TestNativeDisasmFunctionRows(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeDisasmReportBody, 50)
	tail := env.Tails["disasm_functions"]
	if tail.Total != 3 || tail.Returned != 3 || tail.Truncated {
		t.Fatalf("disasm_functions tail = %+v", tail)
	}
	row := tail.Items[0].(map[string]any)
	if row["elf"] != "lib/arm64-v8a/libfoo.so" || row["elf_sha256"] != nativeLibSHA {
		t.Errorf("elf = %v / %v, want the path and the whole sha256", row["elf"], row["elf_sha256"])
	}
	if row["origin"] != "jni_onload" || row["address"] != "0x1000" || row["disasm_status"] != "ok" || row["truncated"] != false {
		t.Errorf("row = %v", row)
	}
	if row["truncated_reason"] != nil {
		t.Errorf("truncated_reason = %v, want null", row["truncated_reason"])
	}
	cut := tail.Items[1].(map[string]any)
	if cut["truncated"] != true || cut["truncated_reason"] != "max_insns" || cut["disasm_status"] != "truncated" {
		t.Errorf("truncated row = %v", cut)
	}
	if row["instructions_count"] != 3 || row["calls_count"] != 4 {
		t.Errorf("counts = %v / %v", row["instructions_count"], row["calls_count"])
	}
	if _, present := row["instructions"]; present {
		t.Error("instructions reached the row; they stay in report.json")
	}
	if got := strings.Join(row["imports_called"].([]string), ","); got != "dlopen,dlsym" {
		t.Errorf("imports_called = %v", got)
	}

	jni := row["jni_calls"].([]any)
	if len(jni) != 3 || row["jni_calls_unresolved"] != 1 {
		t.Fatalf("jni_calls = %v, unresolved = %v", jni, row["jni_calls_unresolved"])
	}
	get := jni[1].(map[string]any)
	if get["name"] != "GetMethodID" || get["class"] != "Lcom/a/Main;" || get["method"] != "onReady" || get["signature"] != "()V" {
		t.Errorf("jni_calls[1] = %v", get)
	}
	if reg := jni[2].(map[string]any); reg["name"] != "RegisterNatives" || len(reg) != 1 {
		t.Errorf("an unresolved call keeps its name only, got %v", reg)
	}

	if refs := row["string_refs"].([]any); len(refs) != 20 || row["string_refs_total"] != 25 {
		t.Errorf("string_refs = %d of %v, want 20 of 25", len(refs), row["string_refs_total"])
	}

	asset := tail.Items[2].(map[string]any)
	if asset["elf_sha256"] != nativeAssetSHA || asset["origin"] != "init_array" {
		t.Errorf("asset row = %v", asset)
	}
	if imports := asset["imports_called"].([]string); imports == nil || len(imports) != 0 {
		t.Errorf("imports_called = %#v, want an empty list", imports)
	}
}

func TestNativeDisasmUpcallsAndRegisteredByCode(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeDisasmReportBody, 50)
	up := env.Tails["upcalls"]
	if up.Total != 3 || up.Truncated {
		t.Fatalf("upcalls tail = %+v", up)
	}
	want := []string{
		"lib/arm64-v8a/libfoo.so Lcom/a/Main; onReady ()V",
		"lib/arm64-v8a/libfoo.so Lcom/a/Main; onFail (I)V",
		"assets/payload.bin Lcom/a/Main; onReady ()V",
	}
	for i, w := range want {
		r := up.Items[i].(map[string]any)
		if got := fmt.Sprintf("%v %v %v %v", r["elf"], r["class"], r["name"], r["signature"]); got != w {
			t.Errorf("upcalls[%d] = %q, want %q", i, got, w)
		}
	}

	byCode := env.Tails["registered_by_code"]
	if byCode.Total != 1 {
		t.Fatalf("registered_by_code tail = %+v", byCode)
	}
	if r := byCode.Items[0].(map[string]any); r["elf"] != "lib/arm64-v8a/libfoo.so" || r["name"] != "run" || r["signature"] != "()V" {
		t.Errorf("registered_by_code[0] = %v", r)
	}
}

func TestNativeMaxRowsCapsDisasmFunctions(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeDisasmReportBody, 2)
	f := env.Tails["disasm_functions"]
	if f.Total != 3 || f.Returned != 2 || !f.Truncated {
		t.Errorf("disasm_functions tail = %+v", f)
	}
	if u := env.Tails["upcalls"]; u.Total != 3 || u.Returned != 3 || u.Truncated {
		t.Errorf("upcalls was cut: %+v", u)
	}
	if head := env.Result.(map[string]any); head["disasm_functions_total"] != 3 {
		t.Errorf("disasm_functions_total = %v, want every function counted", head["disasm_functions_total"])
	}
}

func TestNativeBindingKeepsDisambiguation(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeDisasmReportBody, 50)
	row := env.Tails["binding"].Items[0].(map[string]any)
	if row["java"] != "Lcom/a/Main;->run()V" || row["disambiguated_by"] != "find_class" || row["class"] != "Lcom/a/Main;" {
		t.Errorf("binding[0] = %v", row)
	}
	other := env.Tails["binding"].Items[1].(map[string]any)
	if other["status"] != "registered_ambiguous" || other["class"] != "Lcom/a/Main;" {
		t.Errorf("binding[1] = %v, want the other candidate, status kept, same class retained", other)
	}
}

func TestNativeWithoutDisasmIgnoresTheDisasmSections(t *testing.T) {
	env := finishNativeFixture(t, nativeDisasmReportBody, 50)
	if len(env.Tails) != 3 {
		t.Errorf("tails = %v, want elfs, binding and errors only", env.Tails)
	}
	head := env.Result.(map[string]any)
	for _, k := range []string{"disasm_functions_total", "disasm_truncated", "jni_calls_resolved", "jni_calls_unresolved"} {
		if _, present := head[k]; present {
			t.Errorf("%s is in the head without disasm", k)
		}
	}
}

func TestNativeDisasmAskedButAbsentIsANote(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeReportBody, 50)
	if f := env.Tails["disasm_functions"]; f.Total != 0 || f.Items == nil {
		t.Errorf("disasm_functions tail = %+v", f)
	}
	if head := env.Result.(map[string]any); head["disasm_functions_total"] != 0 {
		t.Errorf("disasm_functions_total = %v", head["disasm_functions_total"])
	}
	if !strings.Contains(strings.Join(env.Notes, " "), "no ELF in the report carries a disasm section") {
		t.Errorf("notes = %v", env.Notes)
	}
}

func TestNativeNotesADrakkarThatPredatesNativeDisasm(t *testing.T) {
	env := &Envelope{}
	env.Drakkar.ExitCode = 2
	env.Stderr.Text = "error: unexpected argument '--native-disasm' found\n\nUsage: drakkar [OPTIONS] [APK]\n"
	noteUnknownNativeFlags(env, true)
	if len(env.Notes) != 1 || env.Notes[0] != "this drakkar predates --native-disasm; drakkar_version shows which one is on PATH" {
		t.Errorf("notes = %v", env.Notes)
	}
}

// One function with two invalid paths, as Drakkar 0.2.3 writes it.
var nativeInvalidPathsReportBody = `{
  "sha256": "` + nativeAPKSHA + `",
  "elfs": [
    {"path": "lib/armeabi-v7a/libobf.so", "origin": "lib", "sha256": "` + nativeLibSHA + `",
     "machine": "arm", "bits": 32, "elf_type": "dyn", "stripped": true, "anomalies": [],
     "jni": {"jni_onload": true, "jni_registration": "none", "static_exports": [], "registered": []},
     "disasm": {
       "functions": [
         {"origin": "jni_onload", "address": "0x4000", "disasm_status": "ok", "truncated": false, "truncated_reason": null,
          "invalid_paths": [
            {"address": "0x4010", "bytes": "ffffffff", "reason": "invalid_instruction", "reached_from": "0x400c"},
            {"address": "0x4030", "bytes": "ffde", "reason": "invalid_instruction", "reached_from": "0x4024"}
          ],
          "instructions": [{"address": "0x4000", "bytes": "7047", "mnemonic": "bx", "operands": "lr"}],
          "calls": [], "string_refs": [], "jni_calls": [], "syscalls": []}
       ],
       "upcalls": [],
       "registered_by_code": [],
       "imports_called": {},
       "invalid_paths_count": 2
     }}
  ],
  "binding": [],
  "summary": {"elf_count": 1, "native_methods_declared": 0, "bound_static": 0, "bound_registered": 0,
              "ambiguous": 0, "unbound": 0, "unclaimed": 0},
  "errors": []
}`

func TestNativeDisasmInvalidPaths(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeInvalidPathsReportBody, 50)
	tail := env.Tails["disasm_functions"]
	if tail.Total != 1 || tail.Returned != 1 || tail.Truncated {
		t.Fatalf("disasm_functions tail = %+v", tail)
	}
	fn := tail.Items[0].(map[string]any)
	if fn["invalid_paths"] != 2 || fn["truncated"] != false {
		t.Errorf("function row = %v, want invalid_paths 2 and not truncated", fn)
	}
	if elf := env.Tails["elfs"].Items[0].(map[string]any); elf["invalid_paths_count"] != 2 {
		t.Errorf("elfs[0].invalid_paths_count = %v, want 2", elf["invalid_paths_count"])
	}

	old := finishNativeDisasmFixture(t, nativeDisasmReportBody, 50)
	for i, item := range old.Tails["elfs"].Items {
		if v, present := item.(map[string]any)["invalid_paths_count"]; !present || v != nil {
			t.Errorf("elfs[%d].invalid_paths_count = %v (present %v), want null before Drakkar 0.2.3", i, v, present)
		}
	}
}

func TestNativeArgvWithNativeDexAndListing(t *testing.T) {
	in := NativeInput{
		Disasm:    true,
		NativeDex: []string{"/corpus/host.apk", "/corpus/payload.dex"},
		Listing:   []string{"libfoo.so@0x1000-0x1040"},
	}
	argv, err := nativeArgs("/corpus/libfoo.so", "/out/report.json", in).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/corpus/libfoo.so", "--native",
		"--native-dex=/corpus/host.apk", "--native-dex=/corpus/payload.dex",
		"--native-disasm", "--native-listing=libfoo.so@0x1000-0x1040",
		"--format=json", "--json-out=/out/report.json",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestNativeListingNeedsDisasm(t *testing.T) {
	in := NativeInput{Listing: []string{"*@0x1000"}}
	if err := checkNativeDisasm(in); err == nil || !strings.Contains(err.Error(), "disasm=true") {
		t.Errorf("err = %v", err)
	}

	s, base := testService(t)
	in.APK = filepath.Join(base, "libfoo.so")
	if _, err := s.Native(context.Background(), in); err == nil || !strings.Contains(err.Error(), "disasm=true") {
		t.Errorf("Native should refuse before running Drakkar, err = %v", err)
	}
	relative := NativeInput{APK: in.APK, NativeDex: []string{"payload.dex"}}
	if _, err := s.Native(context.Background(), relative); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("a relative native_dex should be refused, err = %v", err)
	}
}

// A raw ELF bound against two DEX sources, with one listing, as Drakkar main writes it.
var nativeListingReportBody = `{
  "sha256": "` + nativeLibSHA + `",
  "dex_available": true,
  "dex_sources": ["/corpus/host.apk", "/corpus/payload.dex"],
  "elfs": [
    {"path": "libfoo.so", "origin": "raw", "sha256": "` + nativeLibSHA + `",
     "machine": "aarch64", "bits": 64, "elf_type": "dyn", "stripped": true, "anomalies": [],
     "jni": {"jni_onload": true, "jni_registration": "none", "static_exports": [], "registered": []},
     "disasm": {"functions": [], "upcalls": [], "registered_by_code": [], "imports_called": {}, "invalid_paths_count": 0}}
  ],
  "binding": [],
  "summary": {"elf_count": 1, "native_methods_declared": 0, "bound_static": 0, "bound_registered": 0,
              "ambiguous": 0, "unbound": 0, "unclaimed": 0},
  "listings": [
    {"elf": "libfoo.so", "start": "0x1000", "end": "0x100c", "instructions": [
      {"address": "0x1000", "bytes": "fd7bbfa9", "mnemonic": "stp", "operands": "x29, x30, [sp, #-0x10]!", "comment": null},
      {"address": "0x1004", "bytes": "ff030094", "mnemonic": "bl", "operands": "$+0xffc", "comment": "dlopen"},
      {"address": "0x1008", "bytes": "c0035fd6", "mnemonic": "ret", "operands": "", "comment": null}
    ]}
  ],
  "errors": []
}`

func TestNativeDexSourcesAndListings(t *testing.T) {
	env := finishNativeDisasmFixture(t, nativeListingReportBody, 2)
	head := env.Result.(map[string]any)
	if head["dex_available"] != true {
		t.Errorf("dex_available = %v", head["dex_available"])
	}
	if got := strings.Join(head["dex_sources"].([]string), ","); got != "/corpus/host.apk,/corpus/payload.dex" {
		t.Errorf("dex_sources = %v, want both, in reading order", got)
	}

	tail := env.Tails["listings"]
	if tail.Total != 1 || tail.Returned != 1 || tail.Truncated {
		t.Fatalf("listings tail = %+v", tail)
	}
	l := tail.Items[0].(map[string]any)
	if l["elf"] != "libfoo.so" || l["start"] != "0x1000" || l["end"] != "0x100c" {
		t.Errorf("listing = %v", l)
	}
	insns := l["instructions"].([]any)
	if len(insns) != 2 || l["instructions_total"] != 3 || l["truncated"] != true {
		t.Errorf("instructions = %d of %v, truncated %v; want 2 of 3, truncated", len(insns), l["instructions_total"], l["truncated"])
	}
	if c := insns[1].(map[string]any)["comment"]; c != "dlopen" {
		t.Errorf("comment = %v", c)
	}

	whole := finishNativeDisasmFixture(t, nativeListingReportBody, 50)
	l = whole.Tails["listings"].Items[0].(map[string]any)
	if len(l["instructions"].([]any)) != 3 || l["truncated"] != false {
		t.Errorf("listing = %v, want every instruction and not truncated", l)
	}

	old := finishNativeFixture(t, nativeReportBody, 50)
	if head := old.Result.(map[string]any); head["dex_available"] != nil {
		t.Errorf("dex_available = %v, want null when the report does not carry it", head["dex_available"])
	}
	if _, present := old.Tails["listings"]; present {
		t.Error("a report without listings grew a listings tail")
	}
}
