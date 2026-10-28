package service

import (
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
	if err := s.finishNative(env, writeReport(t, body), maxRows); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeArgv(t *testing.T) {
	argv, err := nativeArgs("/corpus/A sample.apk", "/out/report.json").Argv()
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
	if err := s.finishNative(env, filepath.Join(base, "report.json"), 50); err != nil {
		t.Fatal(err)
	}
	if env.Result != nil || len(env.Notes) != 1 {
		t.Errorf("result = %v, notes = %v", env.Result, env.Notes)
	}
}
