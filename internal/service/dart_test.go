package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	dartAPKSHA = "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9"
	dartLibSHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	// dartVersionHash is a whole 32-hex-digit snapshot version hash.
	dartVersionHash = "0123456789abcdef0123456789abcdef"
)

func dartWitnessJSON(value string, serialized, image int) string {
	return `{"value": "` + value + `", "encoding": "one_byte", "length": 4, "occurrences": 1, "occurrences_examined": 1,
	 "zones": {"serialized": {"count": ` + strconv.Itoa(serialized) + `, "first_offset": null},
	           "data_image": {"count": ` + strconv.Itoa(image) + `, "first_offset": 4096},
	           "outside": {"count": 0, "first_offset": null}},
	 "explained": true}`
}

// The shape of a --dart-snapshot report: one instructions blob without a scan,
// one data blob with string entries and a calibration of six witnesses.
var dartReportBody = `{
  "sha256": "` + dartAPKSHA + `",
  "summary": {"libraries": 1, "sections_found": 2, "located_by_symbol": 2, "located_by_heuristic": 0,
              "headers_parsed": 1, "headers_magic_ok": 1, "data_blobs": 1,
              "version_hashes": ["` + dartVersionHash + `"], "unknown_version_hashes": [],
              "libraries_calibrated": 1, "libraries_with_strings": 1, "libraries_without_strings": 0,
              "string_candidates": 3, "strings_accepted": 2, "strings_rejected": 1, "strings_returned": 2},
  "libraries": [
    {"path": "lib/arm64-v8a/libapp.so", "sha256": "` + dartLibSHA + `", "size": 65536,
     "sections": [
       {"symbol": "_kDartIsolateSnapshotInstructions", "blob_index": 1, "file_offset": 8192, "vaddr": 8192,
        "size": 4096, "elf_section": ".text", "header": null, "serialized": null, "data_image": null},
       {"symbol": "_kDartIsolateSnapshotData", "blob_index": 0, "file_offset": 4096, "vaddr": 4096,
        "size": 4096, "elf_section": ".rodata",
        "header": {"magic": "0xdcdcf5f5", "magic_ok": true, "length": 4000, "kind_raw": 3, "kind": "full_aot",
                   "version_hash": "` + dartVersionHash + `", "known_version": null,
                   "features": "product no-code-comments", "compressed_pointers": true, "errors": []},
        "serialized": {"start": 4096, "end": 6144, "size": 2048},
        "data_image": {"start": 6144, "end": 8192, "size": 2048, "end_bound": "symbol_size",
                       "start_alignment": 16, "start_alignment_source": "read_sdk_3_5_0"},
        "calibration": {"outcome": "calibrated", "not_run_reason": null, "witnesses_total": 6,
                        "witnesses_found": 6, "witnesses_in_data_image": 6, "witnesses_explained": 6,
                        "data_image_verdict": "all_in_data_image",
                        "witnesses": [` +
	dartWitnessJSON("w1", 1, 1) + `,` + dartWitnessJSON("w2", 0, 1) + `,` + dartWitnessJSON("w3", 0, 1) + `,` +
	dartWitnessJSON("w4", 0, 1) + `,` + dartWitnessJSON("w5", 0, 1) + `,` + dartWitnessJSON("w6", 0, 2) + `],
                        "word_size": 8, "compressed_pointers": true,
                        "length_fields_tried": [{"offset": 4, "width": 4}], "object_alignments_tried": [8, 16],
                        "tag_layouts_tried": [],
                        "inferred": [{"layout": {"word_size": 8, "object_alignment": 16}, "derived_cid": "one_byte",
                                      "evidence": [{"witness": "w1", "image_offset": 16, "file_offset": 6160}]}],
                        "known_version_literal": null},
        "strings": {"heuristic": true, "method": "aligned_object_scan", "blob_bound": "symbol_size",
                    "layout_source": "calibrated", "layout": {"word_size": 8}, "stride": 16,
                    "candidates": 3, "accepted": 2, "rejected": {"length_not_smi": 1},
                    "entries_total": 2, "entries_returned": 2, "truncated": false,
                    "entries": [
                      {"image_offset": 32, "file_offset": 6176, "encoding": "one_byte", "length": 22, "value": "https://c2.example/ENTRY"},
                      {"image_offset": 64, "file_offset": 6208, "encoding": "one_byte", "length": 12, "value": "SECRET_ENTRY"}
                    ]},
        "strings_unavailable": null}
     ],
     "missing_symbols": ["_kDartVmSnapshotData", "_kDartVmSnapshotInstructions"],
     "strings_unavailable": null,
     "anomalies": []}
  ],
  "errors": []
}`

func finishDartFixture(t *testing.T, body string, calibrating bool) *Envelope {
	t.Helper()
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishDartSnapshot(env, writeReport(t, body), calibrating); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestDartSnapshotArgv(t *testing.T) {
	argv, err := dartSnapshotArgs("/corpus/A flutter.apk", "/out/report.json", DartSnapshotInput{}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	// No --dart-max-rows unless asked: Drakkar owns that default.
	want := []string{"/corpus/A flutter.apk", "--dart-snapshot", "--format=json", "--json-out=/out/report.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}

	zero := 0
	argv, err = dartSnapshotArgs("/a.apk", "/out/report.json", DartSnapshotInput{
		MaxRows:   &zero,
		Calibrate: []string{"Hello world", "flutter"},
	}).Argv()
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"/a.apk", "--dart-snapshot", "--dart-max-rows=0", "--dart-calibrate=Hello world", "--dart-calibrate=flutter",
		"--format=json", "--json-out=/out/report.json"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestDartSnapshotRequiresAnAbsoluteOutDir(t *testing.T) {
	s, _ := testService(t)
	if _, err := s.DartSnapshot(context.Background(), DartSnapshotInput{APK: "/abs/a.apk"}); err == nil || !strings.Contains(err.Error(), "out_dir is required") {
		t.Errorf("an omitted out_dir gave %v, want a refusal", err)
	}
	if _, err := s.DartSnapshot(context.Background(), DartSnapshotInput{APK: "/abs/a.apk", OutDir: "relative/out"}); err == nil {
		t.Error("a relative out_dir was accepted")
	}
}

func TestDartSnapshotRefusesBadOptions(t *testing.T) {
	s, base := testService(t)
	negative := -1
	for name, in := range map[string]DartSnapshotInput{
		"negative max_rows": {MaxRows: &negative},
		"empty witness":     {Calibrate: []string{"flutter", ""}},
		"blank witness":     {Calibrate: []string{" \t "}},
	} {
		in.APK = "/abs/a.apk"
		in.OutDir = base
		if _, err := s.DartSnapshot(context.Background(), in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestDartSnapshotBlankWitnessIsRefusedBeforeAnythingRuns(t *testing.T) {
	err := checkDartSnapshot(DartSnapshotInput{Calibrate: []string{"flutter", "   "}})
	if err == nil {
		t.Fatal("a witness of spaces only was accepted")
	}
	for _, want := range []string{"calibrate[1]", "matches at every offset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestDartSnapshotEntriesNeverComeBackInline(t *testing.T) {
	env := finishDartFixture(t, dartReportBody, true)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"SECRET_ENTRY", "c2.example", `"entries"`} {
		if strings.Contains(string(b), leaked) {
			t.Errorf("%s reached the envelope; the entries stay in report.json", leaked)
		}
	}
	if filepath.Base(env.ReportPath) != "report.json" {
		t.Errorf("report_path = %q", env.ReportPath)
	}
}

func TestDartSnapshotHeadAndLibraries(t *testing.T) {
	env := finishDartFixture(t, dartReportBody, true)
	head := env.Result.(map[string]any)
	if head["sha256"] != dartAPKSHA {
		t.Errorf("sha256 = %v, want it whole", head["sha256"])
	}
	if _, ok := head["summary"].(map[string]any); !ok {
		t.Errorf("summary = %T, want an object", head["summary"])
	}

	tail := env.Tails["libraries"]
	if tail.Total != 1 || tail.Returned != 1 || tail.Truncated {
		t.Fatalf("libraries tail = %+v", tail)
	}
	lib := tail.Items[0].(map[string]any)
	if lib["sha256"] != dartLibSHA {
		t.Errorf("library sha256 = %v, want it whole", lib["sha256"])
	}
	if m := lib["missing_symbols"].([]string); len(m) != 2 {
		t.Errorf("missing_symbols = %v", m)
	}
	sections := lib["sections"].([]any)
	if len(sections) != 2 {
		t.Fatalf("%d sections, want 2", len(sections))
	}
	if _, present := sections[0].(map[string]any)["strings"]; present {
		t.Error("a blob without a scan gained a strings row")
	}

	data := sections[1].(map[string]any)
	header := data["header"].(map[string]any)
	if header["version_hash"] != dartVersionHash || header["magic_ok"] != true || header["compressed_pointers"] != true {
		t.Errorf("header = %v", header)
	}
	if data["serialized"] == nil || data["data_image"] == nil {
		t.Errorf("spans = %v / %v", data["serialized"], data["data_image"])
	}
	strs := data["strings"].(map[string]any)
	if strs["entries_total"] != uint64(2) || strs["truncated"] != false {
		t.Errorf("strings = %v", strs)
	}
}

func TestDartSnapshotWitnessesPastTheCapStayOnDisk(t *testing.T) {
	env := finishDartFixture(t, dartReportBody, true)
	lib := env.Tails["libraries"].Items[0].(map[string]any)
	cal := lib["sections"].([]any)[1].(map[string]any)["calibration"].(map[string]any)

	if cal["outcome"] != "calibrated" || cal["witnesses_total"] != 6 || cal["word_size"] != 8 {
		t.Errorf("calibration = %v", cal)
	}
	if _, present := cal["witnesses"]; present {
		t.Error("six witnesses came back inline; past the cap they stay in report.json")
	}
	zones := cal["witness_zones"].(map[string]int)
	if zones["serialized"] != 1 || zones["data_image"] != 7 || zones["outside"] != 0 {
		t.Errorf("witness_zones = %v", zones)
	}
	inferred := cal["inferred"].([]any)
	if len(inferred) != 1 || inferred[0].(map[string]any)["evidence_total"] != 1 {
		t.Errorf("inferred = %v", inferred)
	}
	if !strings.Contains(strings.Join(env.Notes, "\n"), "inline only up to") {
		t.Errorf("no note says the witnesses were left out: %q", env.Notes)
	}
}

func TestDartSnapshotWithoutWitnessesHasNoCalibration(t *testing.T) {
	body := strings.Replace(dartReportBody, `"calibration": {"outcome": "calibrated"`, `"calibration_absent": {"outcome": "calibrated"`, 1)
	env := finishDartFixture(t, body, false)
	lib := env.Tails["libraries"].Items[0].(map[string]any)
	if _, present := lib["sections"].([]any)[1].(map[string]any)["calibration"]; present {
		t.Error("a calibration appeared although the report has none")
	}
	if !strings.Contains(strings.Join(env.Notes, "\n"), "no calibration witness was given") {
		t.Errorf("no note says calibration did not run: %q", env.Notes)
	}
}
