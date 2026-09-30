package service

import (
	"encoding/json"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The shape of a --diff-dex report: the measurement is scalar, the evidence is in
// arrays that grow with the corpus.
const diffDexReport = `{
  "input_a": "/corpus/a.apk",
  "input_b": "/corpus/b.apk",
  "jaccard_methods": 0.91,
  "jaccard_ngram": 0.88,
  "identical_classes": 240,
  "identical_by_hash": 3,
  "near_classes": 12,
  "only_in_a": ["Lcom/dy/X;", "Lcom/dy/Y;"],
  "only_in_b": [],
  "identical": [{"a": "Lcom/dy/A;", "b": "Lcom/x/A;"}],
  "near": [{"a": "Lcom/dy/B;", "b": "Lcom/x/B;", "jaccard": 0.9}]
}`

func TestSplitKeepsTheMeasurementInline(t *testing.T) {
	head, tails := Split(decode(t, diffDexReport), "", nil, 50)

	obj, ok := head.(map[string]any)
	if !ok {
		t.Fatalf("head is %T, want an object", head)
	}
	if obj["jaccard_methods"] != 0.91 {
		t.Errorf("jaccard_methods = %v, want it inline and verbatim", obj["jaccard_methods"])
	}
	if obj["identical_classes"] != float64(240) {
		t.Errorf("identical_classes = %v", obj["identical_classes"])
	}
	if _, present := obj["near"]; present {
		t.Error("an unbounded array stayed in the head")
	}

	for _, key := range []string{"only_in_a", "only_in_b", "identical", "near"} {
		if _, ok := tails[key]; !ok {
			t.Errorf("no tail for %q", key)
		}
	}
}

func TestSplitDeclaresTruncation(t *testing.T) {
	head, tails := Split(decode(t, diffDexReport), "", nil, 1)
	_ = head

	tail := tails["only_in_a"]
	if tail.Total != 2 {
		t.Errorf("total = %d, want the real length", tail.Total)
	}
	if tail.Returned != 1 {
		t.Errorf("returned = %d, want the preview size", tail.Returned)
	}
	if !tail.Truncated {
		t.Error("a cut array was not declared truncated")
	}
}

func TestSplitAnEmptyArrayIsNotTruncated(t *testing.T) {
	_, tails := Split(decode(t, diffDexReport), "", nil, 50)

	tail := tails["only_in_b"]
	if tail.Total != 0 || tail.Returned != 0 {
		t.Errorf("tail = %+v", tail)
	}
	if tail.Truncated {
		t.Error("an empty array was reported as truncated")
	}
	if tail.Items == nil {
		t.Error("items should be an empty array, not null")
	}
}

func TestSplitKeepsInlineArrays(t *testing.T) {
	// groups and failed are the answer of --diff-matrix, not its appendix; and a
	// sample that could not be read must not be quietly absent.
	report := `{
      "metric": "opcodes",
      "threshold": 0.85,
      "groups": [["a", "b"], ["c"]],
      "failed": ["tampered.apk"],
      "samples": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
      "pairs": [{"a": "a", "b": "b", "jaccard_opcodes": 0.97}]
    }`

	head, tails := Split(decode(t, report), "", []string{"groups", "failed"}, 50)
	obj := head.(map[string]any)

	if _, ok := obj["groups"]; !ok {
		t.Error("groups was pulled out of the head")
	}
	if _, ok := obj["failed"]; !ok {
		t.Error("failed was pulled out of the head; an unreadable sample would go unnoticed")
	}
	if _, ok := tails["samples"]; !ok {
		t.Error("samples should be a tail")
	}
	if _, ok := tails["pairs"]; !ok {
		t.Error("pairs should be a tail")
	}
	if _, ok := tails["groups"]; ok {
		t.Error("groups became a tail as well")
	}
}

func TestSplitReachesNestedArrays(t *testing.T) {
	// --orphan-audit wraps its report one level down, and the islands are the
	// unbounded part.
	report := `{
      "roots_mode": "heuristic",
      "roots_manifest": 0,
      "roots_clinit": 412,
      "report": {
        "total_nodes": 9001,
        "orphan": 312,
        "islands": [{"size": 40}, {"size": 12}, {"size": 3}]
      }
    }`

	head, tails := Split(decode(t, report), "", nil, 2)
	obj := head.(map[string]any)

	if obj["roots_mode"] != "heuristic" {
		t.Errorf("roots_mode = %v, want it inline: a heuristic measure is not comparable with a manifest one", obj["roots_mode"])
	}
	inner, ok := obj["report"].(map[string]any)
	if !ok {
		t.Fatalf("report is %T, want the nested object kept", obj["report"])
	}
	if inner["orphan"] != float64(312) {
		t.Errorf("nested scalar lost: %v", inner["orphan"])
	}
	if _, present := inner["islands"]; present {
		t.Error("the nested array stayed in the head")
	}

	tail, ok := tails["report.islands"]
	if !ok {
		t.Fatalf("no tail for report.islands, tails were %v", keysOf(tails))
	}
	if tail.Total != 3 || tail.Returned != 2 || !tail.Truncated {
		t.Errorf("tail = %+v", tail)
	}
}

func TestSplitARootArray(t *testing.T) {
	// The rules pipeline prints its detections as a top-level array.
	head, tails := Split(decode(t, `[{"technique": "T1430"}, {"technique": "T1409"}]`), "detections", nil, 50)

	obj, ok := head.(map[string]any)
	if !ok || len(obj) != 0 {
		t.Errorf("head = %v, want an empty object", head)
	}
	tail, ok := tails["detections"]
	if !ok {
		t.Fatalf("no tail named detections, got %v", keysOf(tails))
	}
	if tail.Total != 2 {
		t.Errorf("total = %d", tail.Total)
	}
}

func TestSplitAScalarReport(t *testing.T) {
	head, tails := Split(decode(t, `{"package": "com.x", "version_code": "12"}`), "", nil, 50)
	obj := head.(map[string]any)

	if obj["package"] != "com.x" {
		t.Errorf("head = %v", obj)
	}
	if len(tails) != 0 {
		t.Errorf("tails = %v, want none", keysOf(tails))
	}
}

func TestClampRows(t *testing.T) {
	if got := ClampRows(nil); got != DefaultMaxRows {
		t.Errorf("ClampRows(nil) = %d, want %d", got, DefaultMaxRows)
	}
	zero := 0
	if got := ClampRows(&zero); got != DefaultMaxRows {
		t.Errorf("ClampRows(0) = %d, want the default", got)
	}
	negative := -5
	if got := ClampRows(&negative); got != DefaultMaxRows {
		t.Errorf("ClampRows(-5) = %d, want the default", got)
	}
	huge := 1 << 20
	if got := ClampRows(&huge); got != maxMaxRows {
		t.Errorf("ClampRows(huge) = %d, want %d", got, maxMaxRows)
	}
	ten := 10
	if got := ClampRows(&ten); got != 10 {
		t.Errorf("ClampRows(10) = %d", got)
	}
}

func keysOf(m map[string]Tail) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
