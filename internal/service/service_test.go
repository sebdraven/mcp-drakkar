package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The service needs no configuration now, so the helper only provides a
// directory to build absolute paths from.
func testService(t *testing.T) (*Service, string) {
	t.Helper()
	return New(DefaultTimeouts()), t.TempDir()
}

func TestSingleOrBulkRequiresExactlyOne(t *testing.T) {
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")

	if _, _, err := s.resolveSingleOrBulk("", ""); err == nil {
		t.Error("neither input was given and it was accepted")
	}
	if _, _, err := s.resolveSingleOrBulk(apk, base); err == nil {
		t.Error("both inputs were given and it was accepted")
	}
	file, dir, err := s.resolveSingleOrBulk(apk, "")
	if err != nil || file == "" || dir != "" {
		t.Errorf("single input: file=%q dir=%q err=%v", file, dir, err)
	}
	file, dir, err = s.resolveSingleOrBulk("", base)
	if err != nil || dir == "" || file != "" {
		t.Errorf("bulk input: file=%q dir=%q err=%v", file, dir, err)
	}
}

func TestTruncatedHashIsRefusedAndEchoedWhole(t *testing.T) {
	// A prefix silently accepted is how a hash filter comes back empty and gets
	// read as the absence of the asset.
	const short = "e65324f4430c2717"
	err := checkHashes("hashes", []string{short})
	if err == nil {
		t.Fatal("a 16-character hash was accepted")
	}
	if !strings.Contains(err.Error(), short) {
		t.Errorf("the offending value should appear in full, got %q", err)
	}
}

func TestWholeHashIsAccepted(t *testing.T) {
	const whole = "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a"
	if err := checkHashes("hashes", []string{whole}); err != nil {
		t.Errorf("a whole SHA-256 was refused: %v", err)
	}
	if err := checkHashes("hashes", []string{strings.ToUpper(whole)}); err != nil {
		t.Errorf("an upper-case SHA-256 was refused: %v", err)
	}
}

func TestNonHexHashIsRefused(t *testing.T) {
	bad := strings.Repeat("z", 64)
	if err := checkHashes("hashes", []string{bad}); err == nil {
		t.Error("a 64-character non-hex value was accepted")
	}
}

func TestNoHashesIsFine(t *testing.T) {
	if err := checkHashes("hashes", nil); err != nil {
		t.Errorf("an absent filter was refused: %v", err)
	}
}

func TestTimeoutOverride(t *testing.T) {
	s, _ := testService(t)

	if got := s.timeout(s.timeouts.Fast, nil); got != s.timeouts.Fast {
		t.Errorf("timeout = %v, want the class default", got)
	}
	ninety := 90
	if got := s.timeout(s.timeouts.Fast, &ninety); got != 90*time.Second {
		t.Errorf("timeout = %v, want 90s", got)
	}
	zero := 0
	if got := s.timeout(s.timeouts.Fast, &zero); got != s.timeouts.Fast {
		t.Errorf("timeout = %v, want the class default for a zero override", got)
	}
}

func TestTimeoutsFromEnv(t *testing.T) {
	t.Setenv("DRAKKAR_TIMEOUT_FAST", "45s")
	t.Setenv("DRAKKAR_TIMEOUT_MATRIX", "not a duration")

	got := DefaultTimeouts().FromEnv()
	if got.Fast != 45*time.Second {
		t.Errorf("Fast = %v, want 45s", got.Fast)
	}
	if got.Matrix != DefaultTimeouts().Matrix {
		t.Errorf("Matrix = %v, want the default kept when the value is unparseable", got.Matrix)
	}
}

func TestUnknownModesAreRefusedBeforeAnythingRuns(t *testing.T) {
	s, base := testService(t)
	apk := filepath.Join(base, "a.apk")

	if _, err := s.Resources(context.Background(), ResourcesInput{APK: apk, Mode: "sideways"}); err == nil {
		t.Error("an unknown resources mode was accepted")
	}
	if _, err := s.Assets(context.Background(), AssetsInput{APK: apk, Mode: "sideways"}); err == nil {
		t.Error("an unknown assets mode was accepted")
	}
	if _, err := s.Legend(context.Background(), LegendInput{Topic: "sideways"}); err == nil {
		t.Error("an unknown legend topic was accepted")
	}
}

func TestRelativePathsAreRefused(t *testing.T) {
	// Any absolute path is fair game — there is no perimeter. A relative one is
	// not, because it would resolve against the child's working directory, which
	// is this call's output directory and not the caller's shell.
	s, _ := testService(t)

	if _, err := s.Manifest(context.Background(), InventoryInput{APK: "sample.apk"}); err == nil {
		t.Error("a relative input was accepted")
	}
	if _, err := s.DiffDex(context.Background(), DiffDexInput{A: "a.apk", B: "/tmp/b.apk"}); err == nil {
		t.Error("a relative first input was accepted")
	}
	if _, err := s.DiffMatrix(context.Background(), DiffMatrixInput{Directory: "./corpus"}); err == nil {
		t.Error("a relative directory was accepted")
	}
	if _, err := s.Strings(context.Background(), StringsInput{Input: "/abs/a.apk", OutDir: "relative/out"}); err == nil {
		t.Error("a relative out_dir was accepted")
	}
}

func TestOutDirIsHonouredWhenGiven(t *testing.T) {
	s, base := testService(t)
	want := filepath.Join(base, "chosen", "nested")

	out, err := s.begin("t", want)
	if err != nil {
		t.Fatal(err)
	}
	if out.path != want {
		t.Errorf("out.path = %q, want %q", out.path, want)
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Errorf("the directory was not created: %v", err)
	}
}

func TestOmittedOutDirFallsBackToATemporaryDirectory(t *testing.T) {
	// Drakkar's own --out defaults to ./reports, relative to a working directory
	// nobody chose. The fallback has to be absolute and it has to be reportable.
	s, _ := testService(t)

	out, err := s.begin("diff_dex", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(out.path) })

	if !filepath.IsAbs(out.path) {
		t.Errorf("fallback %q is not absolute", out.path)
	}
	if info, err := os.Stat(out.path); err != nil || !info.IsDir() {
		t.Errorf("the fallback directory was not created: %v", err)
	}

	second, err := s.begin("diff_dex", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(second.path) })
	if second.path == out.path {
		t.Error("two calls shared a directory; one would overwrite the other's report")
	}
}

func TestOutDirRefusesAnythingButAPlainFileName(t *testing.T) {
	s, base := testService(t)
	out, err := s.begin("t", filepath.Join(base, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.file("report.json"); err != nil {
		t.Errorf("a plain name was refused: %v", err)
	}
	for _, bad := range []string{"", ".", "..", "sub/report.json", "../escape.json", "/etc/passwd"} {
		if _, err := out.file(bad); err == nil {
			t.Errorf("%q was accepted as a file name", bad)
		}
	}
}

// The shape of an --api-surface report: the root is an array even for a single
// sample, and every counter lives inside an entry rather than at the root. That
// is why this mode needs a finisher of its own.
const apiSurfaceReport = `[
  {
    "sample": "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9",
    "report": {
      "routes": [
        {"class": "Lcom/dri/agent/UserApi;", "method": "approve", "verb": "POST",
         "path": "/v1/users/auth/passwordless/{token}/approve", "visibility": "runtime"},
        {"class": "Lcom/dri/agent/DeviceApi;", "method": "list", "verb": "GET",
         "path": "/v1/devices", "visibility": "runtime"},
        {"class": "Lcom/dri/agent/BrandApi;", "method": "raw", "verb": null,
         "path": null, "visibility": ""}
      ],
      "fields": [
        {"class": "Lcom/dri/agent/model/Device;", "field": "a", "serialized": "device_id"}
      ],
      "stats": {"classes": 4000, "routes": 2, "annotations_seen": 5200, "other_annotations": 5100}
    }
  }
]`

func writeReport(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAPISurfaceHeadCarriesTheCountersAndTheArraysBecomeTails(t *testing.T) {
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishAPISurface(env, writeReport(t, apiSurfaceReport), 50); err != nil {
		t.Fatal(err)
	}

	head, ok := env.Result.(map[string]any)
	if !ok {
		t.Fatalf("head is %T, want an object", env.Result)
	}
	if head["routes_total"] != 3 || head["fields_total"] != 1 {
		t.Errorf("totals are %v / %v, want 3 / 1", head["routes_total"], head["fields_total"])
	}

	// other_annotations is the counter that separates "no annotations here" from
	// "thousands, none of them a route". Losing it is the whole reason this mode
	// does not go through finishTable.
	stats, ok := head["stats"].(map[string]float64)
	if !ok {
		t.Fatalf("stats is %T, want the summed counters", head["stats"])
	}
	if stats["other_annotations"] != 5100 {
		t.Errorf("other_annotations = %v, want 5100", stats["other_annotations"])
	}

	verbs, ok := head["per_verb"].(map[string]int)
	if !ok {
		t.Fatalf("per_verb is %T", head["per_verb"])
	}
	// The third route has no verb: it carries parameter annotations only, and
	// stats.params_only_methods is what counts it.
	if len(verbs) != 2 || verbs["POST"] != 1 || verbs["GET"] != 1 {
		t.Errorf("per_verb = %v, want one POST and one GET", verbs)
	}

	if env.Tails["routes"].Total != 3 || env.Tails["fields"].Total != 1 {
		t.Errorf("tails are %+v", env.Tails)
	}
	// A single sample must not be flattened into anonymity: the preview says
	// which sample each row came from, the way the TSV column does.
	first, ok := env.Tails["routes"].Items[0].(map[string]any)
	if !ok {
		t.Fatalf("tail item is %T", env.Tails["routes"].Items[0])
	}
	if first["sample"] != "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9" {
		t.Errorf("the whole sample name should be on the row, got %v", first["sample"])
	}
}

func TestAPISurfaceSumsUnknownCountersAcrossSamples(t *testing.T) {
	// A counter this server has never heard of still reaches the head: the stats
	// object is summed key by key, so a counter added upstream needs no change
	// here.
	const twoSamples = `[
  {"sample": "a", "report": {"routes": [], "fields": [], "stats": {"routes": 1, "brand_new": 7}}},
  {"sample": "b", "report": {"routes": [], "fields": [], "stats": {"routes": 2, "brand_new": 5}}}
]`
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishAPISurface(env, writeReport(t, twoSamples), 50); err != nil {
		t.Fatal(err)
	}
	head := env.Result.(map[string]any)
	stats := head["stats"].(map[string]float64)
	if stats["brand_new"] != 12 || stats["routes"] != 3 {
		t.Errorf("stats = %v, want brand_new 12 and routes 3", stats)
	}
	if head["samples"] != 2 {
		t.Errorf("samples = %v, want 2", head["samples"])
	}
	if _, ok := head["per_sample"]; !ok {
		t.Error("per_sample should be present in bulk")
	}
}

func TestAPISurfaceSaysAnEmptyAnswerIsNotAnAbsenceOfRoutes(t *testing.T) {
	const noRoutes = `[{"sample": "a", "report": {"routes": [], "fields": [], "stats": {}}}]`
	s, _ := testService(t)
	env := &Envelope{}
	if err := s.finishAPISurface(env, writeReport(t, noRoutes), 50); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env.Notes, " ")
	if !strings.Contains(joined, "repackaged") {
		t.Errorf("an empty answer must be explained, notes were %v", env.Notes)
	}
}
