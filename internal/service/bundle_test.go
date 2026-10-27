package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bundleSHA = "cdc1a0b585d169e862d637e0152268cafd9ed55d71de6cf86f4bd551c989f5a9"

func TestBundleRootIsReadFromTheOKLine(t *testing.T) {
	out := "/corpus/pCloud Drive/bundles — v2"
	stderr := "2026-10-27T10:00:00Z  INFO manifest-validated entrypoints\n" +
		"[OK]    " + out + "/" + bundleSHA + " — 412 classes, 3120 méthodes (ok 3000, partial 100, failed 20), 3 erreur(s)\n"
	root, ok := bundleRoot(stderr, out)
	if !ok {
		t.Fatal("the root was not found")
	}
	if want := out + "/" + bundleSHA; root != want {
		t.Errorf("root = %q, want %q", root, want)
	}
}

func TestBundleRootRefusesAnotherDirectoryOrAShortHash(t *testing.T) {
	for _, line := range []string{
		"[OK]    /elsewhere/" + bundleSHA + " — 1 classes",
		"[OK]    /out/" + bundleSHA[:12] + " — 1 classes",
		"[OK]    /out/" + bundleSHA,
	} {
		if root, ok := bundleRoot(line, "/out"); ok {
			t.Errorf("%q was accepted as %q", line, root)
		}
	}
}

func TestDecompileSummaryReadsTheThreeCounts(t *testing.T) {
	stderr := "[OK]    7 classe(s) décompilée(s) sur 412 lues, 2 en repli méthode par méthode\n"
	got, ok := decompileSummary(stderr)
	if !ok || got != [3]int{7, 412, 2} {
		t.Errorf("summary = %v, %v", got, ok)
	}
	if _, ok := decompileSummary("[OK]    7 classe(s) désassemblée(s) sur 412 lues\n"); ok {
		t.Error("the --disasm line was read as the --decompile one")
	}
}

func TestReleaseComparison(t *testing.T) {
	for v, older := range map[string]bool{
		"drakkar 0.1.0":       true,
		"drakkar 0.2.0":       false,
		"drakkar 0.2.1":       false,
		"drakkar 1.0.0-rc1":   false,
		"drakkar 0.10.0":      false,
		"drakkar 0.1.9+local": true,
	} {
		r, ok := releaseOf(v)
		if !ok {
			t.Errorf("%q was not parsed", v)
			continue
		}
		if got := olderThan(r, minBundleRelease); got != older {
			t.Errorf("%q older than 0.2.0 = %v, want %v", v, got, older)
		}
	}
	if _, ok := releaseOf(""); ok {
		t.Error("an empty version was parsed")
	}
}

func TestClassFileIsZeroPaddedToSixDigits(t *testing.T) {
	if got := classFile("/b", 42, "class.java"); got != filepath.Join("/b", "classes", "000042.class.java") {
		t.Errorf("got %q", got)
	}
	if got := classFile("/b", 1234567, "dasm"); got != filepath.Join("/b", "classes", "1234567.dasm") {
		t.Errorf("got %q", got)
	}
}

func TestTruncateCharsNeverCutsACharacter(t *testing.T) {
	got, truncated := truncateChars("décompilé", 2)
	if got != "dé" || !truncated {
		t.Errorf("got %q, %v", got, truncated)
	}
	got, truncated = truncateChars("abc", 3)
	if got != "abc" || truncated {
		t.Errorf("got %q, %v", got, truncated)
	}
}

const bundleIndex = `[
  {"id": 0, "descriptor": "Lcom/a/Main;", "dex": "classes.dex", "package": "com.a", "origin": "app", "methods": 3,
   "rules_direct": ["T1437"], "rules_path": [], "decompile_status": "ok", "class_java": "ok"},
  {"id": 1, "descriptor": "Landroidx/core/X;", "dex": "classes.dex", "package": "androidx.core", "origin": "lib", "methods": 1,
   "rules_direct": [], "rules_path": ["T1437"], "decompile_status": "partial", "class_java": "failed"},
  {"id": 2, "descriptor": "Lcom/a/Main;", "dex": "classes2.dex", "package": "com.a", "origin": "app", "methods": 0,
   "rules_direct": [], "rules_path": [], "decompile_status": "failed", "class_java": "failed"},
  {"id": 3, "descriptor": null, "dex": "classes2.dex", "package": null, "origin": null, "methods": 0,
   "rules_direct": [], "rules_path": [], "decompile_status": "failed", "class_java": "failed"}
]`

func decodeIndex(t *testing.T) []map[string]any {
	t.Helper()
	var index []map[string]any
	if err := json.Unmarshal([]byte(bundleIndex), &index); err != nil {
		t.Fatal(err)
	}
	return index
}

func TestRulesPathDoesNotCountAsADirectCitation(t *testing.T) {
	yes := true
	got := filterIndex(decodeIndex(t), indexFilter{hasRulesDirect: &yes, origin: "app"})
	if len(got) != 1 || got[0].(map[string]any)["id"] != float64(0) {
		t.Errorf("got %v", got)
	}
}

func TestPackagePrefixSkipsUnreadableDescriptors(t *testing.T) {
	got := filterIndex(decodeIndex(t), indexFilter{packagePrefix: "com."})
	if len(got) != 2 {
		t.Errorf("got %d entries, want the two com.a classes", len(got))
	}
}

func TestADescriptorDefinedTwiceMustBeAskedForByID(t *testing.T) {
	index := decodeIndex(t)
	_, _, err := findClass(index, nil, "Lcom/a/Main;")
	if err == nil || !strings.Contains(err.Error(), "by id") {
		t.Errorf("err = %v", err)
	}
	two := 2
	if _, id, err := findClass(index, &two, ""); err != nil || id != 2 {
		t.Errorf("id = %d, err = %v", id, err)
	}
	missing := 99
	if _, _, err := findClass(index, &missing, ""); err == nil {
		t.Error("an id absent from index.json was accepted")
	}
}

func TestAPartThatLinksOutOfTheBundleIsRefused(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "classes"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := classFile(root, 0, "java")
	if err := os.Symlink(secret, link); err != nil {
		t.Skip(err)
	}
	if _, err := readPart(root, link, 10); err == nil {
		t.Error("a part resolving outside the bundle was read")
	}
}

func TestAnAbsentPartIsReportedNotFailed(t *testing.T) {
	root := t.TempDir()
	part, err := readPart(root, classFile(root, 1, "class.java"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if part["present"] != false {
		t.Errorf("part = %v", part)
	}
}

func TestSHA256FileIsWholeAndLowercase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("sha256 = %q, want %q", got, want)
	}
}

func TestBundleRootByHashNeedsAMatchingBundleJSON(t *testing.T) {
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	root := filepath.Join(out, abc)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, ok := bundleRootByHash(&Envelope{}, input, out); ok {
		t.Error("a directory without bundle.json was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), []byte(`{"sha256": "`+bundleSHA+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := bundleRootByHash(&Envelope{}, input, out); ok {
		t.Error("a bundle.json naming another sha256 was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), []byte(`{"sha256": "`+abc+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := &Envelope{}
	env.Stderr.Truncated = true
	got, ok := bundleRootByHash(env, input, out)
	if !ok || got != root {
		t.Fatalf("root = %q, %v", got, ok)
	}
	if len(env.Notes) != 1 || !strings.Contains(env.Notes[0], "truncated") {
		t.Errorf("notes = %q", env.Notes)
	}
}

func TestErrorsForMatchesTheClassID(t *testing.T) {
	root := t.TempDir()
	body := `[
  {"stage": "decompile_class", "dex": "classes.dex", "class_id": 42, "target": "Lcom/a/B;", "error": "x"},
  {"stage": "rules", "dex": null, "class_id": null, "target": null, "error": "y"},
  {"stage": "class", "dex": "classes.dex", "class_id": 7, "target": null, "error": "z"}
]`
	if err := os.WriteFile(filepath.Join(root, "errors.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := errorsFor(root, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].(map[string]any)["stage"] != "decompile_class" {
		t.Errorf("got %v", got)
	}
}

func TestUnknownPartIsRefused(t *testing.T) {
	if _, err := selectParts([]string{"smali"}); err == nil {
		t.Error("an unknown part was accepted")
	}
	parts, err := selectParts([]string{"methods", "java"})
	if err != nil || len(parts) != 2 || parts[0].name != "java" {
		t.Errorf("parts = %v, err = %v", parts, err)
	}
}
