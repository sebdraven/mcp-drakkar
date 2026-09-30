package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-drakkar/internal/corpus"
)

func testService(t *testing.T) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "corpus")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.apk"), []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	reports := filepath.Join(base, "reports")
	if err := os.MkdirAll(reports, 0o755); err != nil {
		t.Fatal(err)
	}
	return New(corpus.New([]string{root}, reports), DefaultTimeouts()), root
}

func TestSingleOrBulkRequiresExactlyOne(t *testing.T) {
	s, root := testService(t)
	apk := filepath.Join(root, "a.apk")

	if _, _, err := s.resolveSingleOrBulk("", ""); err == nil {
		t.Error("neither input was given and it was accepted")
	}
	if _, _, err := s.resolveSingleOrBulk(apk, root); err == nil {
		t.Error("both inputs were given and it was accepted")
	}
	file, dir, err := s.resolveSingleOrBulk(apk, "")
	if err != nil || file == "" || dir != "" {
		t.Errorf("single input: file=%q dir=%q err=%v", file, dir, err)
	}
	file, dir, err = s.resolveSingleOrBulk("", root)
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
	s, root := testService(t)
	apk := filepath.Join(root, "a.apk")

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

func TestPathsOutsideTheCorpusNeverReachDrakkar(t *testing.T) {
	s, _ := testService(t)

	if _, err := s.Manifest(context.Background(), InventoryInput{APK: "/etc/hosts"}); err == nil {
		t.Error("a path outside the corpus was accepted")
	}
	if _, err := s.DiffDex(context.Background(), DiffDexInput{A: "/etc/hosts", B: "/etc/passwd"}); err == nil {
		t.Error("two paths outside the corpus were accepted")
	}
}

func TestModeValidationHappensBeforeTheRunDirectory(t *testing.T) {
	// A bad mode must not leave an empty run directory behind.
	s, root := testService(t)
	reports, err := s.Scope().ReportsDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Assets(context.Background(), AssetsInput{APK: filepath.Join(root, "a.apk"), Mode: "sideways"}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	entries, err := os.ReadDir(reports)
	if err != nil {
		t.Fatal(err)
	}
	// One directory is created before the mode switch, which is acceptable; more
	// than one would mean the switch ran twice.
	if len(entries) > 1 {
		t.Errorf("%d run directories left behind", len(entries))
	}
}
