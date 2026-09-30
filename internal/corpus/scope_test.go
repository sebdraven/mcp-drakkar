package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// layout builds a corpus root, a directory outside it, and a sample in each. The
// root name carries a space on purpose: the paths this server is given contain
// them, and an escaping bug would show up here first.
func layout(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "pCloud Drive", "corpus")
	outside = filepath.Join(base, "elsewhere")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "a sample.apk"), "PK")
	write(t, filepath.Join(outside, "secret.apk"), "PK")
	return root, outside
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFileInsideTheCorpusIsAccepted(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root}, t.TempDir())

	got, err := s.File(filepath.Join(root, "a sample.apk"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "a sample.apk") {
		t.Errorf("resolved to %q", got)
	}
}

func TestFileOutsideTheCorpusIsRefused(t *testing.T) {
	root, outside := layout(t)
	s := New([]string{root}, t.TempDir())

	_, err := s.File(filepath.Join(outside, "secret.apk"))
	if err == nil {
		t.Fatal("a path outside the corpus was accepted")
	}
	if !strings.Contains(err.Error(), "outside the configured corpus") {
		t.Errorf("error should say why, got %q", err)
	}
}

func TestDotDotEscapeIsRefused(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root}, t.TempDir())

	if _, err := s.File(filepath.Join(root, "..", "..", "elsewhere", "secret.apk")); err == nil {
		t.Fatal("a .. traversal was accepted")
	}
}

func TestSymlinkEscapeIsRefused(t *testing.T) {
	// This is what EvalSymlinks buys: a link planted inside the corpus otherwise
	// names any file on the machine while passing a textual containment check.
	root, outside := layout(t)
	link := filepath.Join(root, "innocent.apk")
	if err := os.Symlink(filepath.Join(outside, "secret.apk"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := New([]string{root}, t.TempDir())

	if _, err := s.File(link); err == nil {
		t.Fatal("a symlink pointing out of the corpus was followed and accepted")
	}
}

func TestSymlinkedRootStillWorks(t *testing.T) {
	// The roots are resolved too, so a corpus reached through a link — which is
	// what a temporary directory on macOS is — does not refuse its own files.
	root, _ := layout(t)
	base := t.TempDir()
	linkedRoot := filepath.Join(base, "link-to-corpus")
	if err := os.Symlink(root, linkedRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := New([]string{linkedRoot}, base)

	if _, err := s.File(filepath.Join(linkedRoot, "a sample.apk")); err != nil {
		t.Fatalf("a file under a symlinked root was refused: %v", err)
	}
}

func TestFileRefusesADirectoryAndDirRefusesAFile(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root}, t.TempDir())

	if _, err := s.File(root); err == nil {
		t.Error("a directory was accepted where a file was expected")
	}
	if _, err := s.Dir(filepath.Join(root, "a sample.apk")); err == nil {
		t.Error("a file was accepted where a directory was expected")
	}
}

func TestMissingPathIsRefused(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root}, t.TempDir())

	if _, err := s.File(filepath.Join(root, "absent.apk")); err == nil {
		t.Error("a path that does not exist was accepted")
	}
}

func TestUnconfiguredCorpusSaysWhatToSet(t *testing.T) {
	s := New(nil, "")

	_, err := s.File("/anything")
	if err == nil {
		t.Fatal("a path was accepted with no corpus configured")
	}
	if !strings.Contains(err.Error(), EnvCorpus) {
		t.Errorf("error should name the variable to set, got %q", err)
	}

	if _, err := s.ReportsDir(); err == nil {
		t.Error("an unconfigured reports directory was accepted")
	} else if !strings.Contains(err.Error(), EnvReports) {
		t.Errorf("error should name the variable to set, got %q", err)
	}
}

func TestUnusableRootIsRecordedNotDropped(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root, filepath.Join(root, "does-not-exist")}, t.TempDir())

	if len(s.Roots()) != 1 {
		t.Errorf("roots = %v, want only the usable one", s.Roots())
	}
	if len(s.BadRoots()) != 1 {
		t.Fatalf("bad roots = %v, want the unusable one recorded", s.BadRoots())
	}
}

func TestFilesReportsEveryRejectionAtOnce(t *testing.T) {
	root, outside := layout(t)
	s := New([]string{root}, t.TempDir())

	_, err := s.Files([]string{
		filepath.Join(outside, "secret.apk"),
		filepath.Join(root, "absent.apk"),
	})
	if err == nil {
		t.Fatal("expected both inputs to be refused")
	}
	if !strings.Contains(err.Error(), "secret.apk") || !strings.Contains(err.Error(), "absent.apk") {
		t.Errorf("both rejections should be named, got %q", err)
	}
}

func TestNewRunCreatesAFreshDirectoryUnderReports(t *testing.T) {
	root, _ := layout(t)
	reports := t.TempDir()
	s := New([]string{root}, reports)

	first, err := s.NewRun("diff_dex")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.NewRun("diff_dex")
	if err != nil {
		t.Fatal(err)
	}
	if first.Dir == second.Dir {
		t.Error("two runs shared a directory; one would overwrite the other's report")
	}
	for _, r := range []*Run{first, second} {
		info, err := os.Stat(r.Dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("run directory %s not created: %v", r.Dir, err)
		}
		real, err := filepath.EvalSymlinks(r.Dir)
		if err != nil {
			t.Fatal(err)
		}
		realReports, err := filepath.EvalSymlinks(reports)
		if err != nil {
			t.Fatal(err)
		}
		if !within(realReports, real) {
			t.Errorf("run directory %s is not under the reports root %s", real, realReports)
		}
	}
}

func TestRunPathRefusesAnythingButAPlainName(t *testing.T) {
	root, _ := layout(t)
	s := New([]string{root}, t.TempDir())
	run, err := s.NewRun("t")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := run.Path("report.json"); err != nil {
		t.Errorf("a plain name was refused: %v", err)
	}
	for _, bad := range []string{"", "..", ".", "sub/report.json", "../escape.json", "/etc/passwd"} {
		if _, err := run.Path(bad); err == nil {
			t.Errorf("%q was accepted as a file name", bad)
		}
	}
}

func TestSafeNameKeepsRunDirectoriesTame(t *testing.T) {
	if got := safeName("resources_xref"); got != "resources_xref" {
		t.Errorf("safeName = %q", got)
	}
	if got := safeName("../../etc"); strings.Contains(got, "/") || strings.Contains(got, ".") {
		t.Errorf("safeName = %q, want no separators", got)
	}
	if got := safeName(""); got == "" {
		t.Error("safeName produced an empty directory name")
	}
}
