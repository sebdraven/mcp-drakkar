package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// earlierRun leaves out/ under outDir as a previous bulk run would.
func earlierRun(t *testing.T, outDir string, reports ...string) string {
	t.Helper()
	dir := filepath.Join(outDir, "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range reports {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"earlier": true}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestBulkIntoANonEmptyOutIsRefused(t *testing.T) {
	s, base := testService(t)
	corpus := filepath.Join(base, "corpus")
	ctx := context.Background()

	calls := map[string]func(outDir string) error{
		"manifest": func(o string) error {
			_, err := s.Manifest(ctx, InventoryInput{Directory: corpus, OutDir: o})
			return err
		},
		"orphan_audit": func(o string) error {
			_, err := s.OrphanAudit(ctx, OrphanAuditInput{Directory: corpus, OutDir: o})
			return err
		},
		// With overwrite nothing is resumed, so a non-empty out/ is a mix.
		"scan_overwrite": func(o string) error {
			_, err := s.Scan(ctx, ScanInput{Directory: corpus, OutDir: o, Overwrite: true})
			return err
		},
	}
	for name, call := range calls {
		outDir := filepath.Join(base, name)
		dir := earlierRun(t, outDir, "a.json")
		err := call(outDir)
		if err == nil {
			t.Errorf("%s: a bulk run into a non-empty %s was accepted", name, dir)
			continue
		}
		if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "another out_dir") {
			t.Errorf("%s: the refusal should name %s and point to another out_dir, got %q", name, dir, err)
		}
	}
}

func TestBulkIntoAnEmptyOutIsAccepted(t *testing.T) {
	stubDrakkar(t, "exit 0\n")
	s, base := testService(t)
	outDir := filepath.Join(base, "run")
	earlierRun(t, outDir)

	if _, err := s.Manifest(context.Background(), InventoryInput{Directory: filepath.Join(base, "corpus"), OutDir: outDir}); err != nil {
		t.Errorf("an empty out/ was refused: %v", err)
	}
}

func TestScanWithoutOverwriteResumesAndSaysSo(t *testing.T) {
	stubDrakkar(t, "exit 0\n")
	s, base := testService(t)
	outDir := filepath.Join(base, "run")
	dir := earlierRun(t, outDir, "a.json", "b.json")

	env, err := s.Scan(context.Background(), ScanInput{Directory: filepath.Join(base, "corpus"), OutDir: outDir})
	if err != nil {
		t.Fatalf("a resumed scan was refused: %v", err)
	}
	joined := strings.Join(env.Notes, " ")
	if !strings.Contains(joined, "2 report(s) were already under "+dir) || !strings.Contains(joined, "rather than recomputing") {
		t.Errorf("notes = %v, want the resumed reports counted and named as not recomputed", env.Notes)
	}
	if got := env.Tails["samples"].Total; got != 2 {
		t.Errorf("samples total = %d, want the 2 resumed reports", got)
	}
}
