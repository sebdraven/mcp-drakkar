package drakkar

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestCompatibilityFlags(t *testing.T) {
	bin := os.Getenv("DRAKKAR_COMPAT_BIN")
	if bin == "" {
		t.Skip("set DRAKKAR_COMPAT_BIN to an absolute Drakkar binary path")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("DRAKKAR_COMPAT_BIN must be absolute")
	}
	runner := NewRunner(t.TempDir())
	runner.Bin = bin
	result, err := runner.Run(context.Background(), 15*time.Second, []string{"--help"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.StdoutTruncated {
		t.Fatalf("incomplete help: exit %d: %s", result.ExitCode, result.Stderr)
	}
	for flag := range known {
		pattern := `(?m)(?:^|\s)` + regexp.QuoteMeta(flag) + `(?:\s|=|\[|$)`
		if !regexp.MustCompile(pattern).Match(result.Stdout) {
			t.Errorf("whitelisted flag %s is absent from Drakkar's help", flag)
		}
	}
}
