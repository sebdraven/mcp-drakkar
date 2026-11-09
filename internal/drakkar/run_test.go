package drakkar

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// stubRunner points a Runner at a shell script standing in for drakkar. exec
// matters in the scripts below: the kill has to reach the process holding the
// pipes, not a shell waiting on it.
func stubRunner(t *testing.T, script string) *Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub drakkar is a shell script")
	}
	path := filepath.Join(t.TempDir(), "drakkar")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(t.TempDir())
	r.Bin = path
	return r
}

func TestRunCancelledMidwayIsNamedNotAnError(t *testing.T) {
	r := stubRunner(t, "echo started\nexec sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(300*time.Millisecond, cancel)

	res, err := r.Run(ctx, time.Minute, nil)
	if err != nil {
		t.Fatalf("a cancellation came back as a Go error: %v", err)
	}
	if !res.Cancelled || res.TimedOut {
		t.Errorf("Cancelled=%v TimedOut=%v, want true and false", res.Cancelled, res.TimedOut)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1", res.ExitCode)
	}
	if string(res.Stdout) != "started\n" {
		t.Errorf("stdout = %q, want what the child wrote before it was killed", res.Stdout)
	}
}

func TestRunTimeoutIsNotACancellation(t *testing.T) {
	r := stubRunner(t, "exec sleep 30\n")

	res, err := r.Run(context.Background(), 200*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("a timeout came back as a Go error: %v", err)
	}
	if !res.TimedOut || res.Cancelled {
		t.Errorf("TimedOut=%v Cancelled=%v, want true and false", res.TimedOut, res.Cancelled)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1", res.ExitCode)
	}
}

func TestRunExitCodeIsData(t *testing.T) {
	r := stubRunner(t, "exit 3\n")

	res, err := r.Run(context.Background(), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.TimedOut || res.Cancelled {
		t.Errorf("ExitCode=%d TimedOut=%v Cancelled=%v, want 3, false, false", res.ExitCode, res.TimedOut, res.Cancelled)
	}
}
