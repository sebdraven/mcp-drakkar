package drakkar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Bin is the name looked up in PATH. This server never builds Drakkar and never
// downloads it: it invokes the one already installed, or it fails saying so.
const Bin = "drakkar"

// ErrNotInPath is returned when the binary cannot be found.
var ErrNotInPath = errors.New("drakkar not found in PATH")

type Runner struct {
	Bin       string
	WorkDir   string
	Env       []string
	MaxStdout int64
	MaxStderr int64
}

type Result struct {
	Argv            []string
	Stdout          []byte
	Stderr          string
	ExitCode        int
	DurationMS      int64
	TimedOut        bool
	StdoutTruncated bool
	StderrTruncated bool
}

const (
	defaultMaxStdout = 64 << 20
	defaultMaxStderr = 4 << 20
	// waitDelay bounds how long a killed child may keep the output pipes open.
	waitDelay = 5 * time.Second
)

func NewRunner(workDir string) *Runner {
	return &Runner{
		Bin:       Bin,
		WorkDir:   workDir,
		Env:       DefaultEnv(),
		MaxStdout: defaultMaxStdout,
		MaxStderr: defaultMaxStderr,
	}
}

// DefaultEnv builds the child environment explicitly instead of inheriting it.
// HOME is needed because Drakkar caches its generated rules under it; nothing
// else is forwarded, so no API token can reach the child even if one is set in
// the server's own environment.
func DefaultEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "RUST_LOG"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Lookup reports whether Drakkar is callable, with a message that says what to
// do about it rather than just naming the failure.
func (r *Runner) Lookup() (string, error) {
	name := r.Bin
	if name == "" {
		name = Bin
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: install Drakkar and restart the server with a PATH that contains it; this server never builds it: %w", ErrNotInPath, err)
	}
	return path, nil
}

// Run executes one Drakkar command line. A non-zero exit is data, not a Go
// error: it is reported in Result so the caller can hand back stdout, stderr and
// the code together. Only a failure to start is an error.
//
// On timeout the child is killed and whatever it had already written is still
// returned. Discarding partial output on the way out is how a scan gets read as
// a clean result.
func (r *Runner) Run(ctx context.Context, timeout time.Duration, argv []string) (*Result, error) {
	path, err := r.Lookup()
	if err != nil {
		return nil, err
	}

	maxOut := r.MaxStdout
	if maxOut <= 0 {
		maxOut = defaultMaxStdout
	}
	maxErr := r.MaxStderr
	if maxErr <= 0 {
		maxErr = defaultMaxStderr
	}

	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	out := &capped{limit: maxOut}
	errBuf := &capped{limit: maxErr}

	cmd := exec.CommandContext(runCtx, path, argv...)
	cmd.Dir = r.WorkDir
	cmd.Env = r.Env
	cmd.Stdout = out
	cmd.Stderr = errBuf
	cmd.WaitDelay = waitDelay

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	res := &Result{
		Argv:            append([]string{path}, argv...),
		Stdout:          out.buf.Bytes(),
		Stderr:          errBuf.buf.String(),
		DurationMS:      elapsed.Milliseconds(),
		TimedOut:        errors.Is(runCtx.Err(), context.DeadlineExceeded),
		StdoutTruncated: out.truncated,
		StderrTruncated: errBuf.truncated,
	}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	case res.TimedOut:
		res.ExitCode = -1
	default:
		return res, fmt.Errorf("running %s: %w", path, runErr)
	}
	return res, nil
}

// Version returns what `drakkar --version` prints, so that a measurement can
// say which Drakkar produced it.
func (r *Runner) Version(ctx context.Context) (string, error) {
	argv, err := New().Switch("--version").Argv()
	if err != nil {
		return "", err
	}
	res, err := r.Run(ctx, 15*time.Second, argv)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("drakkar --version exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// capped accumulates output up to a limit and records that it stopped. It always
// reports a full write so the child is never handed a short write it would read
// as a broken pipe.
type capped struct {
	buf       bytes.Buffer
	limit     int64
	written   int64
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.written
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > room {
		c.buf.Write(p[:room])
		c.written = c.limit
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	c.written += int64(len(p))
	return len(p), nil
}
