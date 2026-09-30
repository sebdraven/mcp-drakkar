// Package service turns one Drakkar mode into one answer: it resolves the paths
// against the corpus perimeter, builds the command line through the flag
// whitelist, runs it under a bounded timeout, and shapes the output into the
// common envelope.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-drakkar/internal/corpus"
	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
	"github.com/sebdraven/mcp-drakkar/internal/version"
)

// Timeouts are bounded per class of mode, because the classes differ by orders
// of magnitude: a string dump is seconds, an all-against-all matrix over 115
// samples is not, and a damaged DEX can spin for a long time on its own.
type Timeouts struct {
	Fast   time.Duration
	Diff   time.Duration
	Matrix time.Duration
	Bulk   time.Duration
}

func DefaultTimeouts() Timeouts {
	return Timeouts{
		Fast:   2 * time.Minute,
		Diff:   10 * time.Minute,
		Matrix: time.Hour,
		Bulk:   time.Hour,
	}
}

// FromEnv reads the per-class overrides, each a Go duration such as 90s or 45m.
func (t Timeouts) FromEnv() Timeouts {
	t.Fast = durationEnv("DRAKKAR_TIMEOUT_FAST", t.Fast)
	t.Diff = durationEnv("DRAKKAR_TIMEOUT_DIFF", t.Diff)
	t.Matrix = durationEnv("DRAKKAR_TIMEOUT_MATRIX", t.Matrix)
	t.Bulk = durationEnv("DRAKKAR_TIMEOUT_BULK", t.Bulk)
	return t
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

type Service struct {
	scope    *corpus.Scope
	timeouts Timeouts

	mu      sync.Mutex
	version string
}

func New(scope *corpus.Scope, t Timeouts) *Service {
	return &Service{scope: scope, timeouts: t}
}

// Scope exposes the perimeter so the server can report it at startup.
func (s *Service) Scope() *corpus.Scope { return s.scope }

// timeout picks the class timeout unless the caller overrode it.
func (s *Service) timeout(class time.Duration, override *int) time.Duration {
	if override != nil && *override > 0 {
		return time.Duration(*override) * time.Second
	}
	return class
}

// begin creates this invocation's output directory. Every mode gets one, even
// the ones that write nothing, so that a report always has somewhere to land.
func (s *Service) begin(tool string) (*corpus.Run, error) {
	return s.scope.NewRun(tool)
}

// invoke runs the assembled command line with the run directory as the child's
// working directory, so that a relative path Drakkar defaults to on its own
// lands there rather than wherever the MCP client happened to start the server.
func (s *Service) invoke(ctx context.Context, run *corpus.Run, timeout time.Duration, args *drakkar.Args) (*Envelope, *drakkar.Result, error) {
	return s.invokeIn(ctx, run.Dir, timeout, args)
}

// invokeIn is the same for the two modes that need no output directory at all,
// and must therefore keep working when none is configured: --version and
// --legend. Being able to ask what is wired up is most useful precisely when
// nothing is.
func (s *Service) invokeIn(ctx context.Context, workDir string, timeout time.Duration, args *drakkar.Args) (*Envelope, *drakkar.Result, error) {
	argv, err := args.Argv()
	if err != nil {
		return nil, nil, err
	}
	runner := drakkar.NewRunner(workDir)
	res, err := runner.Run(ctx, timeout, argv)
	if err != nil {
		return nil, nil, err
	}

	meta := Meta{
		Server:          version.Version,
		Version:         s.drakkarVersion(ctx, runner),
		Tested:          version.DrakkarTested,
		Argv:            res.Argv,
		ExitCode:        res.ExitCode,
		DurationMS:      res.DurationMS,
		TimedOut:        res.TimedOut,
		StdoutTruncated: res.StdoutTruncated,
	}
	env := &Envelope{
		Drakkar: meta,
		Stderr:  drakkar.ParseDiag(res.Stderr, res.StderrTruncated),
	}
	if res.TimedOut {
		env.note(fmt.Sprintf("timed out after %s and was killed; stdout and stderr are what the child had already written, not a complete run", timeout))
	}
	if res.StdoutTruncated {
		env.note("stdout hit the capture ceiling and was cut; the report on disk, if any, is complete but what was parsed here is not")
	}
	if res.StderrTruncated {
		env.note("stderr hit the capture ceiling and was cut; the marker counts below are lower bounds")
	}
	if res.ExitCode != 0 && !res.TimedOut {
		env.note(fmt.Sprintf("drakkar exited %d; read stderr.text before reading anything else", res.ExitCode))
	}
	if n := env.Stderr.FailedEntries(); n > 0 {
		env.note(fmt.Sprintf("%d entry/entries failed; they are named in stderr.failures and are absent from the counts below", n))
	}
	return env, res, nil
}

func (s *Service) drakkarVersion(ctx context.Context, runner *drakkar.Runner) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != "" {
		return s.version
	}
	v, err := runner.Version(ctx)
	if err != nil {
		return ""
	}
	s.version = v
	return v
}

// RefreshVersion forgets the cached `drakkar --version`, for drakkar_version.
func (s *Service) RefreshVersion() {
	s.mu.Lock()
	s.version = ""
	s.mu.Unlock()
}

// finishJSON reads the report Drakkar wrote and splits it into head and tails.
func (s *Service) finishJSON(env *Envelope, path, rootName string, inline []string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			env.note("no JSON report was produced, which is consistent with the exit code above")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	head, tails := Split(doc, rootName, inline, maxRows)
	env.Result = head
	if len(tails) > 0 {
		env.Tails = tails
	}
	env.ReportPath = path
	return nil
}

// finishJSONStdout is the same, for the one mode that prints its JSON instead of
// writing it: the rules pipeline. The document is written out here so that a
// report path exists for it too.
func (s *Service) finishJSONStdout(env *Envelope, run *corpus.Run, stdout []byte, rootName string, inline []string, maxRows int) error {
	if len(strings.TrimSpace(string(stdout))) == 0 {
		env.note("nothing on stdout")
		return nil
	}
	var doc any
	if err := json.Unmarshal(stdout, &doc); err != nil {
		return fmt.Errorf("parsing the JSON Drakkar printed: %w", err)
	}
	path, err := run.Path("report.json")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, stdout, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	head, tails := Split(doc, rootName, inline, maxRows)
	env.Result = head
	if len(tails) > 0 {
		env.Tails = tails
	}
	env.ReportPath = path
	return nil
}

// finishTable parses a TSV stdout, writes the whole row set to disk and puts a
// declared preview in the envelope.
func (s *Service) finishTable(env *Envelope, run *corpus.Run, stdout []byte, maxRows int) (*drakkar.Table, error) {
	table, err := drakkar.ParseTable(stdout)
	if err != nil {
		env.note(fmt.Sprintf("no table could be read from stdout: %v", err))
		return nil, nil
	}
	objects := table.Objects()

	path, err := run.Path("rows.json")
	if err != nil {
		return nil, err
	}
	if err := writeJSON(path, map[string]any{
		"header":    table.Header,
		"rows":      objects,
		"malformed": table.Malformed,
	}); err != nil {
		return nil, err
	}

	n := maxRows
	if n > len(objects) {
		n = len(objects)
	}
	items := make([]any, 0, n)
	for _, o := range objects[:n] {
		items = append(items, o)
	}
	env.Rows = &RowSet{
		Header:    table.Header,
		Total:     len(objects),
		Returned:  len(items),
		Truncated: len(items) < len(objects),
		Malformed: len(table.Malformed),
		Items:     items,
	}
	env.ReportPath = path
	if len(table.Malformed) > 0 {
		env.note(fmt.Sprintf("%d line(s) did not match the header's field count and were set aside in %s rather than reinterpreted", len(table.Malformed), path))
	}
	return table, nil
}

// finishLines handles the one output that is a bare list with no header.
func (s *Service) finishLines(env *Envelope, run *corpus.Run, stdout []byte, maxRows int) error {
	lines := drakkar.ParseLines(stdout)
	path, err := run.Path("lines.json")
	if err != nil {
		return err
	}
	if err := writeJSON(path, lines); err != nil {
		return err
	}
	n := maxRows
	if n > len(lines) {
		n = len(lines)
	}
	items := make([]any, 0, n)
	for _, l := range lines[:n] {
		items = append(items, l)
	}
	env.Rows = &RowSet{
		Total:     len(lines),
		Returned:  len(items),
		Truncated: len(items) < len(lines),
		Items:     items,
	}
	env.ReportPath = path
	return nil
}

// finishText keeps a text-only mode's stdout: written to disk in full, and
// returned inline only up to a ceiling, declared.
func (s *Service) finishText(env *Envelope, run *corpus.Run, stdout []byte) error {
	const inlineTextMax = 64 << 10
	path, err := run.Path("output.txt")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, stdout, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	text := string(stdout)
	truncated := false
	if len(text) > inlineTextMax {
		text = text[:inlineTextMax]
		truncated = true
	}
	env.Result = map[string]any{
		"text":      text,
		"bytes":     len(stdout),
		"truncated": truncated,
	}
	env.ReportPath = path
	if truncated {
		env.note(fmt.Sprintf("only the first %d bytes of the text output are inline; the whole of it is at %s", inlineTextMax, path))
	}
	return nil
}

// listWritten records what a mode that extracts files actually put on disk.
func (s *Service) listWritten(env *Envelope, dir string) {
	const maxListed = 500
	var found []string
	truncated := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if len(found) >= maxListed {
			truncated = true
			return fs.SkipAll
		}
		found = append(found, p)
		return nil
	})
	if err != nil {
		env.note(fmt.Sprintf("could not list what was written under %s: %v", dir, err))
		return
	}
	env.Written = found
	if truncated {
		env.note(fmt.Sprintf("more than %d files were written; only the first are listed, all of them are under %s", maxListed, dir))
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
