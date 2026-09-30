// Package corpus confines the server to a declared set of directories: inputs
// are read only from the configured corpus roots, and nothing is ever written
// outside the configured reports directory.
//
// The inputs are live malware samples. The point is not to protect Drakkar from
// a bad path, it is to make a path outside the corpus unreachable through this
// server at all.
package corpus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	EnvCorpus  = "DRAKKAR_CORPUS_DIRS"
	EnvReports = "DRAKKAR_REPORTS_DIR"
)

type Scope struct {
	roots    []string
	badRoots []string
	reports  string
	badRepo  string
}

// FromEnv reads the perimeter from the environment. Missing configuration is
// not fatal: the server starts, and every tool that takes a path refuses with a
// message naming what to set. A server that refuses to start tells the user
// nothing they can act on from inside their MCP client.
func FromEnv() *Scope {
	return New(filepath.SplitList(os.Getenv(EnvCorpus)), os.Getenv(EnvReports))
}

func New(corpusDirs []string, reportsDir string) *Scope {
	s := &Scope{}
	for _, d := range corpusDirs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		real, err := resolveExisting(d)
		if err != nil {
			// Recorded, never dropped: an unreadable root would otherwise make
			// every sample under it look like a path outside the perimeter.
			s.badRoots = append(s.badRoots, fmt.Sprintf("%s (%v)", d, err))
			continue
		}
		s.roots = append(s.roots, real)
	}
	if strings.TrimSpace(reportsDir) != "" {
		real, err := resolveExisting(reportsDir)
		if err != nil {
			s.badRepo = fmt.Sprintf("%s (%v)", reportsDir, err)
		} else {
			s.reports = real
		}
	}
	return s
}

// Roots returns the resolved corpus roots.
func (s *Scope) Roots() []string { return append([]string(nil), s.roots...) }

// BadRoots returns the configured roots that could not be resolved.
func (s *Scope) BadRoots() []string { return append([]string(nil), s.badRoots...) }

// ReportsDir returns the resolved reports root.
func (s *Scope) ReportsDir() (string, error) {
	if s.reports == "" {
		if s.badRepo != "" {
			return "", fmt.Errorf("%s is set but unusable: %s", EnvReports, s.badRepo)
		}
		return "", fmt.Errorf("no reports directory: set %s to an existing directory the server may write to", EnvReports)
	}
	return s.reports, nil
}

// File resolves p and requires it to be a regular file inside a corpus root.
func (s *Scope) File(p string) (string, error) {
	real, info, err := s.stat(p)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory, a file was expected", real)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file (mode %s)", real, info.Mode())
	}
	return real, nil
}

// Dir resolves p and requires it to be a directory inside a corpus root.
func (s *Scope) Dir(p string) (string, error) {
	real, info, err := s.stat(p)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", real)
	}
	return real, nil
}

// Files resolves several inputs, reporting every rejection rather than the
// first: a batch that is half outside the perimeter should say so in one go.
func (s *Scope) Files(paths []string) ([]string, error) {
	var out []string
	var bad []string
	for _, p := range paths {
		real, err := s.File(p)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		out = append(out, real)
	}
	if len(bad) > 0 {
		return nil, errors.New(strings.Join(bad, "; "))
	}
	return out, nil
}

func (s *Scope) stat(p string) (string, os.FileInfo, error) {
	if strings.TrimSpace(p) == "" {
		return "", nil, errors.New("empty path")
	}
	if len(s.roots) == 0 {
		msg := fmt.Sprintf("no corpus directory configured: set %s to a %c-separated list of directories holding the samples", EnvCorpus, filepath.ListSeparator)
		if len(s.badRoots) > 0 {
			msg += fmt.Sprintf(" (configured but unusable: %s)", strings.Join(s.badRoots, "; "))
		}
		return "", nil, errors.New(msg)
	}
	real, err := resolveExisting(p)
	if err != nil {
		return "", nil, err
	}
	if !s.inRoots(real) {
		return "", nil, fmt.Errorf("%s resolves to %s, which is outside the configured corpus directories (%s)",
			p, real, strings.Join(s.roots, ", "))
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", nil, err
	}
	return real, info, nil
}

func (s *Scope) inRoots(real string) bool {
	for _, root := range s.roots {
		if within(root, real) {
			return true
		}
	}
	return false
}

// Run is one invocation's output area under the reports root.
type Run struct {
	Dir string
}

// NewRun creates a fresh directory for one invocation's artefacts. The
// timestamp carries nanoseconds because two calls can land in the same second.
func (s *Scope) NewRun(tool string) (*Run, error) {
	base, err := s.ReportsDir()
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405.000000000Z"), safeName(tool))
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	return &Run{Dir: dir}, nil
}

// Path returns a path for a plain file name inside the run directory.
func (r *Run) Path(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a plain file name", name)
	}
	return filepath.Join(r.Dir, name), nil
}

// Subdir creates and returns a subdirectory of the run directory, for the modes
// that hand Drakkar a destination of its own (--out, --extract-assets).
func (r *Run) Subdir(name string) (string, error) {
	p, err := r.Path(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", p, err)
	}
	return p, nil
}

// resolveExisting makes p absolute and then resolves every symlink in it. The
// second step is what makes containment meaningful: without it, a link planted
// inside a corpus root would name any file on the machine.
func resolveExisting(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	return real, nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "run"
	}
	return b.String()
}
