package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// outDir is where one call's output goes: the directory the caller named, or a
// fresh one under the system temp directory when the caller named none.
//
// The fallback is not a convenience. Drakkar's own --out defaults to ./reports,
// relative to the process working directory — which for a server started by an
// MCP client is whatever directory that client happened to be in. So the server
// never lets that default apply: it substitutes an absolute directory of its own
// and returns the path, rather than restating ./reports anywhere.
type outDir struct {
	path string
}

// newOutDir prepares the directory for one call. A caller-supplied path must be
// absolute, for the same reason: a relative one would resolve against a working
// directory nobody chose.
func newOutDir(tool, requested string) (*outDir, error) {
	if strings.TrimSpace(requested) != "" {
		if !filepath.IsAbs(requested) {
			return nil, fmt.Errorf("out_dir must be an absolute path, got %q", requested)
		}
		if err := os.MkdirAll(requested, 0o755); err != nil {
			return nil, fmt.Errorf("creating %s: %w", requested, err)
		}
		return &outDir{path: requested}, nil
	}
	dir, err := os.MkdirTemp("", "mcp-drakkar-"+safeName(tool)+"-")
	if err != nil {
		return nil, fmt.Errorf("creating a temporary output directory: %w", err)
	}
	return &outDir{path: dir}, nil
}

// file returns a path for a plain file name inside the directory.
func (o *outDir) file(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a plain file name", name)
	}
	return filepath.Join(o.path, name), nil
}

// subdir creates and returns a subdirectory, for the modes that hand Drakkar a
// destination of its own (--out, --extract-assets).
func (o *outDir) subdir(name string) (string, error) {
	p, err := o.file(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", p, err)
	}
	return p, nil
}

// requireAbs is the one thing the server still checks about an input path. It is
// not a restriction on which files may be read — any absolute path is fine — but
// a relative path would be resolved against the child's working directory, which
// is this call's output directory and not the caller's shell.
func requireAbs(field, p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s must be an absolute path, got %q", field, p)
	}
	return p, nil
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
