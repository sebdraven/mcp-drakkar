package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

var errTwoInputs = errors.New("two inputs are required")

// In bulk, Drakkar writes one report per sample into --out and leaves stdout
// empty. So the envelope's tail is built from those files: the total is how many
// it wrote, the preview is the first few decoded, and the whole set stays on
// disk under report_path.
func (s *Service) finishBulkOut(env *Envelope, dir string, maxRows int) error {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".json" {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return fmt.Errorf("listing the reports under %s: %w", dir, err)
	}
	sort.Strings(files)

	env.ReportPath = dir

	if len(files) == 0 {
		// Not necessarily a failure: a mode asked for CSV, or every entry failed.
		// Either way what is on disk is listed rather than assumed.
		s.listWritten(env, dir)
		env.note(fmt.Sprintf("no per-sample JSON report under %s; see written and stderr.text", dir))
		return nil
	}

	n := maxRows
	if n > len(files) {
		n = len(files)
	}
	items := make([]any, 0, n)
	for _, p := range files[:n] {
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading %s: %w", p, err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parsing %s: %w", p, err)
		}
		items = append(items, map[string]any{"path": p, "report": doc})
	}
	env.Tails = map[string]Tail{
		"samples": {
			Total:     len(files),
			Returned:  len(items),
			Truncated: len(items) < len(files),
			Items:     items,
		},
	}
	return nil
}

// resolveOne resolves the single-sample input of a mode that accepts an APK or a
// raw DEX.
func (s *Service) resolveOne(p string) (string, error) {
	return s.scope.File(p)
}

// resolveSingleOrBulk enforces the one structural rule the server owns: exactly
// one of the two inputs. Everything else about their validity is Drakkar's call.
func (s *Service) resolveSingleOrBulk(file, dir string) (resolvedFile string, resolvedDir string, err error) {
	switch {
	case file != "" && dir != "":
		return "", "", fmt.Errorf("pass either a single input or a directory, not both")
	case file == "" && dir == "":
		return "", "", fmt.Errorf("pass a single input, or a directory to process in bulk")
	case file != "":
		f, err := s.scope.File(file)
		return f, "", err
	default:
		d, err := s.scope.Dir(dir)
		return "", d, err
	}
}
