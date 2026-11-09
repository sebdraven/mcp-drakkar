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

// In bulk, Drakkar writes one report per sample into --out and leaves stdout
// empty. So the envelope's tail is built from those files: the total is how many
// it wrote, the preview is the first few decoded, and the whole set stays on
// disk under report_path.
func (s *Service) finishBulkOut(env *Envelope, dir string, maxRows int) error {
	files, err := listReports(dir)
	if err != nil {
		return err
	}

	env.ReportPath = dir

	if !env.Drakkar.Complete {
		env.note(fmt.Sprintf("the run did not complete, so the %d report(s) found under %s are a prefix of the walk, not the whole batch", len(files), dir))
	}

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
			// The report being written when drakkar was killed.
			if !env.Drakkar.Complete {
				items = append(items, map[string]any{"path": p, "unreadable": err.Error()})
				continue
			}
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

func listReports(dir string) ([]string, error) {
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
		return nil, fmt.Errorf("listing the reports under %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

// bulkOutDir prepares the out/ that a bulk run hands Drakkar as --out. One that
// already holds files would put two runs' reports under one report_path, so it
// is refused, unless resume is set: then the reports already there are counted,
// because Drakkar skips them rather than recomputing them.
func (s *Service) bulkOutDir(out *outDir, resume bool) (dir string, existing int, err error) {
	p, err := out.file("out")
	if err != nil {
		return "", 0, err
	}
	entries, err := os.ReadDir(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", 0, fmt.Errorf("reading %s: %w", p, err)
	}
	if len(entries) > 0 {
		if !resume {
			return "", 0, fmt.Errorf("%s already holds the output of an earlier run, and this bulk run would mix its reports with that one's; use another out_dir", p)
		}
		files, err := listReports(p)
		if err != nil {
			return "", 0, err
		}
		existing = len(files)
	}
	dir, err = out.subdir("out")
	return dir, existing, err
}

// resolveOne checks the single-sample input of a mode that accepts an APK or a
// raw DEX. Whether the file exists, and whether Drakkar can read it, is
// Drakkar's answer to give.
func (s *Service) resolveOne(field, p string) (string, error) {
	return requireAbs(field, p)
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
		f, err := requireAbs("the single input", file)
		return f, "", err
	default:
		d, err := requireAbs("directory", dir)
		return "", d, err
	}
}
