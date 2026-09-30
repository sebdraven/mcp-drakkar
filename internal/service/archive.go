package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// AssetsInput drives the assets modes, one tool for the same reason as the
// resource views: Drakkar dispatches them as one branch with one output shape.
//
// --assets-hash-file and --assets-hash-exclude-file are deliberately not
// exposed. They would let a caller name any file on the machine for the server
// to read, which is the one thing the perimeter exists to prevent; the hashes
// can be passed inline instead.
type AssetsInput struct {
	APK       string `json:"apk,omitempty" jsonschema:"path to one APK, inside a configured corpus directory"`
	Directory string `json:"directory,omitempty" jsonschema:"path to a directory of APKs to process in bulk instead of one APK"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	Mode string `json:"mode" jsonschema:"list inventories the assets and writes nothing, fingerprint returns the whole-set fingerprint only, extract writes the assets plus an assets.json into this call's report directory"`

	Include []string `json:"include,omitempty" jsonschema:"keep only entries whose path contains one of these substrings, case-insensitive; repeatable"`

	MaxSize *int64 `json:"max_size,omitempty" jsonschema:"ceiling in bytes on the uncompressed size; beyond it an asset is skipped and recorded, never silently omitted"`

	Hashes        []string `json:"hashes,omitempty" jsonschema:"keep only assets whose SHA-256 is in this set, whole and untruncated; the pivot for which binaries carry a known payload"`
	ExcludeHashes []string `json:"exclude_hashes,omitempty" jsonschema:"remove the already-qualified assets, whole and untruncated SHA-256; leaves the remainder"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many rows to return inline; the whole set is written to disk either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Assets runs --list-assets, --assets-fingerprint or --extract-assets.
func (s *Service) Assets(ctx context.Context, in AssetsInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.APK, in.Directory)
	if err != nil {
		return nil, err
	}
	if err := checkHashes("hashes", in.Hashes); err != nil {
		return nil, err
	}
	if err := checkHashes("exclude_hashes", in.ExcludeHashes); err != nil {
		return nil, err
	}
	run, err := s.begin("assets_" + in.Mode)
	if err != nil {
		return nil, err
	}

	args := drakkar.New()
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		args.Value("--bulk", dir).SwitchIf("--recursive", in.Recursive)
	}

	var extractDir string
	switch in.Mode {
	case "list":
		args.Switch("--list-assets")
	case "fingerprint":
		args.Switch("--assets-fingerprint")
	case "extract":
		extractDir, err = run.Subdir("assets")
		if err != nil {
			return nil, err
		}
		args.Value("--extract-assets", extractDir)
	default:
		return nil, fmt.Errorf("mode %q is not one of list, fingerprint, extract", in.Mode)
	}

	args.Multi("--assets-include", in.Include).
		Int64("--assets-max-size", in.MaxSize).
		Multi("--assets-hash", in.Hashes).
		Multi("--assets-hash-exclude", in.ExcludeHashes)

	env, res, err := s.invoke(ctx, run, timeout, args)
	if err != nil {
		return nil, err
	}
	table, err := s.finishTable(env, run, res.Stdout, ClampRows(in.MaxRows))
	if err != nil {
		return nil, err
	}
	if table != nil {
		result := map[string]any{"rows_total": len(table.Rows)}
		// In single mode without a hash filter the assets TSV carries no sample
		// column at all, so its absence is expected rather than worth a note.
		if _, ok := table.Column("sample"); ok {
			result["per_sample"] = s.histogram(env, table, "sample")
		}
		env.Result = result
	}
	if extractDir != "" {
		s.listWritten(env, extractDir)
	}
	return env, nil
}

// ListEntriesInput drives --list-entries.
type ListEntriesInput struct {
	APK string `json:"apk" jsonschema:"path to one APK, inside a configured corpus directory"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entry paths to return inline; the whole list is written to disk either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// ListEntries runs --list-entries. Nothing is extracted.
func (s *Service) ListEntries(ctx context.Context, in ListEntriesInput) (*Envelope, error) {
	apk, err := s.resolveOne(in.APK)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("list_entries")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(apk).Switch("--list-entries")
	env, res, err := s.invoke(ctx, run, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishLines(env, run, res.Stdout, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// ExtractEntryInput drives --extract-entry.
type ExtractEntryInput struct {
	APK      string   `json:"apk" jsonschema:"path to one APK, inside a configured corpus directory"`
	Patterns []string `json:"patterns" jsonschema:"what to extract: an exact path like res/raw/plugin, a glob like assets/*.so, or a substring like plugin; case-insensitive, repeatable"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// ExtractEntry runs --extract-entry. Only the requested entries are read: the
// archive is never unpacked whole.
func (s *Service) ExtractEntry(ctx context.Context, in ExtractEntryInput) (*Envelope, error) {
	apk, err := s.resolveOne(in.APK)
	if err != nil {
		return nil, err
	}
	if len(in.Patterns) == 0 {
		return nil, fmt.Errorf("patterns is required")
	}
	run, err := s.begin("extract_entry")
	if err != nil {
		return nil, err
	}
	out, err := run.Subdir("out")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(apk).
		Multi("--extract-entry", in.Patterns).
		Value("--out", out)

	env, res, err := s.invoke(ctx, run, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, run, res.Stdout); err != nil {
		return nil, err
	}
	s.listWritten(env, out)
	return env, nil
}

// ExtractLibsInput drives --extract-libs.
type ExtractLibsInput struct {
	APK string `json:"apk" jsonschema:"path to one APK, inside a configured corpus directory"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// ExtractLibs runs --extract-libs, which takes the native .so out of lib/ and
// from outside it too, where packers hide them.
func (s *Service) ExtractLibs(ctx context.Context, in ExtractLibsInput) (*Envelope, error) {
	apk, err := s.resolveOne(in.APK)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("extract_libs")
	if err != nil {
		return nil, err
	}
	out, err := run.Subdir("out")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(apk).Switch("--extract-libs").Value("--out", out)

	env, res, err := s.invoke(ctx, run, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, run, res.Stdout); err != nil {
		return nil, err
	}
	s.listWritten(env, out)
	return env, nil
}

// checkHashes refuses a SHA-256 that is not whole. A truncated hash is rejected
// rather than passed through, and the offending value is echoed in full: a
// prefix silently accepted is how a filter comes back empty and gets read as
// the absence of the asset.
func checkHashes(field string, hashes []string) error {
	for _, h := range hashes {
		if len(h) != 64 || !isHex(h) {
			return fmt.Errorf("%s: %q is not a whole SHA-256 (64 hexadecimal characters); this server never accepts a truncated hash", field, h)
		}
	}
	return nil
}

func isHex(s string) bool {
	const hex = "0123456789abcdefABCDEF"
	for _, r := range s {
		if !strings.ContainsRune(hex, r) {
			return false
		}
	}
	return true
}
