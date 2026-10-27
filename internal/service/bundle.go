package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/version"
)

// The two bundle readers run no analysis, only the cached --version check: they
// read OUT/<sha256>/ as --bundle wrote it. Files under classes/ are named by id, never by descriptor, and the
// name is built here from an integer taken from index.json — a caller's string
// never becomes a path.

// BundleClassInput selects one class of a bundle.
type BundleClassInput struct {
	BundleDir string `json:"bundle_dir" jsonschema:"absolute path of OUT/<sha256>, as drakkar_bundle returns it in bundle_dir"`

	ID         *int   `json:"id,omitempty" jsonschema:"the class id from index.json; pass this or descriptor, not both"`
	Descriptor string `json:"descriptor,omitempty" jsonschema:"the whole Dalvik descriptor, for example Lcom/a/B$1;, resolved through index.json; a class defined in two DEX has two ids and must then be asked for by id"`

	Parts []string `json:"parts,omitempty" jsonschema:"which files to return, any of class_java, java, dasm, methods; omit for all four"`

	MaxChars *int `json:"max_chars,omitempty" jsonschema:"how many characters of each part to return inline; every file stays whole on disk"`
}

// classParts maps a part name to its classes/<id>.<ext> suffix, in the order
// they are returned.
var classParts = []struct{ name, ext string }{
	{"class_java", "class.java"},
	{"java", "java"},
	{"dasm", "dasm"},
	{"methods", "json"},
}

// BundleClass reads index.json's entry for one class and its files.
func (s *Service) BundleClass(ctx context.Context, in BundleClassInput) (*Envelope, error) {
	root, err := bundleDir(in.BundleDir)
	if err != nil {
		return nil, err
	}
	if (in.ID == nil) == (in.Descriptor == "") {
		return nil, fmt.Errorf("pass either id or descriptor, exactly one of the two")
	}
	parts, err := selectParts(in.Parts)
	if err != nil {
		return nil, err
	}
	v, err := s.requireBundleModes(ctx, "drakkar_bundle_class")
	if err != nil {
		return nil, err
	}
	env := readerEnvelope(v)

	index, err := loadIndex(root)
	if err != nil {
		return nil, err
	}
	entry, id, err := findClass(index, in.ID, in.Descriptor)
	if err != nil {
		return nil, err
	}

	maxChars := ClampChars(in.MaxChars)
	out := map[string]any{}
	anyTruncated := false
	for _, p := range parts {
		path := classFile(root, id, p.ext)
		part, err := readPart(root, path, maxChars)
		if err != nil {
			return nil, err
		}
		if part["present"] == false {
			if p.name == "class_java" && entry["class_java"] == "failed" {
				part["reason"] = "class_java is failed in index.json: decompile_class failed, so Drakkar wrote no .class.java; the reason is in errors, stage decompile_class"
			} else {
				part["reason"] = "the file is absent although index.json lists the class; see errors, stage write"
			}
		}
		if part["truncated"] == true {
			anyTruncated = true
		}
		out[p.name] = part
	}

	classErrors, err := errorsFor(root, id)
	if err != nil {
		return nil, err
	}
	env.Result = map[string]any{
		"class":  entry,
		"parts":  out,
		"errors": classErrors,
	}
	env.ReportPath = root
	if anyTruncated {
		env.note(fmt.Sprintf("at least one part is cut at %d characters; each part's path names the whole file", maxChars))
	}
	if entry["decompile_status"] == "partial" {
		env.note("decompile_status is partial: the decompiler left fallback markers in some methods, listed per method in methods as partial_markers")
	}
	return env, nil
}

// BundleIndexInput filters index.json.
type BundleIndexInput struct {
	BundleDir string `json:"bundle_dir" jsonschema:"absolute path of OUT/<sha256>, as drakkar_bundle returns it in bundle_dir"`

	Origin          string `json:"origin,omitempty" jsonschema:"app or lib; app is over-inclusive — a library absent from Drakkar's exclusion list, or renamed by ProGuard, counts as app"`
	DecompileStatus string `json:"decompile_status,omitempty" jsonschema:"ok, partial or failed: the worst status among the class's methods"`
	ClassJava       string `json:"class_java,omitempty" jsonschema:"ok or failed: whether decompile_class produced classes/<id>.class.java"`
	HasRulesDirect  *bool  `json:"has_rules_direct,omitempty" jsonschema:"true keeps only the classes some rule cites directly, false only those no rule does"`
	PackagePrefix   string `json:"package_prefix,omitempty" jsonschema:"keep classes whose Java package, dotted as index.json writes it (com.example), starts with this"`

	MaxRows *int `json:"max_rows,omitempty" jsonschema:"how many matching classes to return inline; total counts them all"`
}

// indexFilter is BundleIndexInput without the paths, checked.
type indexFilter struct {
	origin, status, classJava, packagePrefix string
	hasRulesDirect                           *bool
}

// BundleIndex returns the index.json entries matching every filter given, in
// index order: DEX, then class_defs.
func (s *Service) BundleIndex(ctx context.Context, in BundleIndexInput) (*Envelope, error) {
	root, err := bundleDir(in.BundleDir)
	if err != nil {
		return nil, err
	}
	if err := oneOf("origin", in.Origin, "app", "lib"); err != nil {
		return nil, err
	}
	if err := oneOf("decompile_status", in.DecompileStatus, "ok", "partial", "failed"); err != nil {
		return nil, err
	}
	if err := oneOf("class_java", in.ClassJava, "ok", "failed"); err != nil {
		return nil, err
	}
	v, err := s.requireBundleModes(ctx, "drakkar_bundle_index")
	if err != nil {
		return nil, err
	}
	env := readerEnvelope(v)

	index, err := loadIndex(root)
	if err != nil {
		return nil, err
	}
	matched := filterIndex(index, indexFilter{
		origin:         in.Origin,
		status:         in.DecompileStatus,
		classJava:      in.ClassJava,
		packagePrefix:  in.PackagePrefix,
		hasRulesDirect: in.HasRulesDirect,
	})

	env.Result = map[string]any{
		"index_total": len(index),
		"matched":     len(matched),
	}
	env.Tails = map[string]Tail{"classes": makeTail(matched, ClampRows(in.MaxRows))}
	env.ReportPath = filepath.Join(root, "index.json")
	if in.HasRulesDirect != nil && rulesMissing(root) {
		env.note("rules.json is null — the rule engine failed, see errors.json stage rules — so no class has rules_direct, which says nothing about the code")
	}
	return env, nil
}

func filterIndex(index []map[string]any, f indexFilter) []any {
	out := []any{}
	for _, e := range index {
		if f.origin != "" && e["origin"] != f.origin {
			continue
		}
		if f.status != "" && e["decompile_status"] != f.status {
			continue
		}
		if f.classJava != "" && e["class_java"] != f.classJava {
			continue
		}
		if f.packagePrefix != "" {
			pkg, ok := e["package"].(string)
			if !ok || !strings.HasPrefix(pkg, f.packagePrefix) {
				continue
			}
		}
		if f.hasRulesDirect != nil {
			direct, _ := e["rules_direct"].([]any)
			if (len(direct) > 0) != *f.hasRulesDirect {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// readerEnvelope is the envelope of a tool that runs nothing.
func readerEnvelope(drakkarVersion string) *Envelope {
	env := &Envelope{
		Drakkar: Meta{
			Server:  version.Version,
			Version: drakkarVersion,
			Tested:  version.DrakkarTested,
		},
	}
	env.note("no analysis was run: this tool reads a bundle already on disk, so argv is empty and stderr is not Drakkar's")
	return env
}

func bundleDir(p string) (string, error) {
	root, err := requireAbs("bundle_dir", p)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(root, "index.json")); err != nil {
		return "", fmt.Errorf("%s is not a bundle directory, it has no index.json: pass OUT/<sha256>, which drakkar_bundle returns as bundle_dir: %w", root, err)
	}
	return root, nil
}

func loadIndex(root string) ([]map[string]any, error) {
	var index []map[string]any
	if err := readJSONFile(filepath.Join(root, "index.json"), &index); err != nil {
		return nil, err
	}
	return index, nil
}

// findClass resolves id or descriptor to one index entry and its id.
func findClass(index []map[string]any, id *int, descriptor string) (map[string]any, int, error) {
	if id != nil {
		if *id < 0 {
			return nil, 0, fmt.Errorf("id %d is negative", *id)
		}
		for _, e := range index {
			if n, ok := entryID(e); ok && n == *id {
				return e, n, nil
			}
		}
		return nil, 0, fmt.Errorf("id %d is not in index.json, which has %d entries", *id, len(index))
	}
	var found []map[string]any
	for _, e := range index {
		if d, ok := e["descriptor"].(string); ok && d == descriptor {
			found = append(found, e)
		}
	}
	switch len(found) {
	case 0:
		return nil, 0, fmt.Errorf("no class in index.json has the descriptor %q; the match is exact, use drakkar_bundle_index to search", descriptor)
	case 1:
		n, ok := entryID(found[0])
		if !ok {
			return nil, 0, fmt.Errorf("the index.json entry for %q has no usable id", descriptor)
		}
		return found[0], n, nil
	default:
		var where []string
		for _, e := range found {
			where = append(where, fmt.Sprintf("id %v in %v", e["id"], e["dex"]))
		}
		return nil, 0, fmt.Errorf("%q is defined %d times (%s); ask for one by id", descriptor, len(found), strings.Join(where, ", "))
	}
}

func entryID(e map[string]any) (int, bool) {
	f, ok := e["id"].(float64)
	if !ok || f < 0 || f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

// classFile is classes/<id>.<ext>, the id zero-padded to at least six digits as
// decompile.rs writes it.
func classFile(root string, id int, ext string) string {
	return filepath.Join(root, "classes", fmt.Sprintf("%06d.%s", id, ext))
}

func selectParts(names []string) ([]struct{ name, ext string }, error) {
	if len(names) == 0 {
		return classParts, nil
	}
	want := map[string]bool{}
	for _, n := range names {
		known := false
		for _, p := range classParts {
			if p.name == n {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("part %q is not one of class_java, java, dasm, methods", n)
		}
		want[n] = true
	}
	var out []struct{ name, ext string }
	for _, p := range classParts {
		if want[p.name] {
			out = append(out, p)
		}
	}
	return out, nil
}

// readPart returns one file of classes/, cut at maxChars. A file that resolves
// outside root, through a symbolic link, is refused.
func readPart(root, path string, maxChars int) (map[string]any, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return map[string]any{"path": path, "present": false}, nil
	}
	if err := within(root, path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	text, truncated := truncateChars(string(raw), maxChars)
	return map[string]any{
		"path":      path,
		"present":   true,
		"bytes":     len(raw),
		"truncated": truncated,
		"text":      text,
	}, nil
}

func within(root, path string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", root, err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", path, err)
	}
	rel, err := filepath.Rel(realRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s resolves to %s, outside the bundle %s; refused", path, real, root)
	}
	return nil
}

// errorsFor returns the errors.json entries naming this class id.
func errorsFor(root string, id int) ([]any, error) {
	var errs []map[string]any
	if err := readJSONFile(filepath.Join(root, "errors.json"), &errs); err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range errs {
		if f, ok := e["class_id"].(float64); ok && int(f) == id {
			out = append(out, e)
		}
	}
	return out, nil
}

// rulesMissing reports a rules.json that holds null: the rule engine failed.
func rulesMissing(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "rules.json"))
	return err == nil && strings.TrimSpace(string(raw)) == "null"
}

func oneOf(field, v string, allowed ...string) error {
	if v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q is not one of %s", field, v, strings.Join(allowed, ", "))
}

func readJSONFile(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}
