package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// DecompileInput drives --decompile.
type DecompileInput struct {
	Input    string   `json:"input" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Patterns []string `json:"patterns,omitempty" jsonschema:"substrings of the Dalvik class descriptor to decompile, compared case-insensitively; omit to take every class read"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxChars       *int `json:"max_chars,omitempty" jsonschema:"how many characters of Java to return inline; the whole of it is written to decompiled.java either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Decompile runs --decompile. Text only, like --disasm: the mode refuses
// --format upstream.
func (s *Service) Decompile(ctx context.Context, in DecompileInput) (*Envelope, error) {
	input, err := s.resolveOne("input", in.Input)
	if err != nil {
		return nil, err
	}
	if _, err := s.requireBundleModes(ctx, "drakkar_decompile"); err != nil {
		return nil, err
	}
	out, err := s.begin("decompile", in.OutDir)
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(input).Optional("--decompile", in.Patterns)

	env, res, err := s.invoke(ctx, out, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	unknownFlagNote(env, "--decompile")

	path, err := out.file("decompiled.java")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, res.Stdout, 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	env.ReportPath = path

	maxChars := ClampChars(in.MaxChars)
	java, truncated := truncateChars(string(res.Stdout), maxChars)
	result := map[string]any{
		"java":              java,
		"bytes":             len(res.Stdout),
		"truncated":         truncated,
		"truncated_on_disk": res.StdoutTruncated,
	}
	if res.StdoutTruncated {
		env.note(fmt.Sprintf("decompiled.java is incomplete, whatever the note on stdout says: it is written from stdout, which the runner stops capturing at %d bytes. Narrow patterns, or use drakkar_bundle, which writes one file per class", drakkar.NewRunner("").MaxStdout))
	}
	if sum, ok := decompileSummary(env.Stderr.Text); ok {
		result["classes_decompiled"] = sum[0]
		result["classes_scanned"] = sum[1]
		result["classes_fallback"] = sum[2]
		if sum[2] > 0 {
			env.note(fmt.Sprintf("%d class(es) carry a `// repli méthode par méthode` header: decompile_class failed on them, and what follows is the per-method rendering, without fields, imports or inner classes", sum[2]))
		}
	} else if env.Drakkar.ExitCode == 0 {
		env.note("the [OK] summary line was not found on stderr, so the class counts are absent rather than guessed")
	}
	env.Result = result
	if truncated {
		env.note(fmt.Sprintf("only the first %d characters of the Java are inline; the whole of it is at %s", maxChars, path))
	}
	return env, nil
}

// decompileSummary reads the line --decompile ends on: "[OK]    N classe(s)
// décompilée(s) sur M lues, K en repli méthode par méthode".
var decompileSummaryLine = regexp.MustCompile(`^\[OK\]\s+(\d+) classe\(s\) décompilée\(s\) sur (\d+) lues, (\d+) en repli`)

func decompileSummary(stderr string) ([3]int, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		m := decompileSummaryLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var out [3]int
		for i := range out {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return [3]int{}, false
			}
			out[i] = n
		}
		return out, true
	}
	return [3]int{}, false
}

// BundleInput drives --bundle.
type BundleInput struct {
	Input string `json:"input" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`

	OutDir    string `json:"out_dir" jsonschema:"absolute directory OUT; the bundle is written to OUT/<sha256 of the input>/. Required: the bundle is a deliverable, never a temporary report"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"replace an existing OUT/<sha256>/; without it Drakkar refuses and leaves the existing bundle untouched"`

	Jobs *int `json:"jobs,omitempty" jsonschema:"worker threads for the per-class pass; omit to leave Drakkar's own choice in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entries of errors.json to return inline; the whole file stays in the bundle"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Bundle runs --bundle. Drakkar names the directory after the SHA-256 of the
// input; it is read back from the [OK] line rather than recomputed or found by
// listing OUT, which may hold other bundles and, with --overwrite, already held
// this one.
func (s *Service) Bundle(ctx context.Context, in BundleInput) (*Envelope, error) {
	input, err := s.resolveOne("input", in.Input)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.OutDir) == "" {
		return nil, fmt.Errorf("out_dir is required: the bundle is a deliverable written to OUT/<sha256>/, so it never goes to a temporary directory")
	}
	if !filepath.IsAbs(in.OutDir) {
		return nil, fmt.Errorf("out_dir must be an absolute path, got %q", in.OutDir)
	}
	if _, err := s.requireBundleModes(ctx, "drakkar_bundle"); err != nil {
		return nil, err
	}
	out, err := s.begin("bundle", in.OutDir)
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(input).
		OptionalValue("--bundle", out.path).
		SwitchIf("--overwrite", in.Overwrite).
		Int("--jobs", in.Jobs)

	env, _, err := s.invoke(ctx, out, s.timeout(s.timeouts.Bulk, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	unknownFlagNote(env, "--bundle")
	if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
		if line := errorLine(env.Stderr.Text); line != "" {
			env.note("Drakkar's message, verbatim: " + line)
		}
		return env, nil
	}
	root, ok := bundleRoot(env.Stderr.Text, out.path)
	if !ok {
		root, ok = bundleRootByHash(env, input, out.path)
	}
	if !ok {
		env.note(fmt.Sprintf("drakkar exited 0 but no [OK] line naming %s/<sha256> was found on stderr; the bundle directory is not located by guessing", out.path))
		return env, nil
	}
	if err := s.finishBundle(env, root, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// bundleRoot reads OUT/<sha256> from the line run_bundle prints once every file
// is written: "[OK]    <root> — N classes, …". The cut is at the last " — ",
// since the counters after it carry none and a path may.
func bundleRoot(stderr, out string) (string, bool) {
	lines := strings.Split(stderr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		rest, found := strings.CutPrefix(lines[i], "[OK]")
		if !found {
			continue
		}
		rest = strings.TrimSpace(rest)
		cut := strings.LastIndex(rest, " — ")
		if cut < 0 {
			continue
		}
		root := rest[:cut]
		base := filepath.Base(root)
		if len(base) == 64 && isHex(base) && filepath.Clean(filepath.Dir(root)) == filepath.Clean(out) {
			return root, true
		}
	}
	return "", false
}

// bundleRootByHash is the fallback when the [OK] line is lost, typically cut
// off with the end of stderr: Drakkar names the directory after the SHA-256 of
// the input file, so it is recomputed, and accepted only if bundle.json there
// names the same hash.
func bundleRootByHash(env *Envelope, input, out string) (string, bool) {
	sum, err := sha256File(input)
	if err != nil {
		env.note(fmt.Sprintf("the input could not be hashed to locate the bundle: %v", err))
		return "", false
	}
	root := filepath.Join(out, sum)
	var info map[string]any
	if err := readJSONFile(filepath.Join(root, "bundle.json"), &info); err != nil {
		return "", false
	}
	if sha, _ := info["sha256"].(string); sha != sum {
		return "", false
	}
	why := "stderr was not truncated"
	if env.Stderr.Truncated {
		why = "stderr was truncated at the capture ceiling, which is how the line goes missing"
	}
	env.note(fmt.Sprintf("no [OK] line naming the bundle was found on stderr (%s); the bundle was located at %s by hashing the input as Drakkar does, and accepted because bundle.json there names the same sha256", why, root))
	return root, true
}

// sha256File is decompile.rs's sha256_file: the whole input, lowercase hex.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// finishBundle shapes bundle.json, errors.json and index.json into the head.
// bundle.json goes back whole; the index is aggregated, since drakkar_bundle_index
// is the tool for reading it.
func (s *Service) finishBundle(env *Envelope, root string, maxRows int) error {
	var info map[string]any
	if err := readJSONFile(filepath.Join(root, "bundle.json"), &info); err != nil {
		return err
	}
	var errs []any
	if err := readJSONFile(filepath.Join(root, "errors.json"), &errs); err != nil {
		return err
	}
	index, err := loadIndex(root)
	if err != nil {
		return err
	}

	perOrigin := map[string]int{}
	perStatus := map[string]int{}
	perClassJava := map[string]int{}
	for _, e := range index {
		perOrigin[label(e["origin"])]++
		perStatus[label(e["decompile_status"])]++
		perClassJava[label(e["class_java"])]++
	}

	env.Result = map[string]any{
		"bundle_dir":           root,
		"bundle":               info,
		"classes_total":        len(index),
		"per_origin":           perOrigin,
		"per_decompile_status": perStatus,
		"per_class_java":       perClassJava,
		"errors_total":         len(errs),
	}
	env.Tails = map[string]Tail{"errors": makeTail(errs, maxRows)}
	env.ReportPath = root

	if sha, _ := info["sha256"].(string); sha != filepath.Base(root) {
		env.note(fmt.Sprintf("bundle.json names sha256 %q but the directory is %s; one of the two is not this input", sha, root))
	}
	if packed := mapOf(info["packed"]); packed != nil && packed["detected"] == nil {
		env.note("packed.detected is null: Drakkar has no packer detection, so this means not evaluated, never not packed. On a packed sample classes/ describes the stub, not the payload")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d failure(s) recorded in errors.json; a part that failed is null in its own file, never silently absent", len(errs)))
	}
	if rulesMissing(root) {
		env.note("rules.json is null — the rule engine failed, see errors stage rules — so rules_direct and rules_path are empty for every class, which says nothing about the code")
	}
	return nil
}

// label is a histogram key for a JSON scalar, with null kept visible.
func label(v any) string {
	if v == nil {
		return "null"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// errorLine is the first line anyhow prints for a failed main: "Error: …".
func errorLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "Error: ") {
			return line
		}
	}
	return ""
}

// minBundleRelease is the first Drakkar with --decompile and --bundle.
var minBundleRelease = [3]int{0, 2, 0}

// requireBundleModes refuses up front when the drakkar on PATH reports a release
// older than 0.2.0. An unreadable version is not a refusal: the run then says
// so itself, see unknownFlagNote.
func (s *Service) requireBundleModes(ctx context.Context, tool string) (string, error) {
	v := s.drakkarVersion(ctx, drakkar.NewRunner(""))
	if r, ok := releaseOf(v); ok && olderThan(r, minBundleRelease) {
		return v, fmt.Errorf("%s needs Drakkar 0.2.0 or later, the release that introduced --decompile and --bundle; the drakkar on PATH reports %q. Install a newer Drakkar and restart the server — this server never builds it", tool, v)
	}
	return v, nil
}

// unknownFlagNote names clap's refusal of a flag this Drakkar predates.
func unknownFlagNote(env *Envelope, flag string) {
	if env.Drakkar.ExitCode != 0 && strings.Contains(env.Stderr.Text, "unexpected argument '"+flag) {
		env.note(fmt.Sprintf("this drakkar does not know %s: it predates 0.2.0, which introduced it; drakkar_version shows which one is on PATH", flag))
	}
}

// releaseOf reads `drakkar --version`, "drakkar 0.2.0", as {0, 2, 0}.
func releaseOf(v string) ([3]int, bool) {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return [3]int{}, false
	}
	parts := strings.SplitN(fields[len(fields)-1], ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var r [3]int
	for i, p := range parts {
		p, _, _ = strings.Cut(p, "-")
		p, _, _ = strings.Cut(p, "+")
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		r[i] = n
	}
	return r, true
}

func olderThan(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

const (
	// DefaultMaxChars is the inline size of a text part when the caller asks for none.
	DefaultMaxChars = 64 << 10
	// maxMaxChars bounds what a caller may ask for inline.
	maxMaxChars = 1 << 20
)

// ClampChars keeps a caller-supplied inline text size inside sane bounds.
func ClampChars(n *int) int {
	if n == nil || *n <= 0 {
		return DefaultMaxChars
	}
	if *n > maxMaxChars {
		return maxMaxChars
	}
	return *n
}

// truncateChars cuts s after n characters, never inside one.
func truncateChars(s string, n int) (string, bool) {
	count := 0
	for i := range s {
		if count == n {
			return s[:i], true
		}
		count++
	}
	return s, false
}
