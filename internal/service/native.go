package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// NativeInput is single-sample only, like --native-arch.
type NativeInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many binding rows to return inline; elfs and errors come back whole, and the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Native runs --native.
func (s *Service) Native(ctx context.Context, in NativeInput) (*Envelope, error) {
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file("report.json")
	if err != nil {
		return nil, err
	}
	env, _, err := s.invoke(ctx, out, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), nativeArgs(apk, reportPath))
	if err != nil {
		return nil, err
	}
	if env.Drakkar.ExitCode != 0 && strings.Contains(env.Stderr.Text, "unexpected argument '--native'") {
		env.note("this drakkar does not know --native: it predates the release that introduced it; drakkar_version shows which one is on PATH")
	}
	if err := s.finishNative(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

func nativeArgs(apk, reportPath string) *drakkar.Args {
	return drakkar.New().Positional(apk).Switch("--native").JSONReport(reportPath)
}

// nativeStatuses is the order binding rows come back in.
var nativeStatuses = []string{"static", "registered", "registered_ambiguous", "declared_unbound", "native_unclaimed"}

type nativeReport struct {
	SHA256  string           `json:"sha256"`
	ELFs    []nativeELF      `json:"elfs"`
	Binding []map[string]any `json:"binding"`
	Summary map[string]any   `json:"summary"`
	Errors  []any            `json:"errors"`
}

type nativeELF struct {
	Path      string   `json:"path"`
	Origin    string   `json:"origin"`
	SHA256    string   `json:"sha256"`
	Machine   string   `json:"machine"`
	Bits      int      `json:"bits"`
	ELFType   string   `json:"elf_type"`
	Stripped  bool     `json:"stripped"`
	Anomalies []string `json:"anomalies"`
	JNI       struct {
		JNIOnLoad       bool              `json:"jni_onload"`
		JNIRegistration string            `json:"jni_registration"`
		StaticExports   []json.RawMessage `json:"static_exports"`
		Registered      []json.RawMessage `json:"registered"`
	} `json:"jni"`
}

// finishNative puts summary in the head and three tails beside it: one row per
// ELF, the binding rows sorted by status then java, and the report's errors.
func (s *Service) finishNative(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			env.note("no JSON report was produced, which is consistent with the exit code above")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	head := map[string]any{"sha256": r.SHA256}
	for k, v := range r.Summary {
		head[k] = v
	}
	env.Result = head

	elfs := make([]any, 0, len(r.ELFs))
	for _, e := range r.ELFs {
		anomalies := e.Anomalies
		if anomalies == nil {
			anomalies = []string{}
		}
		elfs = append(elfs, map[string]any{
			"path":                 e.Path,
			"origin":               e.Origin,
			"sha256":               e.SHA256,
			"machine":              e.Machine,
			"bits":                 e.Bits,
			"elf_type":             e.ELFType,
			"stripped":             e.Stripped,
			"jni_onload":           e.JNI.JNIOnLoad,
			"jni_registration":     e.JNI.JNIRegistration,
			"static_exports_count": len(e.JNI.StaticExports),
			"registered_count":     len(e.JNI.Registered),
			"anomalies":            anomalies,
		})
	}

	binding := sortBinding(r.Binding)
	errs := r.Errors
	if errs == nil {
		errs = []any{}
	}
	env.Tails = map[string]Tail{
		"elfs":    makeTail(elfs, len(elfs)),
		"binding": makeTail(binding, maxRows),
		"errors":  makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	if len(r.ELFs) == 0 {
		env.note("no ELF was found anywhere in the archive, recognised by content rather than by path or extension")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report: a native method missing from an unreadable DEX can show its export as native_unclaimed, and a DEX not read at all leaves binding empty with native_methods_declared at 0", len(errs)))
	}
	return nil
}

func sortBinding(rows []map[string]any) []any {
	rank := make(map[string]int, len(nativeStatuses))
	for i, st := range nativeStatuses {
		rank[st] = i
	}
	rankOf := func(row map[string]any) (int, string) {
		st, _ := row["status"].(string)
		if n, ok := rank[st]; ok {
			return n, st
		}
		return len(nativeStatuses), st
	}
	sorted := make([]map[string]any, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, si := rankOf(sorted[i])
		rj, sj := rankOf(sorted[j])
		if ri != rj {
			return ri < rj
		}
		if si != sj {
			return si < sj
		}
		ji, _ := sorted[i]["java"].(string)
		jj, _ := sorted[j]["java"].(string)
		return ji < jj
	})
	out := make([]any, 0, len(sorted))
	for _, row := range sorted {
		out = append(out, row)
	}
	return out
}
