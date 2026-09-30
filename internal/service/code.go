package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// StringsInput drives --strings.
type StringsInput struct {
	Input     string `json:"input,omitempty" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory of APKs or DEX files to process in bulk instead of one input"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	Patterns []string `json:"patterns,omitempty" jsonschema:"substrings to keep, compared case-insensitively; omit to dump the whole string pool"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many rows to return inline; the whole set is written to disk either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Strings runs --strings. TSV only upstream, parsed here into named rows.
func (s *Service) Strings(ctx context.Context, in StringsInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.Input, in.Directory)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("strings", in.OutDir)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		args.Value("--bulk", dir).SwitchIf("--recursive", in.Recursive)
	}
	args.Optional("--strings", in.Patterns)

	env, res, err := s.invoke(ctx, out, timeout, args)
	if err != nil {
		return nil, err
	}
	table, err := s.finishTable(env, out, res.Stdout, rows)
	if err != nil {
		return nil, err
	}
	if table != nil {
		env.Result = map[string]any{
			"rows_total":  len(table.Rows),
			"per_sample":  s.histogram(env, table, "sample"),
			"per_pattern": s.histogram(env, table, "motif"),
		}
	}
	return env, nil
}

// DynEntrypointsInput drives --dyn-entrypoints.
type DynEntrypointsInput struct {
	Input     string `json:"input,omitempty" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory of APKs or DEX files to process in bulk instead of one input"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many rows to return inline; the whole set is written to disk either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// DynEntrypoints runs --dyn-entrypoints.
func (s *Service) DynEntrypoints(ctx context.Context, in DynEntrypointsInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.Input, in.Directory)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("dyn_entrypoints", in.OutDir)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		args.Value("--bulk", dir).SwitchIf("--recursive", in.Recursive)
	}
	args.Switch("--dyn-entrypoints")

	env, res, err := s.invoke(ctx, out, timeout, args)
	if err != nil {
		return nil, err
	}
	table, err := s.finishTable(env, out, res.Stdout, rows)
	if err != nil {
		return nil, err
	}
	if table != nil {
		classes, _ := table.Distinct("classe")
		env.Result = map[string]any{
			"rows_total":       len(table.Rows),
			"per_provenance":   s.histogram(env, table, "origine"),
			"per_sink":         s.histogram(env, table, "sink"),
			"distinct_classes": len(classes),
		}
	}
	return env, nil
}

// ReflectionInputsInput drives --reflection-inputs.
type ReflectionInputsInput struct {
	Input     string `json:"input,omitempty" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory of APKs or DEX files to process in bulk instead of one input"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many rows to return inline; the whole set is written to disk either way"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// ReflectionInputs runs --reflection-inputs. The TSV is already an aggregate, so
// the totals per category are computed here rather than left to the caller.
func (s *Service) ReflectionInputs(ctx context.Context, in ReflectionInputsInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.Input, in.Directory)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("reflection_inputs", in.OutDir)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		args.Value("--bulk", dir).SwitchIf("--recursive", in.Recursive)
	}
	args.Switch("--reflection-inputs")

	env, res, err := s.invoke(ctx, out, timeout, args)
	if err != nil {
		return nil, err
	}
	table, err := s.finishTable(env, out, res.Stdout, rows)
	if err != nil {
		return nil, err
	}
	if table != nil {
		result := map[string]any{"rows_total": len(table.Rows)}
		if totals, err := table.SumBy("category", "count"); err == nil {
			result["per_category"] = totals
		} else {
			env.note(fmt.Sprintf("could not total the categories: %v", err))
		}
		if samples, err := table.Distinct("sample"); err == nil {
			result["samples"] = len(samples)
		}
		env.Result = result
	}
	return env, nil
}

// APISurfaceInput drives --api-surface.
type APISurfaceInput struct {
	Input     string `json:"input,omitempty" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory of APKs or DEX files to process in bulk instead of one input"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many routes and how many serialized fields to return inline, each capped separately; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// APISurface runs --api-surface.
//
// JSON rather than the TSV, and not only by the one-representation rule: the
// counters that say how to read the answer — other_annotations above all — are
// in the report and on stderr, and nowhere in the rows.
//
// --out is not passed here, against the usual rule, because this mode never
// reads it: even in bulk it writes one document to --json-out rather than one
// report per sample. Passing it would name a directory Drakkar would not use.
func (s *Service) APISurface(ctx context.Context, in APISurfaceInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.Input, in.Directory)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("api_surface", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file("report.json")
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		args.Value("--bulk", dir).SwitchIf("--recursive", in.Recursive)
	}
	args.Switch("--api-surface").JSONReport(reportPath)

	env, _, err := s.invoke(ctx, out, timeout, args)
	if err != nil {
		return nil, err
	}
	if err := s.finishAPISurface(env, reportPath, rows); err != nil {
		return nil, err
	}
	return env, nil
}

// finishAPISurface shapes the one report whose root is an array in single mode
// as well as in bulk: [{sample, report:{routes, fields, stats}}].
//
// Neither generic finisher fits it. finishTable would drop the counters that
// exist only in the JSON, other_annotations first among them — the one that
// separates "this sample carries no annotations" from "it carries thousands and
// none of them is a route", which is the mode's actual diagnostic. finishJSON
// would turn the whole array into a single tail, and since a tail truncates the
// outer array and not the inner ones, one sample carrying six thousand
// serialized fields would come back inline in full.
//
// So the two arrays are flattened across samples and previewed separately, and
// the counters are summed into the head. The stats object is summed key by key
// rather than field by field: a counter added upstream reaches the head with no
// change here, the same rule the TSV parser follows for a column.
func (s *Service) finishAPISurface(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			env.note("no JSON report was produced, which is consistent with the exit code above")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var doc []map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	env.ReportPath = path

	routes := []any{}
	fields := []any{}
	stats := map[string]float64{}
	verbs := map[string]int{}
	perSample := map[string]any{}

	for _, entry := range doc {
		sample, _ := entry["sample"].(string)
		report, _ := entry["report"].(map[string]any)

		r := taggedArray(report, "routes", sample)
		f := taggedArray(report, "fields", sample)
		routes = append(routes, r...)
		fields = append(fields, f...)
		perSample[sample] = map[string]int{"routes": len(r), "fields": len(f)}

		for _, item := range r {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			// A route with no verb carries parameter annotations only; it is
			// counted by stats.params_only_methods, not as a verb.
			if v, ok := m["verb"].(string); ok && v != "" {
				verbs[v]++
			}
		}
		for k, v := range mapOf(report["stats"]) {
			n, ok := v.(float64)
			if !ok {
				continue
			}
			stats[k] += n
		}
	}

	head := map[string]any{
		"samples":      len(doc),
		"routes_total": len(routes),
		"fields_total": len(fields),
		"per_verb":     verbs,
		"stats":        stats,
	}
	if len(doc) > 1 {
		head["per_sample"] = perSample
		env.note("routes and fields are flattened across samples and each item names the sample it came from; the report on disk keeps them grouped per sample")
	}
	env.Result = head
	env.Tails = map[string]Tail{
		"routes": makeTail(routes, maxRows),
		"fields": makeTail(fields, maxRows),
	}

	if len(routes) == 0 && len(doc) > 0 {
		env.note("no route was recognised, which means not Retrofit — or Retrofit repackaged under another package name — and never that the sample has no HTTP routes. Weigh stats.other_annotations against stats.annotations_seen to tell those apart, and see drakkar_legend with topic api_surface.")
	}
	return nil
}

// taggedArray pulls one array out of a per-sample report and puts the sample
// name back onto each item. The JSON carries it once per sample, above the
// array; flattening across samples would lose it, and the TSV has it as a
// column.
func taggedArray(report map[string]any, key, sample string) []any {
	arr, _ := report[key].([]any)
	out := make([]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		tagged := make(map[string]any, len(m)+1)
		for k, v := range m {
			tagged[k] = v
		}
		tagged["sample"] = sample
		out = append(out, tagged)
	}
	return out
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// OrphanAuditInput drives --orphan-audit.
type OrphanAuditInput struct {
	Input     string `json:"input,omitempty" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory to process in bulk instead of one input"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many orphan islands to return inline; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// OrphanAudit runs --orphan-audit.
func (s *Service) OrphanAudit(ctx context.Context, in OrphanAuditInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.Input, in.Directory)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("orphan_audit", in.OutDir)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	var reportPath, bulkOut string
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
		reportPath, err = out.file("report.json")
		if err != nil {
			return nil, err
		}
		args.Switch("--orphan-audit").JSONReport(reportPath)
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		bulkOut, err = out.subdir("out")
		if err != nil {
			return nil, err
		}
		args.Switch("--orphan-audit").Value("--bulk", dir).Value("--out", bulkOut).Value("--format", "json")
		args.SwitchIf("--recursive", in.Recursive)
	}

	env, _, err := s.invoke(ctx, out, timeout, args)
	if err != nil {
		return nil, err
	}
	if bulkOut != "" {
		if err := s.finishBulkOut(env, bulkOut, rows); err != nil {
			return nil, err
		}
		return env, nil
	}
	if err := s.finishJSON(env, reportPath, "", nil, rows); err != nil {
		return nil, err
	}
	return env, nil
}

// ProbeInput drives --probe.
type ProbeInput struct {
	Input string `json:"input" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	API   string `json:"api" jsonschema:"substring of class->name, for example System;->loadLibrary or Lorg/c/b;->a"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Probe runs --probe. Text only: the mode has no JSON.
func (s *Service) Probe(ctx context.Context, in ProbeInput) (*Envelope, error) {
	input, err := s.resolveOne("input", in.Input)
	if err != nil {
		return nil, err
	}
	if in.API == "" {
		return nil, fmt.Errorf("api is required")
	}
	out, err := s.begin("probe", in.OutDir)
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(input).Value("--probe", in.API)
	env, res, err := s.invoke(ctx, out, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, out, res.Stdout); err != nil {
		return nil, err
	}
	return env, nil
}

// DisasmInput drives --disasm.
type DisasmInput struct {
	Input    string   `json:"input" jsonschema:"absolute path to one APK or raw DEX, recognised by content rather than by extension"`
	Patterns []string `json:"patterns,omitempty" jsonschema:"substrings of the Dalvik class descriptor to disassemble; omit to take every class read"`

	Normalize []string `json:"normalize,omitempty" jsonschema:"display-only substitutions of the form FROM=TO, for example com/duiyun=com/dy; repeatable"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Disasm runs --disasm. Text only, and deliberately so: the mode ignores
// --format json upstream (drakkar issue #10), so asking for it would produce a
// text file with a .json name.
func (s *Service) Disasm(ctx context.Context, in DisasmInput) (*Envelope, error) {
	input, err := s.resolveOne("input", in.Input)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("disasm", in.OutDir)
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(input).
		Optional("--disasm", in.Patterns).
		Multi("--disasm-normalize", in.Normalize)

	env, res, err := s.invoke(ctx, out, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, out, res.Stdout); err != nil {
		return nil, err
	}
	return env, nil
}

// histogram counts one column, noting the absence rather than inventing a zero.
func (s *Service) histogram(env *Envelope, t *drakkar.Table, column string) map[string]int {
	h, err := t.CountBy(column)
	if err != nil {
		env.note(fmt.Sprintf("no aggregate on %q: %v", column, err))
		return nil
	}
	return h
}
