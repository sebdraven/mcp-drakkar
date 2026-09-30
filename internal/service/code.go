package service

import (
	"context"
	"fmt"

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
