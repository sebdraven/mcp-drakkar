package service

import (
	"context"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// ScanInput drives the rules pipeline, Drakkar's default mode.
//
// --rules is deliberately not exposed: pointing the engine at an arbitrary
// directory is a bench configuration decision, and it would let a caller name
// any directory on the machine for the server to read.
type ScanInput struct {
	APK       string `json:"apk,omitempty" jsonschema:"path to one APK, inside a configured corpus directory"`
	Directory string `json:"directory,omitempty" jsonschema:"path to a directory of APKs to process in bulk instead of one APK"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"in bulk, re-analyse a sample whose output JSON already exists"`

	Refresh     bool `json:"refresh,omitempty" jsonschema:"force a re-download of the MITRE catalogue and a rebuild of the rule cache; this one reaches the network"`
	ExportGraph bool `json:"export_graph,omitempty" jsonschema:"single sample only: also write the call graph as NetworkX node-link JSON into this call's report directory"`

	Jobs *int `json:"jobs,omitempty" jsonschema:"in bulk, rayon worker threads; omit to leave Drakkar's own value in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many detections or per-sample reports to return inline; the whole set stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Scan runs the rule engine. Unlike every other mode this one loads the MITRE
// catalogue, so the first call after a cache miss reaches the network.
func (s *Service) Scan(ctx context.Context, in ScanInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.APK, in.Directory)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("scan")
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	var outDir, graphPath string
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	if file != "" {
		args.Positional(file)
		if in.ExportGraph {
			graphPath, err = run.Path("call-graph.json")
			if err != nil {
				return nil, err
			}
			args.Value("--export-graph", graphPath)
		}
	} else {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		outDir, err = run.Subdir("out")
		if err != nil {
			return nil, err
		}
		args.Value("--bulk", dir).Value("--out", outDir).
			SwitchIf("--recursive", in.Recursive).
			SwitchIf("--overwrite", in.Overwrite).
			Int("--jobs", in.Jobs)
	}
	args.SwitchIf("--refresh", in.Refresh)

	env, res, err := s.invoke(ctx, run, timeout, args)
	if err != nil {
		return nil, err
	}
	if outDir != "" {
		if err := s.finishBulkOut(env, outDir, rows); err != nil {
			return nil, err
		}
		return env, nil
	}
	// In single mode the pipeline prints its detections rather than writing them,
	// and the document root is an array.
	if err := s.finishJSONStdout(env, run, res.Stdout, "detections", nil, rows); err != nil {
		return nil, err
	}
	if graphPath != "" {
		env.Written = append(env.Written, graphPath)
	}
	return env, nil
}
