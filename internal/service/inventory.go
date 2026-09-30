package service

import (
	"context"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// InventoryInput is shared by the three inventory modes: same inputs, same
// flags, three unrelated report shapes.
type InventoryInput struct {
	APK       string `json:"apk,omitempty" jsonschema:"path to one APK, inside a configured corpus directory"`
	Directory string `json:"directory,omitempty" jsonschema:"path to a directory of APKs to process in bulk instead of one APK"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"in bulk, how many per-sample reports to return inline; the rest stay on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Manifest runs --manifest.
func (s *Service) Manifest(ctx context.Context, in InventoryInput) (*Envelope, error) {
	return s.inventory(ctx, "manifest", "--manifest", in)
}

// Cert runs --cert.
func (s *Service) Cert(ctx context.Context, in InventoryInput) (*Envelope, error) {
	return s.inventory(ctx, "cert", "--cert", in)
}

// Dating runs --dating.
func (s *Service) Dating(ctx context.Context, in InventoryInput) (*Envelope, error) {
	return s.inventory(ctx, "dating", "--dating", in)
}

func (s *Service) inventory(ctx context.Context, tool, mode string, in InventoryInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.APK, in.Directory)
	if err != nil {
		return nil, err
	}
	run, err := s.begin(tool)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	if file != "" {
		args.Positional(file)
	}
	args.Switch(mode)

	var reportPath, outDir string
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if dir != "" {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		outDir, err = run.Subdir("out")
		if err != nil {
			return nil, err
		}
		args.Value("--bulk", dir).Value("--out", outDir).Value("--format", "json")
		args.SwitchIf("--recursive", in.Recursive)
	} else {
		reportPath, err = run.Path("report.json")
		if err != nil {
			return nil, err
		}
		args.JSONReport(reportPath)
	}

	env, _, err := s.invoke(ctx, run, timeout, args)
	if err != nil {
		return nil, err
	}
	if outDir != "" {
		if err := s.finishBulkOut(env, outDir, rows); err != nil {
			return nil, err
		}
		return env, nil
	}
	if err := s.finishJSON(env, reportPath, "", nil, rows); err != nil {
		return nil, err
	}
	return env, nil
}

// NativeArchInput is single-sample only: the mode reads ELF headers in memory.
type NativeArchInput struct {
	APK string `json:"apk" jsonschema:"path to one APK, inside a configured corpus directory"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeArch runs --native-arch. Text only: the mode has no JSON.
func (s *Service) NativeArch(ctx context.Context, in NativeArchInput) (*Envelope, error) {
	apk, err := s.resolveOne(in.APK)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("native_arch")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(apk).Switch("--native-arch")
	env, res, err := s.invoke(ctx, run, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, run, res.Stdout); err != nil {
		return nil, err
	}
	return env, nil
}
