package service

import (
	"context"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// InventoryInput is shared by the three inventory modes: same inputs, same
// flags, three unrelated report shapes.
type InventoryInput struct {
	APK       string `json:"apk,omitempty" jsonschema:"absolute path to one APK"`
	Directory string `json:"directory,omitempty" jsonschema:"absolute path to a directory of APKs to process in bulk instead of one APK"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

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
	out, err := s.begin(tool, in.OutDir)
	if err != nil {
		return nil, err
	}
	rows := ClampRows(in.MaxRows)

	args := drakkar.New()
	if file != "" {
		args.Positional(file)
	}
	args.Switch(mode)

	var reportPath, bulkOut string
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if dir != "" {
		timeout = s.timeout(s.timeouts.Bulk, in.TimeoutSeconds)
		bulkOut, err = out.subdir("out")
		if err != nil {
			return nil, err
		}
		args.Value("--bulk", dir).Value("--out", bulkOut).Value("--format", "json")
		args.SwitchIf("--recursive", in.Recursive)
	} else {
		reportPath, err = out.file("report.json")
		if err != nil {
			return nil, err
		}
		args.JSONReport(reportPath)
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

// NativeArchInput is single-sample only: the mode reads ELF headers in memory.
type NativeArchInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output — reports, parsed rows, extracted files; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeArch runs --native-arch. Text only: the mode has no JSON.
func (s *Service) NativeArch(ctx context.Context, in NativeArchInput) (*Envelope, error) {
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_arch", in.OutDir)
	if err != nil {
		return nil, err
	}
	args := drakkar.New().Positional(apk).Switch("--native-arch")
	env, res, err := s.invoke(ctx, out, s.timeout(s.timeouts.Fast, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishText(env, out, res.Stdout); err != nil {
		return nil, err
	}
	return env, nil
}
