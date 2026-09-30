package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
	"github.com/sebdraven/mcp-drakkar/internal/version"
)

// VersionInput takes nothing: the point of this tool is that it works before
// anything is configured.
type VersionInput struct{}

// Version reports which Drakkar is on the PATH and what perimeter the server is
// running with. It exists so that a measurement can be dated — today nothing in
// a conversation says which Drakkar produced a number — and so that "the binary
// is missing" is a clear answer rather than a puzzling failure elsewhere.
func (s *Service) Version(ctx context.Context, _ VersionInput) (*Envelope, error) {
	s.RefreshVersion()

	runner := drakkar.NewRunner("")
	path, lookErr := runner.Lookup()

	timeouts := map[string]string{
		"fast":   s.timeouts.Fast.String(),
		"diff":   s.timeouts.Diff.String(),
		"matrix": s.timeouts.Matrix.String(),
		"bulk":   s.timeouts.Bulk.String(),
	}
	result := map[string]any{
		"server_version": version.Version,
		"server_commit":  version.Commit,
		"drakkar_tested": version.DrakkarTested,
		"corpus_dirs":    s.scope.Roots(),
		"timeouts":       timeouts,
	}
	if bad := s.scope.BadRoots(); len(bad) > 0 {
		result["corpus_dirs_unusable"] = bad
	}
	if reports, err := s.scope.ReportsDir(); err == nil {
		result["reports_dir"] = reports
	} else {
		result["reports_dir_error"] = err.Error()
	}

	env := &Envelope{
		Drakkar: Meta{
			Server: version.Version,
			Tested: version.DrakkarTested,
		},
	}
	if lookErr != nil {
		result["drakkar_path_error"] = lookErr.Error()
		env.Result = result
		env.note("drakkar is not callable, so every analysis tool will refuse; this server never builds or installs it")
		return env, nil
	}
	result["drakkar_path"] = path

	args := drakkar.New().Switch("--version")
	ran, res, err := s.invokeIn(ctx, "", 15*time.Second, args)
	if err != nil {
		result["drakkar_version_error"] = err.Error()
		env.Result = result
		return env, nil
	}
	result["drakkar_version"] = strings.TrimSpace(string(res.Stdout))
	ran.Result = result
	return ran, nil
}

// LegendInput selects which legend to print.
type LegendInput struct {
	Topic string `json:"topic" jsonschema:"one of manifest, cert, dating, assets, entries, resources, diff_dex, diff_strings, diff_explain, diff_matrix, disasm"`
}

// Legend prints Drakkar's own legend for a mode. These texts are what keeps a
// metric from being misread — the resources one states outright that orphan does
// not mean unused, the diff-dex one that 0.85 is not a published threshold — so
// they are worth being callable.
func (s *Service) Legend(ctx context.Context, in LegendInput) (*Envelope, error) {
	args := drakkar.New().Switch("--legend")
	var note string

	switch in.Topic {
	case "manifest":
		// The standalone legend branch falls through to the manifest legend.
	case "cert":
		args.Switch("--cert")
	case "dating":
		args.Switch("--dating")
	case "assets":
		args.Switch("--list-assets")
	case "entries":
		args.Switch("--list-entries")
	case "resources":
		args.Switch("--resource-xref")
	case "disasm":
		args.Optional("--disasm", nil)
	case "diff_dex":
		args.Pair("--diff-dex", legendPlaceholder, legendPlaceholder)
		note = legendPlaceholderNote
	case "diff_strings":
		args.Pair("--diff-strings", legendPlaceholder, legendPlaceholder)
		note = legendPlaceholderNote
	case "diff_explain":
		args.Pair("--diff-explain", legendPlaceholder, legendPlaceholder)
		note = legendPlaceholderNote
	case "diff_matrix":
		args.Value("--diff-matrix", legendPlaceholder)
		note = legendPlaceholderNote
	default:
		return nil, fmt.Errorf("topic %q is not one of manifest, cert, dating, assets, entries, resources, diff_dex, diff_strings, diff_explain, diff_matrix, disasm", in.Topic)
	}

	env, res, err := s.invokeIn(ctx, "", 30*time.Second, args)
	if err != nil {
		return nil, err
	}
	env.Result = map[string]any{
		"topic": in.Topic,
		"text":  string(res.Stdout),
	}
	if note != "" {
		env.note(note)
	}
	return env, nil
}

// The diff legends live inside a branch clap will not enter without its operands,
// so they are supplied. Drakkar prints the legend and returns before opening
// anything, so no file is read; if that order ever changed the call would fail
// loudly on a missing path rather than answer something wrong.
const (
	legendPlaceholder     = "LEGEND-ONLY-PLACEHOLDER"
	legendPlaceholderNote = "the operands in argv are placeholders: this mode's legend sits behind a flag clap requires operands for, and Drakkar prints it before opening any input"
)
