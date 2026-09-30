package service

import (
	"context"
	"fmt"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// ResourcesInput drives the resource table modes. They are one tool because
// Drakkar dispatches them as one branch with one output shape; the selector is a
// closed enumeration, so the whitelist property is intact.
type ResourcesInput struct {
	APK       string `json:"apk,omitempty" jsonschema:"path to one APK, inside a configured corpus directory"`
	Directory string `json:"directory,omitempty" jsonschema:"path to a directory of APKs to process in bulk instead of one APK"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"in bulk, walk subdirectories too"`

	Mode string `json:"mode" jsonschema:"which view: name resolves resource names, id resolves resource identifiers, dump lists the table, xref joins DEX constants to real resource entries, orphans lists resources no DEX constant references"`

	Names []string `json:"names,omitempty" jsonschema:"for mode name: the resource names to resolve, the key of R.type.name; repeatable"`
	IDs   []string `json:"ids,omitempty" jsonschema:"for mode id: identifiers as 0x7f110228, 7f110228 or 2131886120; repeatable"`
	Types []string `json:"types,omitempty" jsonschema:"for mode dump: restrict to these resource types, for example string, layout, drawable; omit for every type"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entries to return inline; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// Resources runs one of --resource, --resource-id, --resources, --resource-xref
// or --resource-orphans.
func (s *Service) Resources(ctx context.Context, in ResourcesInput) (*Envelope, error) {
	file, dir, err := s.resolveSingleOrBulk(in.APK, in.Directory)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("resources_" + in.Mode)
	if err != nil {
		return nil, err
	}
	reportPath, err := run.Path("report.json")
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

	switch in.Mode {
	case "name":
		if len(in.Names) == 0 {
			return nil, fmt.Errorf("mode name needs at least one entry in names")
		}
		args.Multi("--resource", in.Names)
	case "id":
		if len(in.IDs) == 0 {
			return nil, fmt.Errorf("mode id needs at least one entry in ids")
		}
		args.Multi("--resource-id", in.IDs)
	case "dump":
		args.Optional("--resources", in.Types)
	case "xref":
		args.Switch("--resource-xref")
		timeout = s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	case "orphans":
		args.Switch("--resource-orphans")
		timeout = s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	default:
		return nil, fmt.Errorf("mode %q is not one of name, id, dump, xref, orphans", in.Mode)
	}
	args.JSONReport(reportPath)

	env, _, err := s.invoke(ctx, run, timeout, args)
	if err != nil {
		return nil, err
	}
	// In bulk the report is an array of per-sample payloads; in single it is the
	// payload itself.
	if err := s.finishJSON(env, reportPath, "samples", nil, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	if in.Mode == "orphans" {
		env.note("orphan here means not referenced from the code, never unused: a resource cited by a layout, a style, a theme or the manifest is orphan by this measure and perfectly used. See drakkar_legend with topic resources.")
	}
	return env, nil
}
