package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// DartSnapshotInput is single-sample only, like --native.
type DartSnapshotInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (libapp.so) recognised by its magic"`

	OutDir string `json:"out_dir" jsonschema:"absolute directory for this call's output; report.json, which holds every string entry, is written there. Required: a Flutter APK yields tens of thousands of entries, and they never go to a temporary directory"`

	MaxRows   *int     `json:"max_rows,omitempty" jsonschema:"passed to Drakkar as --dart-max-rows: how many string entries per data image Drakkar writes into report.json, 0 for all of them; omitted, Drakkar's own default applies. The entries never come back inline, whatever this is"`
	Calibrate []string `json:"calibrate,omitempty" jsonschema:"calibration witnesses, each the text of a string expected in clear in the data image; repeatable, each one visible in the argv. Optional: without a witness no calibration runs"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// dartWitnessesInline caps the witnesses, and the evidence of each inferred
// layout, returned per section; past it they stay in report.json.
const dartWitnessesInline = 5

// DartSnapshot runs --dart-snapshot.
func (s *Service) DartSnapshot(ctx context.Context, in DartSnapshotInput) (*Envelope, error) {
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.OutDir) == "" {
		return nil, fmt.Errorf("out_dir is required: report.json holds every string entry of every data image, so it never goes to a temporary directory")
	}
	if !filepath.IsAbs(in.OutDir) {
		return nil, fmt.Errorf("out_dir must be an absolute path, got %q", in.OutDir)
	}
	if err := checkDartSnapshot(in); err != nil {
		return nil, err
	}
	out, err := s.begin("dart_snapshot", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file("report.json")
	if err != nil {
		return nil, err
	}
	// The long class whether or not witnesses are given: the enumeration runs
	// without them too for any version in Drakkar's table of known versions.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, dartSnapshotArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	unknownFlagNote(env, "--dart-snapshot", "0.5.0")
	if err := s.finishDartSnapshot(env, reportPath, len(in.Calibrate) > 0); err != nil {
		return nil, err
	}
	return env, nil
}

func checkDartSnapshot(in DartSnapshotInput) error {
	if n := in.MaxRows; n != nil && *n < 0 {
		return fmt.Errorf("max_rows %d is out of bounds: 0 for every entry, or a positive count", *n)
	}
	for i, w := range in.Calibrate {
		if strings.TrimSpace(w) == "" {
			return fmt.Errorf("calibrate[%d] is empty or only spaces: a witness of zero length matches at every offset of the data image, and one of spaces nearly as often, so it can only blur the calibration, never support it", i)
		}
	}
	return nil
}

func dartSnapshotArgs(apk, reportPath string, in DartSnapshotInput) *drakkar.Args {
	return drakkar.New().Positional(apk).Switch("--dart-snapshot").
		Int("--dart-max-rows", in.MaxRows).
		Multi("--dart-calibrate", in.Calibrate).
		JSONReport(reportPath)
}

type dartReport struct {
	SHA256    string         `json:"sha256"`
	Summary   map[string]any `json:"summary"`
	Libraries []dartLibrary  `json:"libraries"`
	Errors    []any          `json:"errors"`
}

type dartLibrary struct {
	Path               string        `json:"path"`
	Split              *string       `json:"split"`
	SHA256             string        `json:"sha256"`
	Size               uint64        `json:"size"`
	Sections           []dartSection `json:"sections"`
	MissingSymbols     []string      `json:"missing_symbols"`
	StringsUnavailable *string       `json:"strings_unavailable"`
	Anomalies          []string      `json:"anomalies"`
}

// dartSection declares no entries field: the string entries are skipped while
// decoding and never reach the envelope.
type dartSection struct {
	Symbol             string           `json:"symbol"`
	BlobIndex          *int             `json:"blob_index"`
	FileOffset         *uint64          `json:"file_offset"`
	VAddr              uint64           `json:"vaddr"`
	Size               *uint64          `json:"size"`
	ELFSection         *string          `json:"elf_section"`
	Header             *dartHeader      `json:"header"`
	Serialized         json.RawMessage  `json:"serialized"`
	DataImage          json.RawMessage  `json:"data_image"`
	Calibration        *dartCalibration `json:"calibration"`
	Strings            *dartStrings     `json:"strings"`
	StringsUnavailable *string          `json:"strings_unavailable"`
}

type dartHeader struct {
	MagicOK            bool     `json:"magic_ok"`
	Length             *uint64  `json:"length"`
	Kind               *string  `json:"kind"`
	VersionHash        *string  `json:"version_hash"`
	KnownVersion       *string  `json:"known_version"`
	Features           *string  `json:"features"`
	CompressedPointers *bool    `json:"compressed_pointers"`
	Errors             []string `json:"errors"`
}

type dartStrings struct {
	Heuristic       bool              `json:"heuristic"`
	LayoutSource    string            `json:"layout_source"`
	Candidates      uint64            `json:"candidates"`
	Accepted        uint64            `json:"accepted"`
	Rejected        map[string]uint64 `json:"rejected"`
	EntriesTotal    uint64            `json:"entries_total"`
	EntriesReturned uint64            `json:"entries_returned"`
	Truncated       bool              `json:"truncated"`
}

type dartCalibration struct {
	Outcome              string         `json:"outcome"`
	NotRunReason         *string        `json:"not_run_reason"`
	WitnessesTotal       int            `json:"witnesses_total"`
	WitnessesFound       *int           `json:"witnesses_found"`
	WitnessesInDataImage *int           `json:"witnesses_in_data_image"`
	WitnessesExplained   *int           `json:"witnesses_explained"`
	DataImageVerdict     *string        `json:"data_image_verdict"`
	Witnesses            []dartWitness  `json:"witnesses"`
	WordSize             *int           `json:"word_size"`
	Inferred             []dartInferred `json:"inferred"`
	KnownVersionLiteral  *string        `json:"known_version_literal"`
}

type dartWitness struct {
	Value               string     `json:"value"`
	Encoding            string     `json:"encoding"`
	Length              uint64     `json:"length"`
	Occurrences         *int       `json:"occurrences"`
	OccurrencesExamined *int       `json:"occurrences_examined"`
	Zones               *dartZones `json:"zones"`
	Explained           bool       `json:"explained"`
}

type dartZones struct {
	Serialized dartZoneCount `json:"serialized"`
	DataImage  dartZoneCount `json:"data_image"`
	Outside    dartZoneCount `json:"outside"`
}

type dartZoneCount struct {
	Count       int     `json:"count"`
	FirstOffset *uint64 `json:"first_offset"`
}

type dartInferred struct {
	Layout     json.RawMessage   `json:"layout"`
	DerivedCID *string           `json:"derived_cid"`
	Evidence   []json.RawMessage `json:"evidence"`
}

// finishDartSnapshot puts sha256 and summary in the head and two tails beside
// it, both whole: one row per library, its sections stripped of their string
// entries, and the report's errors. The entries stay in report.json, whatever
// their number.
func (s *Service) finishDartSnapshot(env *Envelope, path string, calibrating bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			env.note("no JSON report was produced, which is consistent with the exit code above")
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r dartReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	env.Result = map[string]any{
		"sha256":  r.SHA256,
		"summary": r.Summary,
	}

	libraries := make([]any, 0, len(r.Libraries))
	witnessesLeftOut := false
	for _, l := range r.Libraries {
		sections := make([]any, 0, len(l.Sections))
		for _, sec := range l.Sections {
			row, cut := dartSectionRow(sec)
			witnessesLeftOut = witnessesLeftOut || cut
			sections = append(sections, row)
		}
		lib := map[string]any{
			"path":                l.Path,
			"sha256":              l.SHA256,
			"size":                l.Size,
			"sections":            sections,
			"missing_symbols":     nonNilStrings(l.MissingSymbols),
			"strings_unavailable": stringOrNil(l.StringsUnavailable),
			"anomalies":           nonNilStrings(l.Anomalies),
		}
		setIfPresent(lib, "split", l.Split)
		libraries = append(libraries, lib)
	}

	errs := r.Errors
	if errs == nil {
		errs = []any{}
	}
	env.Tails = map[string]Tail{
		"libraries": makeTail(libraries, len(libraries)),
		"errors":    makeTail(errs, len(errs)),
	}
	env.ReportPath = path

	env.note("the string entries are in report_path only, under libraries[].sections[].strings.entries; they never come back inline, and each section's strings row counts them")
	if len(r.Libraries) == 0 {
		env.note("the report lists no library: Drakkar found no Dart AOT snapshot in this input")
	}
	if !calibrating {
		env.note("no calibration witness was given, so no section carries a calibration: strings are enumerated only for the snapshot versions Drakkar's table knows")
	}
	if witnessesLeftOut {
		env.note(fmt.Sprintf("a section's calibration witnesses, or an inferred layout's evidence, come back inline only up to %d; past that only the counts are here and the detail is in report_path", dartWitnessesInline))
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// dartSectionRow keeps a section's location, header, spans, string counters and
// calibration. It reports whether any witness or evidence list was left out.
func dartSectionRow(sec dartSection) (map[string]any, bool) {
	row := map[string]any{
		"symbol":      sec.Symbol,
		"blob_index":  intOrNil(sec.BlobIndex),
		"file_offset": uint64OrNil(sec.FileOffset),
		"vaddr":       sec.VAddr,
		"size":        uint64OrNil(sec.Size),
		"elf_section": stringOrNil(sec.ELFSection),
		"header":      dartHeaderRow(sec.Header),
		"serialized":  rawOrNil(sec.Serialized),
		"data_image":  rawOrNil(sec.DataImage),
	}
	if sec.Strings != nil {
		rejected := sec.Strings.Rejected
		if rejected == nil {
			rejected = map[string]uint64{}
		}
		row["strings"] = map[string]any{
			"heuristic":        sec.Strings.Heuristic,
			"layout_source":    sec.Strings.LayoutSource,
			"candidates":       sec.Strings.Candidates,
			"accepted":         sec.Strings.Accepted,
			"rejected":         rejected,
			"entries_total":    sec.Strings.EntriesTotal,
			"entries_returned": sec.Strings.EntriesReturned,
			"truncated":        sec.Strings.Truncated,
		}
	}
	if sec.StringsUnavailable != nil {
		row["strings_unavailable"] = *sec.StringsUnavailable
	}
	cut := false
	if sec.Calibration != nil {
		row["calibration"], cut = dartCalibrationRow(sec.Calibration)
	}
	return row, cut
}

func dartHeaderRow(h *dartHeader) any {
	if h == nil {
		return nil
	}
	return map[string]any{
		"magic_ok":            h.MagicOK,
		"length":              uint64OrNil(h.Length),
		"kind":                stringOrNil(h.Kind),
		"version_hash":        stringOrNil(h.VersionHash),
		"known_version":       stringOrNil(h.KnownVersion),
		"features":            stringOrNil(h.Features),
		"compressed_pointers": boolOrNil(h.CompressedPointers),
		"errors":              nonNilStrings(h.Errors),
	}
}

// dartCalibrationRow sums each witness's zone counts into witness_zones, so the
// split between the serialized part, the data image and the rest survives when
// the witnesses themselves are left out.
func dartCalibrationRow(c *dartCalibration) (map[string]any, bool) {
	cut := false
	row := map[string]any{
		"outcome":                 c.Outcome,
		"not_run_reason":          stringOrNil(c.NotRunReason),
		"witnesses_total":         c.WitnessesTotal,
		"witnesses_found":         intOrNil(c.WitnessesFound),
		"witnesses_in_data_image": intOrNil(c.WitnessesInDataImage),
		"witnesses_explained":     intOrNil(c.WitnessesExplained),
		"data_image_verdict":      stringOrNil(c.DataImageVerdict),
		"word_size":               intOrNil(c.WordSize),
		"known_version_literal":   stringOrNil(c.KnownVersionLiteral),
	}

	var zones map[string]int
	for _, w := range c.Witnesses {
		if w.Zones == nil {
			continue
		}
		if zones == nil {
			zones = map[string]int{"serialized": 0, "data_image": 0, "outside": 0}
		}
		zones["serialized"] += w.Zones.Serialized.Count
		zones["data_image"] += w.Zones.DataImage.Count
		zones["outside"] += w.Zones.Outside.Count
	}
	if zones != nil {
		row["witness_zones"] = zones
	} else {
		row["witness_zones"] = nil
	}
	if len(c.Witnesses) <= dartWitnessesInline {
		witnesses := c.Witnesses
		if witnesses == nil {
			witnesses = []dartWitness{}
		}
		row["witnesses"] = witnesses
	} else {
		cut = true
	}

	inferred := make([]any, 0, len(c.Inferred))
	for _, inf := range c.Inferred {
		item := map[string]any{
			"layout":         rawOrNil(inf.Layout),
			"derived_cid":    stringOrNil(inf.DerivedCID),
			"evidence_total": len(inf.Evidence),
		}
		if len(inf.Evidence) <= dartWitnessesInline {
			evidence := inf.Evidence
			if evidence == nil {
				evidence = []json.RawMessage{}
			}
			item["evidence"] = evidence
		} else {
			cut = true
		}
		inferred = append(inferred, item)
	}
	row["inferred"] = inferred
	return row, cut
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func intOrNil(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func uint64OrNil(v *uint64) any {
	if v == nil {
		return nil
	}
	return *v
}

// rawOrNil passes a sub-object through as Drakkar wrote it, null when absent.
func rawOrNil(v json.RawMessage) any {
	if len(v) == 0 || string(v) == "null" {
		return nil
	}
	return v
}
