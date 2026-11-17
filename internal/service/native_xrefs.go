package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// maxXrefsAddresses is Drakkar's MAX_XREFS_TARGETS.
const maxXrefsAddresses = 64

// NativeXrefsInput is single-sample only, like --native.
type NativeXrefsInput struct {
	APK string `json:"apk" jsonschema:"absolute path to one APK, or to one raw ELF (.so) recognised by its magic"`

	ELF string `json:"elf,omitempty" jsonschema:"path of the ELF inside the APK (elfs[].path of drakkar_native, the file name for a raw ELF), or *; omitted, * takes every AArch64 ELF with an allocated section holding the address"`

	Addresses []string `json:"addresses" jsonschema:"1 to 64 hex addresses to look up, 0x prefix optional; duplicates count once, as Drakkar drops them"`

	Max *int `json:"max,omitempty" jsonschema:"references Drakkar keeps per list and per address (--native-xrefs-max); totals stay exact; omitted, Drakkar's default"`

	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute directory for this call's output; omitted, a fresh directory under the system temp directory is used and its path comes back in report_path"`

	Background bool `json:"background,omitempty" jsonschema:"run as a job detached from this request and answer at once with a job_id; out_dir is then required, and drakkar_job_status gives the outcome"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many rows of code_refs, addr_refs and data_refs, each, to return inline, every address together; the whole report stays in report_path"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// NativeXrefs runs --native --native-xrefs.
func (s *Service) NativeXrefs(ctx context.Context, in NativeXrefsInput) (*Envelope, error) {
	if err := checkNativeXrefs(in); err != nil {
		return nil, err
	}
	apk, err := s.resolveOne("apk", in.APK)
	if err != nil {
		return nil, err
	}
	out, err := s.begin("native_xrefs", in.OutDir)
	if err != nil {
		return nil, err
	}
	reportPath, err := out.file("report.json")
	if err != nil {
		return nil, err
	}
	// A refused run writes no report: an earlier one must not pass for it.
	if err := os.Remove(reportPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("removing the earlier report at %s: %w", reportPath, err)
	}
	// Same class as drakkar_native_symex: both walk code.
	timeout := s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	env, _, err := s.invoke(ctx, out, timeout, nativeXrefsArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	if err := s.finishNativeXrefs(env, reportPath, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// checkNativeXrefs checks the form only; Drakkar refuses the rest.
func checkNativeXrefs(in NativeXrefsInput) error {
	if len(in.Addresses) == 0 {
		return errors.New("addresses is empty: give 1 to 64 hex addresses")
	}
	distinct := map[uint64]bool{}
	for i, a := range in.Addresses {
		if !isHexAddress(a) {
			return fmt.Errorf("addresses[%d] %q is not a hex address", i, a)
		}
		v, _ := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 64)
		distinct[v] = true
	}
	if len(distinct) > maxXrefsAddresses {
		return fmt.Errorf("%d distinct addresses: give 1 to %d", len(distinct), maxXrefsAddresses)
	}
	if in.Max != nil && *in.Max < 0 {
		return fmt.Errorf("max %d is negative", *in.Max)
	}
	return nil
}

// nativeXrefsArgs builds <elf|*>@<a1>,<a2>,... as Drakkar splits it.
func nativeXrefsArgs(apk, reportPath string, in NativeXrefsInput) *drakkar.Args {
	elf := in.ELF
	if elf == "" {
		elf = "*"
	}
	return drakkar.New().Positional(apk).Switch("--native").
		Value("--native-xrefs", elf+"@"+strings.Join(in.Addresses, ",")).
		Int("--native-xrefs-max", in.Max).
		JSONReport(reportPath)
}

var (
	nativeXrefsHeadKeys = []string{"elf", "target", "section", "function"}
	nativeXrefsLists    = []string{"code_refs", "addr_refs", "data_refs"}
)

type nativeXrefsReport struct {
	Xrefs  []map[string]any `json:"xrefs"`
	Errors []any            `json:"errors"`
}

// finishNativeXrefs puts one summary per xrefs entry in the head, and the
// items of every entry in one tail per list, cut at maxRows.
func (s *Service) finishNativeXrefs(env *Envelope, path string, maxRows int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if env.Drakkar.ExitCode != 0 || env.Drakkar.TimedOut {
			noteNativeXrefsRefusal(env)
			return nil
		}
		return fmt.Errorf("reading the report Drakkar was asked to write at %s: %w", path, err)
	}
	var r nativeXrefsReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	heads := make([]any, 0, len(r.Xrefs))
	rows := map[string][]any{}
	var cut, empty []string
	for _, e := range r.Xrefs {
		head := map[string]any{}
		for _, k := range nativeXrefsHeadKeys {
			if v, ok := e[k]; ok {
				head[k] = v
			}
		}
		where := fmt.Sprintf("%v in %v", e["target"], e["elf"])
		zero := 0
		for _, name := range nativeXrefsLists {
			list, ok := e[name].(map[string]any)
			if !ok {
				continue
			}
			counts := map[string]any{}
			for _, k := range []string{"total", "truncated"} {
				if v, ok := list[k]; ok {
					counts[k] = v
				}
			}
			head[name] = counts
			items, _ := list["items"].([]any)
			for _, it := range items {
				rows[name] = append(rows[name], xrefsRow(e, it))
			}
			if list["truncated"] == true {
				cut = append(cut, fmt.Sprintf("%s for %s: Drakkar kept %d of %v", name, where, len(items), list["total"]))
			}
			if list["total"] == float64(0) {
				zero++
			}
		}
		if zero == len(nativeXrefsLists) {
			empty = append(empty, where)
		}
		heads = append(heads, head)
	}
	errs := r.Errors
	if errs == nil {
		errs = []any{}
	}

	env.Result = map[string]any{"xrefs": heads}
	env.Tails = map[string]Tail{"errors": makeTail(errs, len(errs))}
	for _, name := range nativeXrefsLists {
		env.Tails[name] = makeTail(rows[name], maxRows)
	}
	env.ReportPath = path

	if len(r.Xrefs) == 0 {
		env.note("the report holds no xrefs entry: errors says why")
	}
	for _, c := range cut {
		env.note(c + " (exact total); max raises Drakkar's cap per list and per address")
	}
	for _, w := range empty {
		env.note("no static reference to " + w + ": not a proof of absence — an indirect branch, a computed address, an ADRP and its ADD far apart, a jump table, or encrypted or generated code escape the search")
	}
	if len(errs) > 0 {
		env.note(fmt.Sprintf("%d error(s) in the report", len(errs)))
	}
	return nil
}

// noteNativeXrefsRefusal relays Drakkar's own message when it wrote no report.
func noteNativeXrefsRefusal(env *Envelope) {
	line := errorLine(env.Stderr.Text)
	if strings.Contains(env.Stderr.Text, "unexpected argument '--native-xrefs") {
		env.note("this drakkar does not know --native-xrefs: it predates the mode; drakkar_version shows which one is on PATH")
	} else {
		env.note("no JSON report was produced, which is consistent with the exit code above")
	}
	if line == "" {
		return
	}
	env.note("Drakkar's message, verbatim: " + line)
	env.Tails = map[string]Tail{"errors": makeTail([]any{line}, 1)}
}

// xrefsRow copies an item and adds the elf and target of its entry, so that
// rows from several entries stay apart.
func xrefsRow(entry map[string]any, v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	row := make(map[string]any, len(m)+2)
	for k, x := range m {
		row[k] = x
	}
	for _, k := range []string{"elf", "target"} {
		if x, ok := entry[k]; ok {
			row[k] = x
		}
	}
	return row
}
