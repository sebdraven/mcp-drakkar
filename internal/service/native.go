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

	Disasm         bool `json:"disasm,omitempty" jsonschema:"also disassemble, statically, every JNI-bound function, JNI_OnLoad and the init_array constructors, decoding JNIEnv calls, PLT imports called and referenced strings; adds the disasm_functions, upcalls and registered_by_code tails, and the instructions themselves stay in report_path"`
	DisasmDepth    *int `json:"disasm_depth,omitempty" jsonschema:"with disasm only: how deep to follow local calls from each disassembled function, 0 to 3; omitted, Drakkar's default"`
	DisasmMaxInsns *int `json:"disasm_max_insns,omitempty" jsonschema:"with disasm only: instruction budget per function, 1 to 20000, past which the function is marked truncated; omitted, Drakkar's default"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many binding rows, and with disasm disasm_functions rows, to return inline; elfs, errors, upcalls and registered_by_code come back whole, and the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

const (
	nativeDisasmMaxDepth = 3
	nativeDisasmMaxInsns = 20000
	// nativeStringRefsPerFunction caps string_refs in each disasm_functions row.
	nativeStringRefsPerFunction = 20
)

// Native runs --native, and --native-disasm on request.
func (s *Service) Native(ctx context.Context, in NativeInput) (*Envelope, error) {
	if err := checkNativeDisasm(in); err != nil {
		return nil, err
	}
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
	timeout := s.timeout(s.timeouts.Fast, in.TimeoutSeconds)
	if in.Disasm {
		timeout = s.timeout(s.timeouts.Diff, in.TimeoutSeconds)
	}
	env, _, err := s.invoke(ctx, out, timeout, nativeArgs(apk, reportPath, in))
	if err != nil {
		return nil, err
	}
	noteUnknownNativeFlags(env, in.Disasm)
	if err := s.finishNative(env, reportPath, ClampRows(in.MaxRows), in.Disasm); err != nil {
		return nil, err
	}
	return env, nil
}

func checkNativeDisasm(in NativeInput) error {
	if !in.Disasm {
		if in.DisasmDepth != nil || in.DisasmMaxInsns != nil {
			return fmt.Errorf("disasm_depth and disasm_max_insns only apply with disasm=true")
		}
		return nil
	}
	if d := in.DisasmDepth; d != nil && (*d < 0 || *d > nativeDisasmMaxDepth) {
		return fmt.Errorf("disasm_depth %d is out of bounds: 0 to %d", *d, nativeDisasmMaxDepth)
	}
	if n := in.DisasmMaxInsns; n != nil && (*n < 1 || *n > nativeDisasmMaxInsns) {
		return fmt.Errorf("disasm_max_insns %d is out of bounds: 1 to %d", *n, nativeDisasmMaxInsns)
	}
	return nil
}

func nativeArgs(apk, reportPath string, in NativeInput) *drakkar.Args {
	args := drakkar.New().Positional(apk).Switch("--native")
	if in.Disasm {
		args.Switch("--native-disasm").Int("--disasm-depth", in.DisasmDepth).Int("--disasm-max-insns", in.DisasmMaxInsns)
	}
	return args.JSONReport(reportPath)
}

func noteUnknownNativeFlags(env *Envelope, disasm bool) {
	if env.Drakkar.ExitCode == 0 {
		return
	}
	if strings.Contains(env.Stderr.Text, "unexpected argument '--native'") {
		env.note("this drakkar does not know --native: it predates the release that introduced it; drakkar_version shows which one is on PATH")
	}
	if disasm && strings.Contains(env.Stderr.Text, "unexpected argument '--native-disasm'") {
		env.note("this drakkar predates --native-disasm; drakkar_version shows which one is on PATH")
	}
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
	Disasm *nativeDisasm `json:"disasm"`
}

type nativeDisasm struct {
	Functions        []nativeFunction `json:"functions"`
	Upcalls          []nativeMember   `json:"upcalls"`
	RegisteredByCode []nativeMember   `json:"registered_by_code"`
}

type nativeFunction struct {
	Origin          string            `json:"origin"`
	Address         any               `json:"address"`
	DisasmStatus    string            `json:"disasm_status"`
	Truncated       bool              `json:"truncated"`
	TruncatedReason *string           `json:"truncated_reason"`
	Instructions    []json.RawMessage `json:"instructions"`
	Calls           []any             `json:"calls"`
	StringRefs      []any             `json:"string_refs"`
	JNICalls        []nativeJNICall   `json:"jni_calls"`
}

// nativeJNICall: name is the JNIEnv function; method is the member it resolved to.
type nativeJNICall struct {
	Name      string  `json:"name"`
	Resolved  bool    `json:"resolved"`
	Class     *string `json:"class"`
	Method    *string `json:"method"`
	Signature *string `json:"signature"`
}

type nativeMember struct {
	Class     string `json:"class"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

// finishNative puts summary in the head and three tails beside it: one row per
// ELF, the binding rows sorted by status then java, and the report's errors.
// With disasm, three more tails and four counters in the head.
func (s *Service) finishNative(env *Envelope, path string, maxRows int, disasm bool) error {
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
	if disasm {
		addNativeDisasm(env, head, r.ELFs, maxRows)
	}
	return nil
}

// addNativeDisasm summarises every disassembled function without its
// instructions, which stay in report.json.
func addNativeDisasm(env *Envelope, head map[string]any, elfs []nativeELF, maxRows int) {
	var functions, upcalls, byCode []any
	truncated, resolved, unresolved, withDisasm := 0, 0, 0, 0
	for _, e := range elfs {
		if e.Disasm == nil {
			continue
		}
		withDisasm++
		for _, f := range e.Disasm.Functions {
			if f.Truncated {
				truncated++
			}
			jni := make([]any, 0, len(f.JNICalls))
			fnUnresolved := 0
			for _, c := range f.JNICalls {
				row := map[string]any{"name": c.Name}
				if c.Resolved {
					setIfPresent(row, "class", c.Class)
					setIfPresent(row, "method", c.Method)
					setIfPresent(row, "signature", c.Signature)
				} else {
					fnUnresolved++
				}
				jni = append(jni, row)
			}
			resolved += len(f.JNICalls) - fnUnresolved
			unresolved += fnUnresolved

			refs := f.StringRefs
			if len(refs) > nativeStringRefsPerFunction {
				refs = refs[:nativeStringRefsPerFunction]
			}
			if refs == nil {
				refs = []any{}
			}
			functions = append(functions, map[string]any{
				"elf":                  e.Path,
				"elf_sha256":           e.SHA256,
				"origin":               f.Origin,
				"address":              f.Address,
				"disasm_status":        f.DisasmStatus,
				"truncated":            f.Truncated,
				"truncated_reason":     stringOrNil(f.TruncatedReason),
				"instructions_count":   len(f.Instructions),
				"calls_count":          len(f.Calls),
				"imports_called":       importsCalled(f.Calls),
				"jni_calls":            jni,
				"jni_calls_unresolved": fnUnresolved,
				"string_refs":          refs,
				"string_refs_total":    len(f.StringRefs),
			})
		}
		upcalls = appendMembers(upcalls, e.Path, e.Disasm.Upcalls)
		byCode = appendMembers(byCode, e.Path, e.Disasm.RegisteredByCode)
	}

	head["disasm_functions_total"] = len(functions)
	head["disasm_truncated"] = truncated
	head["jni_calls_resolved"] = resolved
	head["jni_calls_unresolved"] = unresolved
	env.Tails["disasm_functions"] = makeTail(functions, maxRows)
	env.Tails["upcalls"] = makeTail(upcalls, len(upcalls))
	env.Tails["registered_by_code"] = makeTail(byCode, len(byCode))

	if len(elfs) > 0 && withDisasm == 0 {
		env.note("disasm was requested but no ELF in the report carries a disasm section")
	}
}

func stringOrNil(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func setIfPresent(row map[string]any, key string, v *string) {
	if v != nil && *v != "" {
		row[key] = *v
	}
}

// importsCalled reads the import name a call carries when its target is a PLT entry.
func importsCalled(calls []any) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, c := range calls {
		call, _ := c.(map[string]any)
		name, _ := call["import"].(string)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// appendMembers adds one row per distinct member of one ELF.
func appendMembers(rows []any, elf string, members []nativeMember) []any {
	seen := make(map[nativeMember]bool, len(members))
	for _, m := range members {
		if seen[m] {
			continue
		}
		seen[m] = true
		rows = append(rows, map[string]any{
			"elf":       elf,
			"class":     m.Class,
			"name":      m.Name,
			"signature": m.Signature,
		})
	}
	return rows
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
