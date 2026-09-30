package service

import (
	"context"

	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
)

// The four diff modes share a shape: a head of scalars that is the measurement,
// and arrays that are the evidence. by_kind, groups and failed are bounded and
// answer the question, so they stay inline; everything else becomes a declared
// preview over a complete report on disk.

// DiffDexInput drives --diff-dex.
type DiffDexInput struct {
	A string `json:"a" jsonschema:"first input, an APK or a raw DEX inside a configured corpus directory"`
	B string `json:"b" jsonschema:"second input, an APK or a raw DEX inside a configured corpus directory"`

	Include   []string `json:"include,omitempty" jsonschema:"only compare classes whose Dalvik descriptor starts with one of these prefixes, for example Lcom/dy/; pass the prefixes of both sides"`
	Normalize []string `json:"normalize,omitempty" jsonschema:"substitutions of the form FROM=TO applied to the class descriptor to build the pairing key, for example com/duiyun=com/dy; repeatable"`

	Threshold *float64 `json:"threshold,omitempty" jsonschema:"method Jaccard above which two non-identical classes count as near; omit to leave Drakkar's own value in force, which is not a published empirical threshold"`
	Ngram     *int     `json:"ngram,omitempty" jsonschema:"window size of the global method-word n-gram; omit to leave Drakkar's own value in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entries of each array to return inline; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// DiffDex runs --diff-dex.
func (s *Service) DiffDex(ctx context.Context, in DiffDexInput) (*Envelope, error) {
	a, b, err := s.resolvePair(in.A, in.B)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("diff_dex")
	if err != nil {
		return nil, err
	}
	reportPath, err := run.Path("report.json")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().
		Pair("--diff-dex", a, b).
		Multi("--diff-include", in.Include).
		Multi("--diff-normalize", in.Normalize).
		Float("--diff-threshold", in.Threshold).
		Int("--diff-ngram", in.Ngram).
		JSONReport(reportPath)

	env, _, err := s.invoke(ctx, run, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishJSON(env, reportPath, "", nil, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// DiffStringsInput drives --diff-strings.
type DiffStringsInput struct {
	A string `json:"a" jsonschema:"first input, an APK or a raw DEX inside a configured corpus directory"`
	B string `json:"b" jsonschema:"second input, an APK or a raw DEX inside a configured corpus directory"`

	Normalize []string `json:"normalize,omitempty" jsonschema:"substitutions of the form FROM=TO applied before comparison, for example spyzie=BRAND, to keep only what differs beyond the name; repeatable"`

	LiteralsOnly bool `json:"literals_only,omitempty" jsonschema:"mask the structural noise of the DEX format: Dalvik descriptors and bare identifiers"`

	MinLength *int `json:"min_length,omitempty" jsonschema:"ignore strings shorter than this; omit to leave Drakkar's own value in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entries of each array to return inline; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// DiffStrings runs --diff-strings.
func (s *Service) DiffStrings(ctx context.Context, in DiffStringsInput) (*Envelope, error) {
	a, b, err := s.resolvePair(in.A, in.B)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("diff_strings")
	if err != nil {
		return nil, err
	}
	reportPath, err := run.Path("report.json")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().
		Pair("--diff-strings", a, b).
		Multi("--strings-normalize", in.Normalize).
		SwitchIf("--strings-literals", in.LiteralsOnly).
		Int("--strings-min-len", in.MinLength).
		JSONReport(reportPath)

	env, _, err := s.invoke(ctx, run, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishJSON(env, reportPath, "", []string{"by_kind"}, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// DiffExplainInput drives --diff-explain.
type DiffExplainInput struct {
	A string `json:"a" jsonschema:"first input, an APK or a raw DEX inside a configured corpus directory"`
	B string `json:"b" jsonschema:"second input, an APK or a raw DEX inside a configured corpus directory"`

	Include   []string `json:"include,omitempty" jsonschema:"only compare classes whose Dalvik descriptor starts with one of these prefixes; pass the prefixes of both sides"`
	Normalize []string `json:"normalize,omitempty" jsonschema:"substitutions of the form FROM=TO applied before comparison; indispensable between two differently-obfuscated namespaces, otherwise every operand diverges on the namespace alone"`

	Context  *int `json:"context,omitempty" jsonschema:"identical context lines shown around each change in the LCS-aligned rendering; omit to leave Drakkar's own value in force"`
	AlignCap *int `json:"align_cap,omitempty" jsonschema:"per-method instruction ceiling for LCS alignment, which is quadratic in time and memory; omit to leave Drakkar's own value in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many entries of each array to return inline; the whole report stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call"`
}

// DiffExplain runs --diff-explain.
func (s *Service) DiffExplain(ctx context.Context, in DiffExplainInput) (*Envelope, error) {
	a, b, err := s.resolvePair(in.A, in.B)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("diff_explain")
	if err != nil {
		return nil, err
	}
	reportPath, err := run.Path("report.json")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().
		Pair("--diff-explain", a, b).
		Multi("--explain-include", in.Include).
		Multi("--explain-normalize", in.Normalize).
		Int("--explain-context", in.Context).
		Int("--explain-align-cap", in.AlignCap).
		JSONReport(reportPath)

	env, _, err := s.invoke(ctx, run, s.timeout(s.timeouts.Diff, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishJSON(env, reportPath, "", []string{"by_kind"}, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

// DiffMatrixInput drives --diff-matrix.
//
// --matrix-top is deliberately not exposed: it truncates the text ranking only,
// and the JSON report carries every pair regardless. Exposing it would suggest a
// bound on the answer that it does not place.
type DiffMatrixInput struct {
	Directory string `json:"directory" jsonschema:"directory of APKs or raw DEX files, inside a configured corpus directory"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"walk subdirectories too"`

	Metric    string   `json:"metric,omitempty" jsonschema:"which metric drives the matrix and the grouping: opcodes for same engine, strings for same constants; both are computed either way; omit to leave Drakkar's own choice in force"`
	Normalize []string `json:"normalize,omitempty" jsonschema:"substitutions of the form FROM=TO applied to descriptors and strings before comparison; indispensable on a multi-namespace batch, otherwise descriptors sink the similarity for a reason unrelated to the code"`

	Threshold *float64 `json:"threshold,omitempty" jsonschema:"single-linkage grouping threshold; omit to leave Drakkar's own value in force"`

	MaxRows        *int `json:"max_rows,omitempty" jsonschema:"how many pairs and samples to return inline; the whole n-squared matrix stays on disk"`
	TimeoutSeconds *int `json:"timeout_seconds,omitempty" jsonschema:"override the timeout for this call; an all-against-all run over a hundred samples takes a while"`
}

// DiffMatrix runs --diff-matrix. The pairs in the report are already sorted by
// the chosen metric, descending, so the inline preview is the top of the ranking.
func (s *Service) DiffMatrix(ctx context.Context, in DiffMatrixInput) (*Envelope, error) {
	dir, err := s.scope.Dir(in.Directory)
	if err != nil {
		return nil, err
	}
	run, err := s.begin("diff_matrix")
	if err != nil {
		return nil, err
	}
	reportPath, err := run.Path("report.json")
	if err != nil {
		return nil, err
	}
	args := drakkar.New().
		Value("--diff-matrix", dir).
		SwitchIf("--recursive", in.Recursive).
		ValueIf("--matrix-metric", in.Metric).
		Multi("--matrix-normalize", in.Normalize).
		Float("--matrix-threshold", in.Threshold).
		JSONReport(reportPath)

	env, _, err := s.invoke(ctx, run, s.timeout(s.timeouts.Matrix, in.TimeoutSeconds), args)
	if err != nil {
		return nil, err
	}
	if err := s.finishJSON(env, reportPath, "", []string{"groups", "failed"}, ClampRows(in.MaxRows)); err != nil {
		return nil, err
	}
	return env, nil
}

func (s *Service) resolvePair(a, b string) (string, string, error) {
	resolved, err := s.scope.Files([]string{a, b})
	if err != nil {
		return "", "", err
	}
	if len(resolved) != 2 {
		return "", "", errTwoInputs
	}
	return resolved[0], resolved[1], nil
}
