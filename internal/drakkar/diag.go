package drakkar

import "strings"

// Drakkar prefixes its per-sample diagnostics on stderr with these markers, in
// main.rs and bulk.rs alike. Counting them is how the number of failed entries
// is obtained without guessing, and [FIN] states it outright for the modes that
// emit one.
const (
	markOK    = "[OK]"
	markFail  = "[FAIL]"
	markPanic = "[PANIC]"
	markWarn  = "[AVERT]"
	markFin   = "[FIN]"
)

// Diag is what the server reports about a run's stderr. Text is the whole of it,
// verbatim, including when the exit code is zero: a warning on a green batch is
// exactly the signal that discarding stderr used to hide.
type Diag struct {
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`

	OK       int `json:"ok"`
	Failed   int `json:"failed"`
	Panicked int `json:"panicked"`
	Warned   int `json:"warned"`

	Fin      string    `json:"fin,omitempty"`
	Failures []Failure `json:"failures,omitempty"`
}

type Failure struct {
	Kind   string `json:"kind"`
	Sample string `json:"sample"`
	Reason string `json:"reason"`
}

// ParseDiag counts the markers and pulls out the named failures. Nothing is
// dropped: unrecognised lines stay in Text, which is returned in full.
func ParseDiag(stderr string, truncated bool) Diag {
	d := Diag{Text: stderr, Truncated: truncated}
	var fins []string

	for _, line := range strings.Split(stderr, "\n") {
		switch {
		case strings.HasPrefix(line, markOK):
			d.OK++
		case strings.HasPrefix(line, markFail):
			d.Failed++
			d.Failures = append(d.Failures, failureFrom("fail", line, markFail))
		case strings.HasPrefix(line, markPanic):
			d.Panicked++
			d.Failures = append(d.Failures, failureFrom("panic", line, markPanic))
		case strings.HasPrefix(line, markWarn):
			d.Warned++
		case strings.HasPrefix(line, markFin):
			fins = append(fins, strings.TrimSpace(strings.TrimPrefix(line, markFin)))
		}
	}
	d.Fin = strings.Join(fins, " | ")
	return d
}

// FailedEntries is the count the caller reports: a panic is a failed entry too.
func (d Diag) FailedEntries() int { return d.Failed + d.Panicked }

// failureFrom splits "[FAIL]  sample — reason" on the em dash Drakkar uses.
func failureFrom(kind, line, mark string) Failure {
	rest := strings.TrimSpace(strings.TrimPrefix(line, mark))
	sample, reason, found := strings.Cut(rest, "—")
	if !found {
		return Failure{Kind: kind, Sample: rest}
	}
	return Failure{
		Kind:   kind,
		Sample: strings.TrimSpace(sample),
		Reason: strings.TrimSpace(reason),
	}
}
