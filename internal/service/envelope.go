package service

import "github.com/sebdraven/mcp-drakkar/internal/drakkar"

// Envelope is the same shape for every tool. A caller that learns to read one
// tool's answer can read all of them, and the fields that matter for trusting a
// measurement — which Drakkar, which argv, which exit code, what stderr said —
// are never the ones left out.
type Envelope struct {
	Drakkar Meta         `json:"drakkar"`
	Stderr  drakkar.Diag `json:"stderr"`

	Result any             `json:"result,omitempty"`
	Tails  map[string]Tail `json:"tails,omitempty"`
	Rows   *RowSet         `json:"rows,omitempty"`

	ReportPath string   `json:"report_path,omitempty"`
	Written    []string `json:"written,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

type Meta struct {
	Server  string `json:"server"`
	Version string `json:"drakkar_version"`
	Tested  string `json:"drakkar_tested"`

	Argv     []string `json:"argv"`
	ExitCode int      `json:"exit_code"`

	DurationMS      int64 `json:"duration_ms"`
	TimedOut        bool  `json:"timed_out"`
	StdoutTruncated bool  `json:"stdout_truncated,omitempty"`
}

// RowSet is what a TSV mode returns: the header as read, a declared preview, and
// the count of rows whose field count did not match that header.
type RowSet struct {
	Header    []string `json:"header,omitempty"`
	Total     int      `json:"total"`
	Returned  int      `json:"returned"`
	Truncated bool     `json:"truncated"`
	Malformed int      `json:"malformed,omitempty"`
	Items     []any    `json:"items"`
}

func (e *Envelope) note(s string) {
	e.Notes = append(e.Notes, s)
}
