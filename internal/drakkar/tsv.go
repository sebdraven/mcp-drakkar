package drakkar

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Six Drakkar modes have no JSON at all, so the TSV is not a rendering choice
// there, it is the only output. Parsing it here, once, in code that is tested,
// is the whole point: it replaces an awk pipeline retyped into a conversation.
//
// The header is read, never assumed. A column added upstream shifts nothing
// silently — it either still matches by name, or the row lands in Malformed.

type Table struct {
	Header    []string       `json:"header"`
	Rows      [][]string     `json:"rows"`
	Malformed []MalformedRow `json:"malformed,omitempty"`
}

type MalformedRow struct {
	Line   int    `json:"line"`
	Fields int    `json:"fields"`
	Raw    string `json:"raw"`
}

// ParseTable reads a TSV stream whose first non-empty line is the header.
func ParseTable(b []byte) (*Table, error) {
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	t := &Table{}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if t.Header == nil {
			t.Header = fields
			continue
		}
		if len(fields) != len(t.Header) {
			t.Malformed = append(t.Malformed, MalformedRow{
				Line:   i + 1,
				Fields: len(fields),
				Raw:    line,
			})
			continue
		}
		t.Rows = append(t.Rows, fields)
	}
	if t.Header == nil {
		return nil, errors.New("no TSV header on stdout")
	}
	return t, nil
}

// ParseLines reads an output that is one bare value per line, with no header.
func ParseLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// Column resolves a column by name.
func (t *Table) Column(name string) (int, bool) {
	for i, h := range t.Header {
		if h == name {
			return i, true
		}
	}
	return 0, false
}

// Objects turns the rows into name-keyed maps, which is what the envelope hands
// back: a caller should never have to know a column's position.
func (t *Table) Objects() []map[string]string {
	out := make([]map[string]string, 0, len(t.Rows))
	for _, row := range t.Rows {
		m := make(map[string]string, len(t.Header))
		for i, h := range t.Header {
			m[h] = row[i]
		}
		out = append(out, m)
	}
	return out
}

// CountBy is a histogram over one column.
func (t *Table) CountBy(column string) (map[string]int, error) {
	idx, ok := t.Column(column)
	if !ok {
		return nil, fmt.Errorf("no column %q in header %v", column, t.Header)
	}
	out := map[string]int{}
	for _, row := range t.Rows {
		out[row[idx]]++
	}
	return out, nil
}

// SumBy totals a numeric column grouped by another, for the modes whose TSV is
// already an aggregate (--reflection-inputs emits sample/category/count).
func (t *Table) SumBy(keyColumn, valueColumn string) (map[string]int, error) {
	ki, ok := t.Column(keyColumn)
	if !ok {
		return nil, fmt.Errorf("no column %q in header %v", keyColumn, t.Header)
	}
	vi, ok := t.Column(valueColumn)
	if !ok {
		return nil, fmt.Errorf("no column %q in header %v", valueColumn, t.Header)
	}
	out := map[string]int{}
	for _, row := range t.Rows {
		n, err := strconv.Atoi(strings.TrimSpace(row[vi]))
		if err != nil {
			return nil, fmt.Errorf("column %q holds %q, which is not a number", valueColumn, row[vi])
		}
		out[row[ki]] += n
	}
	return out, nil
}

// Distinct lists the distinct values of a column, for the sample axis.
func (t *Table) Distinct(column string) ([]string, error) {
	idx, ok := t.Column(column)
	if !ok {
		return nil, fmt.Errorf("no column %q in header %v", column, t.Header)
	}
	seen := map[string]bool{}
	var out []string
	for _, row := range t.Rows {
		if seen[row[idx]] {
			continue
		}
		seen[row[idx]] = true
		out = append(out, row[idx])
	}
	return out, nil
}
