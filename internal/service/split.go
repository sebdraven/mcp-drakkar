package service

// Every Drakkar report has the same anatomy: a head of scalars — the Jaccard,
// the counters, the threshold actually used — and tails of unbounded arrays. The
// head is the number one reads; the 299 classes are what one opens afterwards,
// and only sometimes.
//
// So the head goes back inline, verbatim, and each array becomes a declared
// preview plus a count. The complete report stays on disk, where Drakkar wrote
// it. Nothing is ever cut without saying so.

const (
	// DefaultMaxRows is the preview size when the caller asks for none.
	DefaultMaxRows = 50
	// maxMaxRows bounds what a caller may ask for inline.
	maxMaxRows = 2000
	// maxSplitDepth limits how far into nested objects arrays are pulled out.
	// --orphan-audit nests its islands one level down, under "report".
	maxSplitDepth = 3
)

type Tail struct {
	Total     int   `json:"total"`
	Returned  int   `json:"returned"`
	Truncated bool  `json:"truncated"`
	Items     []any `json:"items"`
}

// ClampRows keeps a caller-supplied preview size inside sane bounds.
func ClampRows(n *int) int {
	if n == nil || *n <= 0 {
		return DefaultMaxRows
	}
	if *n > maxMaxRows {
		return maxMaxRows
	}
	return *n
}

// Split separates a decoded report into its scalar head and its array tails.
// Arrays whose dotted path appears in inline stay in the head: by_kind, groups
// and failed are bounded and they are the answer, not the appendix.
//
// A document whose root is itself an array — the rules pipeline prints one —
// becomes a single tail named rootName.
func Split(doc any, rootName string, inline []string, maxRows int) (any, map[string]Tail) {
	keep := make(map[string]bool, len(inline))
	for _, k := range inline {
		keep[k] = true
	}
	tails := map[string]Tail{}

	if arr, ok := doc.([]any); ok {
		name := rootName
		if name == "" {
			name = "items"
		}
		tails[name] = makeTail(arr, maxRows)
		return map[string]any{}, tails
	}

	head := splitValue(doc, "", keep, maxRows, tails, 0)
	return head, tails
}

func splitValue(v any, path string, keep map[string]bool, maxRows int, tails map[string]Tail, depth int) any {
	obj, ok := v.(map[string]any)
	if !ok || depth >= maxSplitDepth {
		return v
	}
	out := make(map[string]any, len(obj))
	for k, val := range obj {
		p := k
		if path != "" {
			p = path + "." + k
		}
		if arr, isArr := val.([]any); isArr {
			if keep[p] {
				out[k] = arr
				continue
			}
			tails[p] = makeTail(arr, maxRows)
			continue
		}
		out[k] = splitValue(val, p, keep, maxRows, tails, depth+1)
	}
	return out
}

func makeTail(arr []any, maxRows int) Tail {
	n := len(arr)
	if maxRows > n {
		maxRows = n
	}
	items := make([]any, 0, maxRows)
	items = append(items, arr[:maxRows]...)
	return Tail{
		Total:     n,
		Returned:  len(items),
		Truncated: len(items) < n,
		Items:     items,
	}
}
