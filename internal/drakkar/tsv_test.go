package drakkar

import "testing"

// Drakkar's real headers, so a column renamed upstream breaks a test here rather
// than silently shifting a field in an answer.
const dynTSV = "sample\torigine\tclasse\tsink\toffset\tappelant\tdetail\n" +
	"a3f\tconst\tLcom/dy/A;\tstartActivity\t+12\tLcom/dy/B;->run\t\n" +
	"a3f\tconst\tLcom/dy/C;\tbindService\t+40\tLcom/dy/B;->run\t\n" +
	"b7c\truntime\tLcom/x/D;\tstartService\t+4\tLcom/x/E;->go\t\n"

const reflectionTSV = "sample\tcategory\tcount\n" +
	"a3f\tconst\t12\n" +
	"a3f\tdecrypt-const\t4\n" +
	"a3f\truntime\t0\n" +
	"b7c\tconst\t3\n"

func TestParseTableReadsTheHeader(t *testing.T) {
	table, err := ParseTable([]byte(dynTSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Header) != 7 {
		t.Fatalf("header has %d columns: %q", len(table.Header), table.Header)
	}
	if len(table.Rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(table.Rows))
	}
	if _, ok := table.Column("origine"); !ok {
		t.Error("column origine not resolved by name")
	}
	if _, ok := table.Column("nope"); ok {
		t.Error("a column that is not there resolved anyway")
	}
}

func TestObjectsKeyRowsByColumnName(t *testing.T) {
	table, err := ParseTable([]byte(dynTSV))
	if err != nil {
		t.Fatal(err)
	}
	objects := table.Objects()
	if len(objects) != 3 {
		t.Fatalf("objects = %d, want 3", len(objects))
	}
	if objects[0]["classe"] != "Lcom/dy/A;" {
		t.Errorf("classe = %q", objects[0]["classe"])
	}
	if objects[0]["detail"] != "" {
		t.Errorf("the trailing empty field should survive as an empty string, got %q", objects[0]["detail"])
	}
}

func TestMalformedRowsAreSetAsideNotReinterpreted(t *testing.T) {
	// A row with the wrong field count must never be padded or trimmed into
	// shape: that is how a shifted column becomes a wrong answer.
	bad := "sample\tcategory\tcount\n" +
		"a3f\tconst\t12\n" +
		"a3f\tconst\n" +
		"b7c\tconst\t3\textra\n"

	table, err := ParseTable([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 1 {
		t.Errorf("rows = %d, want only the well-formed one", len(table.Rows))
	}
	if len(table.Malformed) != 2 {
		t.Fatalf("malformed = %d, want 2", len(table.Malformed))
	}
	if table.Malformed[0].Fields != 2 || table.Malformed[0].Line != 3 {
		t.Errorf("first malformed row = %+v", table.Malformed[0])
	}
	if table.Malformed[0].Raw == "" {
		t.Error("a malformed row must keep its raw line")
	}
}

func TestParseTableWithoutHeader(t *testing.T) {
	if _, err := ParseTable([]byte("")); err == nil {
		t.Error("empty stdout parsed as a table")
	}
	if _, err := ParseTable([]byte("   \n\n")); err == nil {
		t.Error("blank stdout parsed as a table")
	}
}

func TestHeaderOnlyIsAValidEmptyResult(t *testing.T) {
	// A filter that matches nothing still prints its header. That is zero rows,
	// not a failure.
	table, err := ParseTable([]byte("sample\tmotif\tchaine\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 0 {
		t.Errorf("rows = %d, want 0", len(table.Rows))
	}
}

func TestCountBy(t *testing.T) {
	table, err := ParseTable([]byte(dynTSV))
	if err != nil {
		t.Fatal(err)
	}
	got, err := table.CountBy("origine")
	if err != nil {
		t.Fatal(err)
	}
	if got["const"] != 2 || got["runtime"] != 1 {
		t.Errorf("histogram = %v", got)
	}
	if _, err := table.CountBy("nope"); err == nil {
		t.Error("a histogram over a missing column should be an error, not an empty map")
	}
}

func TestSumBy(t *testing.T) {
	table, err := ParseTable([]byte(reflectionTSV))
	if err != nil {
		t.Fatal(err)
	}
	got, err := table.SumBy("category", "count")
	if err != nil {
		t.Fatal(err)
	}
	if got["const"] != 15 {
		t.Errorf("const = %d, want 15", got["const"])
	}
	if got["runtime"] != 0 {
		t.Errorf("runtime = %d, want 0 kept as a real zero", got["runtime"])
	}
	if _, ok := got["decrypt-const"]; !ok {
		t.Error("decrypt-const missing; the ratio it feeds would be unreadable")
	}
}

func TestSumByRefusesNonNumeric(t *testing.T) {
	table, err := ParseTable([]byte("sample\tcategory\tcount\na3f\tconst\tmany\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.SumBy("category", "count"); err == nil {
		t.Error("a non-numeric count was summed anyway")
	}
}

func TestDistinct(t *testing.T) {
	table, err := ParseTable([]byte(dynTSV))
	if err != nil {
		t.Fatal(err)
	}
	samples, err := table.Distinct("sample")
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Errorf("distinct samples = %v", samples)
	}
}

func TestParseLines(t *testing.T) {
	got := ParseLines([]byte("res/raw/plugin\nassets/libjiagu.so\n\n"))
	if len(got) != 2 {
		t.Fatalf("lines = %q", got)
	}
	if got[1] != "assets/libjiagu.so" {
		t.Errorf("lines = %q", got)
	}
}

func TestParseTableHandlesCRLF(t *testing.T) {
	table, err := ParseTable([]byte("a\tb\r\n1\t2\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 1 || table.Rows[0][1] != "2" {
		t.Errorf("rows = %q", table.Rows)
	}
}
