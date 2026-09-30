package drakkar

import (
	"strings"
	"testing"
)

// The lines below keep Drakkar's exact shapes: two spaces after [FAIL], the em
// dash as separator, and the wider spacing bulk.rs uses. A parser tuned to a
// tidied-up version of them would count zero failures on a real run.
const sample = `[OK]    a3f — 12 resolus (4 classes distinctes), 0 non resolus
[FAIL]  b7c — dex header: bad magic
[PANIC] d91 — parsing abandonné
[AVERT] --assets-max-size est actif avec un filtre par hash
[FAIL]  /corpus/tampered.apk  — non reconnu comme APK : central directory
[FIN]   115 echantillon(s) candidat(s), 2 en echec, 4211 ligne(s) emise(s)
some unprefixed line that must survive in Text
`

func TestParseDiagCountsMarkers(t *testing.T) {
	d := ParseDiag(sample, false)

	if d.OK != 1 {
		t.Errorf("OK = %d, want 1", d.OK)
	}
	if d.Failed != 2 {
		t.Errorf("Failed = %d, want 2", d.Failed)
	}
	if d.Panicked != 1 {
		t.Errorf("Panicked = %d, want 1", d.Panicked)
	}
	if d.Warned != 1 {
		t.Errorf("Warned = %d, want 1", d.Warned)
	}
	if got := d.FailedEntries(); got != 3 {
		t.Errorf("FailedEntries = %d, want 3 (a panic is a failed entry too)", got)
	}
}

func TestParseDiagKeepsStderrWhole(t *testing.T) {
	d := ParseDiag(sample, false)
	if d.Text != sample {
		t.Error("Text is not stderr verbatim")
	}
	if !strings.Contains(d.Text, "some unprefixed line that must survive in Text") {
		t.Error("an unrecognised line was dropped")
	}
}

func TestParseDiagNamesFailures(t *testing.T) {
	d := ParseDiag(sample, false)
	if len(d.Failures) != 3 {
		t.Fatalf("Failures = %d, want 3", len(d.Failures))
	}

	if d.Failures[0].Kind != "fail" || d.Failures[0].Sample != "b7c" {
		t.Errorf("first failure = %+v", d.Failures[0])
	}
	if d.Failures[0].Reason != "dex header: bad magic" {
		t.Errorf("reason = %q", d.Failures[0].Reason)
	}
	if d.Failures[1].Kind != "panic" || d.Failures[1].Sample != "d91" {
		t.Errorf("second failure = %+v", d.Failures[1])
	}
	// The bulk form pads before the dash; the sample must come back trimmed.
	if d.Failures[2].Sample != "/corpus/tampered.apk" {
		t.Errorf("third sample = %q, want the path with no trailing spaces", d.Failures[2].Sample)
	}
	if !strings.HasPrefix(d.Failures[2].Reason, "non reconnu comme APK") {
		t.Errorf("third reason = %q", d.Failures[2].Reason)
	}
}

func TestParseDiagKeepsFinLine(t *testing.T) {
	d := ParseDiag(sample, false)
	if !strings.Contains(d.Fin, "2 en echec") {
		t.Errorf("Fin = %q, want Drakkar's own end-of-pass count", d.Fin)
	}
}

func TestParseDiagWithoutDash(t *testing.T) {
	d := ParseDiag("[FAIL]  lonely\n", false)
	if len(d.Failures) != 1 {
		t.Fatalf("Failures = %d, want 1", len(d.Failures))
	}
	if d.Failures[0].Sample != "lonely" || d.Failures[0].Reason != "" {
		t.Errorf("failure = %+v", d.Failures[0])
	}
}

func TestParseDiagRecordsTruncation(t *testing.T) {
	d := ParseDiag("[OK]    x\n", true)
	if !d.Truncated {
		t.Error("truncation of stderr was not recorded, so the counts would read as exact")
	}
}

func TestParseDiagEmpty(t *testing.T) {
	d := ParseDiag("", false)
	if d.OK != 0 || d.Failed != 0 || d.FailedEntries() != 0 || len(d.Failures) != 0 {
		t.Errorf("empty stderr produced %+v", d)
	}
}
