package drakkar

import (
	"strings"
	"testing"
)

func TestInventedFlagIsRefused(t *testing.T) {
	// The flag an assistant once proposed. It does not exist, and the point of
	// the whitelist is that it cannot be expressed rather than merely discouraged.
	_, err := New().Value("--diff-json", "x").Argv()
	if err == nil {
		t.Fatal("--diff-json was accepted; the whitelist did not hold")
	}
	if !strings.Contains(err.Error(), "not a Drakkar flag") {
		t.Errorf("error should say the flag is unknown, got %q", err)
	}
}

func TestWithheldFlagIsRefused(t *testing.T) {
	for name := range withheld {
		if _, err := New().Value(name, "vt").Argv(); err == nil {
			t.Errorf("%s was accepted; it is withheld on purpose", name)
		}
	}
}

func TestWithheldFlagsAreNotAlsoKnown(t *testing.T) {
	for name := range withheld {
		if _, ok := known[name]; ok {
			t.Errorf("%s is both known and withheld; one of the two tables is wrong", name)
		}
	}
}

func TestFlagNamesAreWellFormed(t *testing.T) {
	for name := range known {
		if !strings.HasPrefix(name, "--") {
			t.Errorf("%q is not a long flag", name)
		}
		if strings.ContainsAny(name, " \t=") {
			t.Errorf("%q contains a separator", name)
		}
	}
}

func TestWrongUseOfAKnownFlagIsRefused(t *testing.T) {
	if _, err := New().Switch("--diff-threshold").Argv(); err == nil {
		t.Error("--diff-threshold accepted as a boolean switch")
	}
	if _, err := New().Value("--manifest", "yes").Argv(); err == nil {
		t.Error("--manifest accepted as a valued flag")
	}
	if _, err := New().Multi("--format", []string{"json"}).Argv(); err == nil {
		t.Error("--format accepted as a repeatable flag")
	}
}

func TestPositionalsComeFirstAndValuesAreAttached(t *testing.T) {
	// A bare --strings after the APK is safe; before it, clap's num_args(0..)
	// would read the APK as a pattern. Same reason values are attached with '='.
	argv, err := New().
		Positional("/corpus/A sample.apk").
		Optional("--strings", nil).
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/corpus/A sample.apk", "--strings"}
	assertArgv(t, argv, want)
}

func TestMultiEmitsOneOccurrencePerValue(t *testing.T) {
	argv, err := New().
		Positional("/corpus/a.apk").
		Multi("--diff-include", []string{"Lcom/dy/", "Lcom/duiyun/"}).
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/corpus/a.apk",
		"--diff-include=Lcom/dy/",
		"--diff-include=Lcom/duiyun/",
	}
	assertArgv(t, argv, want)
}

func TestOmittedOptionsLeaveDrakkarItsDefaults(t *testing.T) {
	// The whole no-duplicated-default rule lives here: a nil pointer must produce
	// no flag at all, not a restated value.
	argv, err := New().
		Pair("--diff-dex", "/corpus/a.apk", "/corpus/b.apk").
		Float("--diff-threshold", nil).
		Int("--diff-ngram", nil).
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range argv {
		if strings.HasPrefix(got, "--diff-threshold") || strings.HasPrefix(got, "--diff-ngram") {
			t.Errorf("a nil option produced %q; Drakkar's default was overridden", got)
		}
	}
	assertArgv(t, argv, []string{"--diff-dex", "/corpus/a.apk", "/corpus/b.apk"})
}

func TestSetOptionsAreEmitted(t *testing.T) {
	threshold := 0.7
	ngram := 3
	argv, err := New().
		Pair("--diff-dex", "/corpus/a.apk", "/corpus/b.apk").
		Float("--diff-threshold", &threshold).
		Int("--diff-ngram", &ngram).
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{
		"--diff-dex", "/corpus/a.apk", "/corpus/b.apk",
		"--diff-threshold=0.7",
		"--diff-ngram=3",
	})
}

func TestOptionalWithValues(t *testing.T) {
	argv, err := New().
		Positional("/corpus/a.apk").
		Optional("--strings", []string{"http", "token"}).
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{
		"/corpus/a.apk",
		"--strings=http",
		"--strings=token",
	})
}

func TestOptionalValueIsBareOrAttached(t *testing.T) {
	argv, err := New().Positional("/corpus/a.apk").OptionalValue("--bundle", "/out").Argv()
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"/corpus/a.apk", "--bundle=/out"})

	argv, err = New().Switch("--legend").OptionalValue("--bundle", "").Argv()
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"--legend", "--bundle"})

	if _, err := New().Value("--bundle", "/out").Argv(); err == nil {
		t.Error("--bundle accepted as a plain valued flag")
	}
}

func TestEmptyValuesAreRefused(t *testing.T) {
	if _, err := New().Value("--probe", "").Argv(); err == nil {
		t.Error("an empty value was accepted")
	}
	if _, err := New().Pair("--diff-dex", "/corpus/a.apk", "").Argv(); err == nil {
		t.Error("a half-empty pair was accepted")
	}
	if _, err := New().Positional("").Argv(); err == nil {
		t.Error("an empty operand was accepted")
	}
}

func TestJSONReportNeverAsksForBoth(t *testing.T) {
	argv, err := New().
		Positional("/corpus/a.apk").
		Switch("--manifest").
		JSONReport("/reports/r.json").
		Argv()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "--format=both") {
		t.Error("--format both was requested; one invocation must produce one representation")
	}
	if !strings.Contains(joined, "--format=json") || !strings.Contains(joined, "--json-out=/reports/r.json") {
		t.Errorf("JSONReport did not ask for a JSON file: %q", joined)
	}
}

func TestErrorsAccumulate(t *testing.T) {
	_, err := New().Value("--nope", "1").Value("--also-nope", "2").Argv()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "--nope") || !strings.Contains(err.Error(), "--also-nope") {
		t.Errorf("both unknown flags should be reported, got %q", err)
	}
}

func assertArgv(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %q, want %q", got, want)
		}
	}
}
