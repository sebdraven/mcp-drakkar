package drakkar

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Args builds one Drakkar command line. It is the only way this server produces
// arguments: there is no code path that takes a caller-supplied flag string, so
// a flag Drakkar does not have cannot be expressed, let alone passed.
//
// Two layout rules are not deducible from the flag table:
//
// Values are attached with '=', never passed as a following token. Several
// Drakkar options are declared num_args(0..) or num_args(1..), and clap lets
// those swallow the next argument — `--diff-include Lcom/dy/ a.apk` would read
// the APK as a second prefix. An attached value cannot over-consume.
//
// Positionals come first, right after the binary, for the same reason: a bare
// --strings or --disasm placed before the APK would eat it as a pattern.
type Args struct {
	pos   []string
	flags []string
	errs  []string
}

func New() *Args { return &Args{} }

func (a *Args) fail(format string, v ...any) *Args {
	a.errs = append(a.errs, fmt.Sprintf(format, v...))
	return a
}

func (a *Args) check(name string, want kind) bool {
	if why, ok := withheld[name]; ok {
		a.fail("%s is withheld by this server: %s", name, why)
		return false
	}
	got, ok := known[name]
	if !ok {
		a.fail("%s is not a Drakkar flag", name)
		return false
	}
	if got != want {
		a.fail("%s is not used that way", name)
		return false
	}
	return true
}

// Positional adds an operand. Order of calls is preserved.
func (a *Args) Positional(p string) *Args {
	if p == "" {
		return a.fail("empty operand")
	}
	a.pos = append(a.pos, p)
	return a
}

// Switch adds a bare boolean flag.
func (a *Args) Switch(name string) *Args {
	if a.check(name, switchFlag) {
		a.flags = append(a.flags, name)
	}
	return a
}

// SwitchIf adds a bare boolean flag only when on.
func (a *Args) SwitchIf(name string, on bool) *Args {
	if !on {
		return a
	}
	return a.Switch(name)
}

// Value adds a single-valued flag. An empty value is an error rather than an
// empty string handed to Drakkar.
func (a *Args) Value(name, v string) *Args {
	if !a.check(name, valueFlag) {
		return a
	}
	if v == "" {
		return a.fail("%s needs a value", name)
	}
	a.flags = append(a.flags, name+"="+v)
	return a
}

// ValueIf adds a single-valued flag, omitted entirely when v is empty.
func (a *Args) ValueIf(name, v string) *Args {
	if v == "" {
		return a
	}
	return a.Value(name, v)
}

// Int adds a numeric flag, omitted entirely when v is nil. Omission is the
// point: Drakkar owns the default, and a default restated here would drift.
func (a *Args) Int(name string, v *int) *Args {
	if v == nil {
		return a
	}
	return a.Value(name, strconv.Itoa(*v))
}

// Int64 adds a numeric flag, omitted entirely when v is nil.
func (a *Args) Int64(name string, v *int64) *Args {
	if v == nil {
		return a
	}
	return a.Value(name, strconv.FormatInt(*v, 10))
}

// Float adds a fractional flag, omitted entirely when v is nil.
func (a *Args) Float(name string, v *float64) *Args {
	if v == nil {
		return a
	}
	return a.Value(name, strconv.FormatFloat(*v, 'g', -1, 64))
}

// Multi adds a repeatable flag, one occurrence per value. Nothing is emitted
// for an empty slice.
func (a *Args) Multi(name string, vs []string) *Args {
	if len(vs) == 0 {
		return a
	}
	if !a.check(name, multiFlag) {
		return a
	}
	for _, v := range vs {
		if v == "" {
			a.fail("%s has an empty value", name)
			continue
		}
		a.flags = append(a.flags, name+"="+v)
	}
	return a
}

// Optional adds a flag declared num_args(0..): bare when vs is empty, one
// occurrence per value otherwise. Unlike Multi, the bare form is meaningful —
// `--strings` with no pattern dumps the whole pool.
func (a *Args) Optional(name string, vs []string) *Args {
	if !a.check(name, optionalMultiFlag) {
		return a
	}
	if len(vs) == 0 {
		a.flags = append(a.flags, name)
		return a
	}
	for _, v := range vs {
		if v == "" {
			a.fail("%s has an empty value", name)
			continue
		}
		a.flags = append(a.flags, name+"="+v)
	}
	return a
}

// OptionalValue adds a flag declared num_args(0..=1): bare when v is empty,
// --name=v otherwise. `--bundle` bare is only meaningful with --legend.
func (a *Args) OptionalValue(name, v string) *Args {
	if !a.check(name, optionalValueFlag) {
		return a
	}
	if v == "" {
		a.flags = append(a.flags, name)
		return a
	}
	a.flags = append(a.flags, name+"="+v)
	return a
}

// Pair adds a flag declared num_args(2). It consumes exactly two operands, so
// the attached-value rule does not apply and cannot.
func (a *Args) Pair(name, first, second string) *Args {
	if !a.check(name, pairFlag) {
		return a
	}
	if first == "" || second == "" {
		return a.fail("%s needs two operands", name)
	}
	a.flags = append(a.flags, name, first, second)
	return a
}

// Argv returns the assembled command line, or every error collected on the way.
func (a *Args) Argv() ([]string, error) {
	if len(a.errs) > 0 {
		return nil, errors.New(strings.Join(a.errs, "; "))
	}
	out := make([]string, 0, len(a.pos)+len(a.flags))
	out = append(out, a.pos...)
	out = append(out, a.flags...)
	return out, nil
}

// JSONReport asks for the JSON representation in a file. The server never uses
// --format both: one invocation, one representation. That also sidesteps the
// stream mixing of drakkar issue #9 and the buffering of a large report
// through a pipe.
func (a *Args) JSONReport(path string) *Args {
	return a.Value("--format", "json").Value("--json-out", path)
}
