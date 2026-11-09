package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// envelopeFile is the on-disk record of a call: the whole envelope, tails
// included, written once drakkar has run, whether or not the answer ever
// reaches the client.
const envelopeFile = "envelope.json"

// Call says how to run one tool call. Tool names it in job records; with
// Background the call is detached from the request and OutDir is required.
type Call struct {
	Tool       string
	Background bool
	OutDir     string
}

// call is what invoke leaves behind for Do: the output directory and the
// envelope of the run, which a mode that fails afterwards does not return.
type call struct {
	dir    string
	env    *Envelope
	onArgv func([]string)
}

type callKey struct{}

func withCall(ctx context.Context, c *call) context.Context {
	return context.WithValue(ctx, callKey{}, c)
}

// callOf returns nil outside Do; the methods below accept a nil receiver.
func callOf(ctx context.Context) *call {
	c, _ := ctx.Value(callKey{}).(*call)
	return c
}

func (c *call) starting(dir string, argv []string) {
	if c == nil {
		return
	}
	c.dir = dir
	if c.onArgv != nil {
		c.onArgv(argv)
	}
}

func (c *call) ran(env *Envelope) {
	if c != nil {
		c.env = env
	}
}

// Do runs one tool call, and is the one place envelope.json is written.
func (s *Service) Do(ctx context.Context, c Call, fn func(context.Context) (*Envelope, error)) (*Envelope, error) {
	if c.Background {
		return s.startJob(ctx, c, fn)
	}
	rec := &call{}
	env, err := fn(withCall(ctx, rec))
	if werr := rec.record(env, err); werr != nil && env != nil {
		env.note(werr.Error())
	}
	return env, err
}

// record writes envelope.json into the directory drakkar ran in. A mode that
// failed after the run returns no envelope, so the run's own is written, with
// the failure noted on it.
func (c *call) record(env *Envelope, err error) error {
	if c.dir == "" {
		return nil
	}
	if env == nil {
		if c.env == nil {
			return nil
		}
		env = c.env
		if err != nil {
			env.note(fmt.Sprintf("the call failed after drakkar ran, and answered with this error instead of this envelope: %v", err))
		}
	}
	if err := writeJSONAtomic(filepath.Join(c.dir, envelopeFile), env); err != nil {
		return fmt.Errorf("the on-disk record of this call could not be written: %v", err)
	}
	return nil
}

func readEnvelope(dir string) (*Envelope, error) {
	raw, err := os.ReadFile(filepath.Join(dir, envelopeFile))
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filepath.Join(dir, envelopeFile), err)
	}
	return &env, nil
}

// writeJSONAtomic replaces path with one rename, so that a status read racing
// the write never sees half a file.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
