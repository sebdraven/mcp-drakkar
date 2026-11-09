package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stubDrakkar puts a shell script named drakkar first on PATH. It answers
// --version like a 0.5.0 and runs body for anything else.
func stubDrakkar(t *testing.T, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub drakkar is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'drakkar 0.5.0'; exit 0; fi\n" + body
	if err := os.WriteFile(filepath.Join(dir, "drakkar"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func stringsCall(s *Service, base, out string) func(context.Context) (*Envelope, error) {
	return func(ctx context.Context) (*Envelope, error) {
		return s.Strings(ctx, StringsInput{Input: filepath.Join(base, "a.apk"), OutDir: out})
	}
}

func startStrings(t *testing.T, s *Service, ctx context.Context, base, out string) JobInfo {
	t.Helper()
	env, err := s.Do(ctx, Call{Tool: "drakkar_strings", Background: true, OutDir: out}, stringsCall(s, base, out))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := env.Result.(JobInfo)
	if !ok {
		t.Fatalf("the answer to a background call is %T, want a JobInfo", env.Result)
	}
	if info.JobID == "" || info.OutDir != out || info.Tool != "drakkar_strings" || info.StartedAt == "" {
		t.Errorf("the answer is %+v", info)
	}
	if env.Drakkar.Complete {
		t.Error("a job that has only started cannot be complete")
	}
	return info
}

func waitState(t *testing.T, s *Service, id, want string) *JobView {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err := s.JobStatus(context.Background(), JobStatusInput{JobID: id})
		if err != nil {
			t.Fatal(err)
		}
		if st.Job.State == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s is %s, still not %s", id, st.Job.State, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stopJobs ends whatever is still running before the temporary directories go.
func stopJobs(t *testing.T, s *Service) {
	t.Cleanup(func() {
		list, _ := s.JobList(context.Background(), JobListInput{})
		for _, j := range list.Jobs {
			if j.State == JobRunning {
				_, _ = s.JobCancel(context.Background(), JobCancelInput{JobID: j.JobID})
			}
		}
	})
}

func readJobFile(t *testing.T, dir string) JobInfo {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, jobFile))
	if err != nil {
		t.Fatal(err)
	}
	var info JobInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestFinishTableStampsAPartialRunOnRowsJSON(t *testing.T) {
	s, base := testService(t)
	out, err := s.begin("strings", filepath.Join(base, "out"))
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{Drakkar: Meta{ExitCode: -1, Cancelled: true, DurationMS: 1234}}
	stdout := []byte("sample\tmotif\tvalue\na\tb\tc\n")
	if _, err := s.finishTable(env, out, stdout, 50); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out.path, "rows.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Complete *bool            `json:"complete"`
		Drakkar  map[string]any   `json:"drakkar"`
		Rows     []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Complete == nil || *doc.Complete {
		t.Errorf("complete = %v, want false on a cancelled run", doc.Complete)
	}
	if doc.Drakkar["cancelled"] != true || doc.Drakkar["timed_out"] != false ||
		doc.Drakkar["exit_code"] != float64(-1) || doc.Drakkar["duration_ms"] != float64(1234) {
		t.Errorf("drakkar = %v", doc.Drakkar)
	}
	if len(doc.Rows) != 1 {
		t.Errorf("rows = %v, want the one row the run had printed", doc.Rows)
	}
}

func TestFinishLinesStampsTheRunOnLinesJSON(t *testing.T) {
	s, base := testService(t)
	out, err := s.begin("list_entries", filepath.Join(base, "out"))
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{Drakkar: Meta{Complete: true}}
	if err := s.finishLines(env, out, []byte("AndroidManifest.xml\nclasses.dex\n"), 50); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out.path, "lines.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lines    []string       `json:"lines"`
		Complete bool           `json:"complete"`
		Drakkar  map[string]any `json:"drakkar"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Complete || len(doc.Lines) != 2 || doc.Drakkar == nil {
		t.Errorf("lines.json = %s", raw)
	}
}

func TestBulkOutOfAPartialRunIsNamedAPrefix(t *testing.T) {
	s, base := testService(t)
	dir := filepath.Join(base, "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"ok": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// The report drakkar was writing when it was killed.
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"ok": tr`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := &Envelope{Drakkar: Meta{ExitCode: -1, Cancelled: true}}
	if err := s.finishBulkOut(env, dir, 50); err != nil {
		t.Fatalf("a half-written report failed the call: %v", err)
	}
	if got := env.Tails["samples"].Total; got != 2 {
		t.Errorf("total = %d, want 2", got)
	}
	joined := strings.Join(env.Notes, " ")
	if !strings.Contains(joined, "prefix of the walk") || !strings.Contains(joined, "2 report(s)") {
		t.Errorf("notes = %v, want the list named a prefix with its count", env.Notes)
	}
}

func TestEnvelopeJSONIsWrittenWhenTheCallIsCancelled(t *testing.T) {
	stubDrakkar(t, "printf 'sample\\tmotif\\tvalue\\n'\nexec sleep 30\n")
	s, base := testService(t)
	out := filepath.Join(base, "out")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(300*time.Millisecond, cancel)
	env, err := s.Do(ctx, Call{Tool: "drakkar_strings"}, stringsCall(s, base, out))
	if err != nil {
		t.Fatal(err)
	}
	if !env.Drakkar.Cancelled || env.Drakkar.TimedOut || env.Drakkar.Complete || env.Drakkar.ExitCode != -1 {
		t.Errorf("drakkar = %+v", env.Drakkar)
	}
	joined := strings.Join(env.Notes, " ")
	if !strings.Contains(joined, "cancelled by the client or the bridge") {
		t.Errorf("notes = %v, want the cancellation named", env.Notes)
	}
	if strings.Contains(joined, "drakkar exited") {
		t.Errorf("a cancelled run was also reported as an exit code: %v", env.Notes)
	}

	disk, err := readEnvelope(out)
	if err != nil {
		t.Fatalf("no envelope.json after a cancelled call: %v", err)
	}
	if !disk.Drakkar.Cancelled || disk.Drakkar.Complete {
		t.Errorf("envelope.json says %+v", disk.Drakkar)
	}
	if disk.Rows == nil || disk.Rows.Total != 0 {
		t.Errorf("envelope.json rows = %+v, want the header and no row", disk.Rows)
	}
}

func TestEnvelopeJSONRecordsACompleteCall(t *testing.T) {
	stubDrakkar(t, "printf 'sample\\tmotif\\tvalue\\na\\tb\\tc\\n'\n")
	s, base := testService(t)
	out := filepath.Join(base, "out")

	env, err := s.Do(context.Background(), Call{Tool: "drakkar_strings"}, stringsCall(s, base, out))
	if err != nil {
		t.Fatal(err)
	}
	if !env.Drakkar.Complete {
		t.Errorf("a clean run is not complete: %+v", env.Drakkar)
	}
	disk, err := readEnvelope(out)
	if err != nil {
		t.Fatal(err)
	}
	if !disk.Drakkar.Complete || disk.Rows == nil || disk.Rows.Total != 1 {
		t.Errorf("envelope.json = %+v, rows %+v", disk.Drakkar, disk.Rows)
	}
}

func TestJobOutlivesItsRequestAndEndsWithItsEnvelope(t *testing.T) {
	s, base := testService(t)
	gate := filepath.Join(base, "gate")
	stubDrakkar(t, fmt.Sprintf("while [ ! -f %q ]; do sleep 0.05; done\nprintf 'sample\\tmotif\\tvalue\\na\\tb\\tc\\n'\n", gate))
	stopJobs(t, s)
	out := filepath.Join(base, "out")

	ctx, cancel := context.WithCancel(context.Background())
	info := startStrings(t, s, ctx, base, out)
	// The request is gone; the job must not notice.
	cancel()

	st := waitState(t, s, info.JobID, JobRunning)
	if st.Envelope != nil {
		t.Error("a running job came back with an envelope")
	}
	if got := readJobFile(t, out); got.State != JobRunning || got.JobID != info.JobID {
		t.Errorf("job.json = %+v", got)
	}

	if err := os.WriteFile(gate, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, s, info.JobID, JobDone)
	if st.Envelope == nil || !st.Envelope.Drakkar.Complete || st.Envelope.Drakkar.Cancelled {
		t.Fatalf("a finished job's envelope is %+v", st.Envelope)
	}
	if st.Envelope.Rows == nil || st.Envelope.Rows.Total != 1 {
		t.Errorf("rows = %+v", st.Envelope.Rows)
	}
	if len(st.Job.Argv) == 0 || st.Job.FinishedAt == "" || st.Job.Complete == nil || !*st.Job.Complete {
		t.Errorf("job = %+v", st.Job)
	}

	if got := readJobFile(t, out); got.State != JobDone || len(got.Argv) == 0 || got.FinishedAt == "" {
		t.Errorf("job.json = %+v", got)
	}
	if disk, err := readEnvelope(out); err != nil || !disk.Drakkar.Complete {
		t.Errorf("envelope.json: %v, %+v", err, disk)
	}
	byDir, err := s.JobStatus(context.Background(), JobStatusInput{OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if byDir.Job.State != JobDone || byDir.Envelope == nil {
		t.Errorf("by out_dir: %+v", byDir)
	}
}

func TestJobCancelEndsAsCancelledWithItsEnvelope(t *testing.T) {
	stubDrakkar(t, "exec sleep 30\n")
	s, base := testService(t)
	stopJobs(t, s)
	out := filepath.Join(base, "out")

	info := startStrings(t, s, context.Background(), base, out)
	st, err := s.JobCancel(context.Background(), JobCancelInput{JobID: info.JobID})
	if err != nil {
		t.Fatal(err)
	}
	if st.Job.State != JobCancelled {
		t.Fatalf("state = %s, want cancelled", st.Job.State)
	}
	if st.Envelope == nil || !st.Envelope.Drakkar.Cancelled || st.Envelope.Drakkar.Complete {
		t.Errorf("envelope = %+v", st.Envelope)
	}
	disk, err := readEnvelope(out)
	if err != nil {
		t.Fatalf("no envelope.json after a cancel: %v", err)
	}
	if !disk.Drakkar.Cancelled {
		t.Errorf("envelope.json says %+v", disk.Drakkar)
	}
	if got := readJobFile(t, out); got.State != JobCancelled {
		t.Errorf("job.json state = %s", got.State)
	}

	again, err := s.JobCancel(context.Background(), JobCancelInput{JobID: info.JobID})
	if err != nil {
		t.Fatal(err)
	}
	if again.Job.State != JobCancelled || len(again.Notes) == 0 {
		t.Errorf("a second cancel = %+v", again)
	}
}

func TestJobsBeyondTheCeilingAreRefused(t *testing.T) {
	t.Setenv("DRAKKAR_MAX_JOBS", "1")
	stubDrakkar(t, "exec sleep 30\n")
	s, base := testService(t)
	stopJobs(t, s)

	startStrings(t, s, context.Background(), base, filepath.Join(base, "one"))
	_, err := s.Do(context.Background(), Call{Tool: "drakkar_strings", Background: true, OutDir: filepath.Join(base, "two")},
		stringsCall(s, base, filepath.Join(base, "two")))
	if err == nil {
		t.Fatal("a second job was started past DRAKKAR_MAX_JOBS=1")
	}
	if !strings.Contains(err.Error(), "1 background job(s) already running") || !strings.Contains(err.Error(), "allows 1") {
		t.Errorf("the refusal should say how many run and the ceiling, got %q", err)
	}
}

func TestBackgroundWithoutOutDirIsRefused(t *testing.T) {
	s, _ := testService(t)
	ran := false
	_, err := s.Do(context.Background(), Call{Tool: "drakkar_scan", Background: true}, func(context.Context) (*Envelope, error) {
		ran = true
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "out_dir") {
		t.Errorf("err = %v, want a refusal naming out_dir", err)
	}
	if ran {
		t.Error("the call ran anyway")
	}
	if _, err := s.Do(context.Background(), Call{Tool: "drakkar_scan", Background: true, OutDir: "relative"}, nil); err == nil {
		t.Error("a relative out_dir was accepted")
	}
}

func TestJobRunningOnDiskButUnknownHereIsOrphaned(t *testing.T) {
	s, base := testService(t)
	dir := filepath.Join(base, "left-behind")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, jobFile), JobInfo{
		JobID:     "from-a-dead-server",
		Tool:      "drakkar_diff_matrix",
		OutDir:    dir,
		State:     JobRunning,
		StartedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	st, err := s.JobStatus(context.Background(), JobStatusInput{OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if st.Job.State != JobOrphaned {
		t.Errorf("state = %s, want orphaned", st.Job.State)
	}
	if st.Envelope != nil || len(st.Notes) == 0 {
		t.Errorf("an orphan should come with a note and no envelope: %+v", st)
	}
	if st.ElapsedMS < int64(time.Hour/time.Millisecond) {
		t.Errorf("elapsed = %dms, want at least an hour", st.ElapsedMS)
	}
	if _, err := s.JobStatus(context.Background(), JobStatusInput{JobID: "from-a-dead-server"}); err == nil {
		t.Error("a job absent from the registry was found by id")
	}
}
