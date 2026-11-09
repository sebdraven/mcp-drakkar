package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-drakkar/internal/version"
)

// A background job runs the same pipeline as the synchronous call, under a
// context detached from the MCP request — a bridge that gives up on the request
// after a minute or two no longer kills drakkar — and still bounded by the class
// timeout. It leaves job.json and envelope.json in its out_dir, so its outcome
// can be read back without the request, and without this process.

const (
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
	// JobOrphaned is never written: it is how a job.json left at running by a
	// server that is gone is reported.
	JobOrphaned = "orphaned"

	jobFile        = "job.json"
	defaultMaxJobs = 2
	// cancelWait bounds how long drakkar_job_cancel waits for the job to end.
	cancelWait = 15 * time.Second
)

// JobInfo is job.json, and what the registry says about a job.
type JobInfo struct {
	JobID      string   `json:"job_id"`
	Tool       string   `json:"tool"`
	OutDir     string   `json:"out_dir"`
	Argv       []string `json:"argv,omitempty"`
	State      string   `json:"state"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Complete   *bool    `json:"complete,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type job struct {
	info      JobInfo
	started   time.Time
	finished  time.Time
	env       *Envelope
	notes     []string
	cancel    context.CancelFunc
	cancelled bool
	done      chan struct{}
}

type jobs struct {
	mu    sync.Mutex
	limit int
	byID  map[string]*job
}

func newJobs(limit int) *jobs {
	return &jobs{limit: limit, byID: map[string]*job{}}
}

func (r *jobs) add(tool, outDir string, cancel context.CancelFunc) (*job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	running := 0
	for _, j := range r.byID {
		if j.info.State != JobRunning {
			continue
		}
		running++
		if j.info.OutDir == outDir {
			return nil, fmt.Errorf("job %s is already running in %s; give this call another out_dir, or stop that job with drakkar_job_cancel", j.info.JobID, outDir)
		}
	}
	if running >= r.limit {
		return nil, fmt.Errorf("%d background job(s) already running, and DRAKKAR_MAX_JOBS allows %d; wait for one with drakkar_job_status or stop one with drakkar_job_cancel", running, r.limit)
	}
	now := time.Now()
	j := &job{
		info: JobInfo{
			JobID:     rand.Text(),
			Tool:      tool,
			OutDir:    outDir,
			State:     JobRunning,
			StartedAt: now.UTC().Format(time.RFC3339Nano),
		},
		started: now,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	r.byID[j.info.JobID] = j
	return j, nil
}

func (r *jobs) drop(j *job) {
	r.mu.Lock()
	delete(r.byID, j.info.JobID)
	r.mu.Unlock()
}

func (r *jobs) get(id string) (*job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.byID[id]
	return j, ok
}

func (r *jobs) snapshot(j *job) JobInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return j.snapshotLocked()
}

func (j *job) snapshotLocked() JobInfo {
	info := j.info
	info.Argv = append([]string(nil), j.info.Argv...)
	return info
}

func (r *jobs) setArgv(j *job, argv []string) {
	r.mu.Lock()
	j.info.Argv = argv
	r.mu.Unlock()
}

func (r *jobs) addNote(j *job, note string) {
	r.mu.Lock()
	j.notes = append(j.notes, note)
	r.mu.Unlock()
}

// finish settles the state. done means drakkar ran and left an envelope, whose
// drakkar.complete says whether the run was whole; failed means no envelope.
func (r *jobs) finish(j *job, env *Envelope, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j.finished = time.Now()
	j.info.FinishedAt = j.finished.UTC().Format(time.RFC3339Nano)
	j.env = env
	if env != nil {
		complete := env.Drakkar.Complete
		j.info.Complete = &complete
		if len(env.Drakkar.Argv) > 0 {
			j.info.Argv = env.Drakkar.Argv
		}
	}
	if err != nil {
		j.info.Error = err.Error()
	}
	switch {
	case j.cancelled:
		j.info.State = JobCancelled
	case err != nil || env == nil:
		j.info.State = JobFailed
	default:
		j.info.State = JobDone
	}
	j.cancel()
}

// requestCancel reports false when the job had already ended.
func (r *jobs) requestCancel(j *job) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j.info.State != JobRunning {
		return false
	}
	j.cancelled = true
	j.cancel()
	return true
}

func (r *jobs) status(j *job) *JobView {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := &JobView{
		Job:   j.snapshotLocked(),
		Notes: append([]string(nil), j.notes...),
	}
	end := time.Now()
	if !j.finished.IsZero() {
		end = j.finished
	}
	st.ElapsedMS = end.Sub(j.started).Milliseconds()
	if j.info.State != JobRunning {
		st.Envelope = j.env
	}
	return st
}

func (s *Service) startJob(ctx context.Context, c Call, fn func(context.Context) (*Envelope, error)) (*Envelope, error) {
	if strings.TrimSpace(c.OutDir) == "" {
		return nil, fmt.Errorf("background needs out_dir: job.json and envelope.json are written there, and it is how drakkar_job_status finds the job after a restart of the server")
	}
	if !filepath.IsAbs(c.OutDir) {
		return nil, fmt.Errorf("out_dir must be an absolute path, got %q", c.OutDir)
	}
	dir := filepath.Clean(c.OutDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	jobCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	j, err := s.jobs.add(c.Tool, dir, cancel)
	if err != nil {
		cancel()
		return nil, err
	}
	// An earlier call's envelope.json must not pass for this job's.
	err = os.Remove(filepath.Join(dir, envelopeFile))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil {
		err = writeJSONAtomic(filepath.Join(dir, jobFile), s.jobs.snapshot(j))
	}
	if err != nil {
		s.jobs.drop(j)
		cancel()
		return nil, fmt.Errorf("preparing the job in %s: %w", dir, err)
	}

	go s.runJob(jobCtx, j, fn)

	info := s.jobs.snapshot(j)
	env := &Envelope{
		Drakkar: Meta{Server: version.Version, Tested: version.DrakkarTested},
		Result:  info,
	}
	env.note(fmt.Sprintf("started in the background as job %s; nothing has been measured yet. Poll drakkar_job_status with this job_id, or with out_dir after a restart of the server; envelope.json in out_dir is the answer once the job has ended", info.JobID))
	return env, nil
}

func (s *Service) runJob(ctx context.Context, j *job, fn func(context.Context) (*Envelope, error)) {
	defer close(j.done)
	rec := &call{onArgv: func(argv []string) {
		s.jobs.setArgv(j, argv)
		s.writeJob(j)
	}}
	env, err := fn(withCall(ctx, rec))
	werr := rec.record(env, err)
	if env == nil {
		env = rec.env
	}
	if werr != nil {
		s.jobs.addNote(j, werr.Error())
	}
	s.jobs.finish(j, env, err)
	s.writeJob(j)
}

func (s *Service) writeJob(j *job) {
	info := s.jobs.snapshot(j)
	if err := writeJSONAtomic(filepath.Join(info.OutDir, jobFile), info); err != nil {
		s.jobs.addNote(j, fmt.Sprintf("job.json could not be updated, so it may lag behind this answer: %v", err))
	}
}

// JobStatusInput names a job one of two ways.
type JobStatusInput struct {
	JobID  string `json:"job_id,omitempty" jsonschema:"the job_id a background call answered with; known only to the server process that started the job"`
	OutDir string `json:"out_dir,omitempty" jsonschema:"absolute out_dir of a background call; job.json and envelope.json are read there, which also works after a restart of the server"`
}

// JobView is the state of one job and, once it has ended, its envelope as
// the original tool built it, with that call's max_rows.
type JobView struct {
	Job       JobInfo   `json:"job"`
	ElapsedMS int64     `json:"elapsed_ms"`
	Envelope  *Envelope `json:"envelope,omitempty"`
	Notes     []string  `json:"notes,omitempty"`
}

// JobStatus reads a job from the registry, or from its out_dir.
func (s *Service) JobStatus(_ context.Context, in JobStatusInput) (*JobView, error) {
	switch {
	case in.JobID != "" && in.OutDir != "":
		return nil, fmt.Errorf("pass either job_id or out_dir, not both")
	case in.JobID != "":
		j, ok := s.jobs.get(in.JobID)
		if !ok {
			return nil, fmt.Errorf("no job %q in this server's registry; the registry does not survive a restart, so ask with out_dir instead", in.JobID)
		}
		return s.jobs.status(j), nil
	case in.OutDir != "":
		return s.jobStatusOnDisk(in.OutDir)
	default:
		return nil, fmt.Errorf("pass job_id, or the out_dir of a background call")
	}
}

func (s *Service) jobStatusOnDisk(outDir string) (*JobView, error) {
	dir, err := requireAbs("out_dir", outDir)
	if err != nil {
		return nil, err
	}
	dir = filepath.Clean(dir)
	raw, err := os.ReadFile(filepath.Join(dir, jobFile))
	if err != nil {
		return nil, fmt.Errorf("reading %s, which only a background call writes: %w", filepath.Join(dir, jobFile), err)
	}
	var info JobInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filepath.Join(dir, jobFile), err)
	}
	if j, ok := s.jobs.get(info.JobID); ok {
		return s.jobs.status(j), nil
	}

	st := &JobView{Job: info}
	end := time.Now()
	if info.State == JobRunning {
		st.Job.State = JobOrphaned
		st.Notes = append(st.Notes, "job.json says running, but no server process holds this job any more: nothing will ever finish this record, and whatever is in out_dir is partial. Run the call again")
	} else if t, err := time.Parse(time.RFC3339Nano, info.FinishedAt); err == nil {
		end = t
	}
	if started, err := time.Parse(time.RFC3339Nano, info.StartedAt); err == nil {
		st.ElapsedMS = end.Sub(started).Milliseconds()
	}
	if info.State != JobRunning {
		env, err := readEnvelope(dir)
		// A job that failed before drakkar ran has no envelope; its error says why.
		if err != nil && info.Error == "" {
			st.Notes = append(st.Notes, fmt.Sprintf("the job has ended but its envelope could not be read: %v", err))
		} else {
			st.Envelope = env
		}
	}
	return st, nil
}

// JobCancelInput names the job to stop.
type JobCancelInput struct {
	JobID string `json:"job_id" jsonschema:"the job_id a background call answered with"`
}

// JobCancel cancels the job's context, which kills drakkar, and waits a bounded
// time for the job to record itself as cancelled.
func (s *Service) JobCancel(_ context.Context, in JobCancelInput) (*JobView, error) {
	j, ok := s.jobs.get(in.JobID)
	if !ok {
		return nil, fmt.Errorf("no job %q in this server's registry; a job started by an earlier server process cannot be cancelled from this one", in.JobID)
	}
	if !s.jobs.requestCancel(j) {
		st := s.jobs.status(j)
		st.Notes = append(st.Notes, fmt.Sprintf("the job had already ended as %s; nothing was cancelled", st.Job.State))
		return st, nil
	}
	select {
	case <-j.done:
	case <-time.After(cancelWait):
	}
	st := s.jobs.status(j)
	if st.Job.State == JobRunning {
		st.Notes = append(st.Notes, "drakkar was told to stop but the job has not ended yet; drakkar_job_status will show cancelled once it has")
	}
	return st, nil
}

// JobListInput takes nothing.
type JobListInput struct{}

// JobRegistry is the registry, without envelopes.
type JobRegistry struct {
	Jobs    []JobInfo `json:"jobs"`
	Running int       `json:"running"`
	MaxJobs int       `json:"max_jobs"`
}

// JobList lists the jobs this server process knows of, oldest first.
func (s *Service) JobList(_ context.Context, _ JobListInput) (*JobRegistry, error) {
	r := s.jobs
	r.mu.Lock()
	defer r.mu.Unlock()
	all := make([]*job, 0, len(r.byID))
	for _, j := range r.byID {
		all = append(all, j)
	}
	sort.Slice(all, func(a, b int) bool { return all[a].started.Before(all[b].started) })

	out := &JobRegistry{Jobs: []JobInfo{}, MaxJobs: r.limit}
	for _, j := range all {
		if j.info.State == JobRunning {
			out.Running++
		}
		out.Jobs = append(out.Jobs, j.snapshotLocked())
	}
	return out, nil
}
