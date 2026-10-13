package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// routeSample adds the one-click sample-data endpoints. Loading and removing
// sample data writes and deletes documents for everyone, so every route is
// for admins only.
func (s *Server) routeSample(api *router) {
	api.admin("GET /api/sample", s.handleSampleStatus)
	api.admin("POST /api/sample/load", s.handleSampleLoad)
	api.admin("POST /api/sample/remove", s.handleSampleRemove)
}

var errSampleOff = errors.New("sample data is not available on this server")

// sampleJob tracks the sample-data load or remove this server started. Its
// own mutex guards the fields; the long-running work runs in a goroutine so
// the request returns at once. The loader's record in OpenSearch keeps one
// job at a time across processes: other servers that share the OpenSearch,
// the command line, or this server after a restart in place.
type sampleJob struct {
	mu      sync.Mutex
	running bool
	op      string // "load" or "remove"
	prog    sample.Progress
	err     error
	// after is what the shared record was once the job failed.
	after sampleAfter
}

// sampleAfter is the shared record a failed job left behind: left is its
// ID, or "" when there is none, and known is false when it could not be
// read. seen is the loader's count of sample sets come and gone
// (Loader.Changes) at that moment: once it moves on, another server, the
// command line or this one has loaded or removed since, and the old error
// no longer applies, even if the record is back to what it was.
type sampleAfter struct {
	left  string
	known bool
	seen  uint64
}

// sampleJobView is a copy of sampleJob's fields for one status reply.
type sampleJobView struct {
	running bool
	op      string
	prog    sample.Progress
	err     error
	after   sampleAfter
}

func (j *sampleJob) snapshot() sampleJobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return sampleJobView{j.running, j.op, j.prog, j.err, j.after}
}

// errorApplies reports whether the last job's error still describes the
// shared record st: no load or removal has happened since, anywhere, as
// far as this server's reads of the record (changes) tell.
func (v sampleJobView) errorApplies(st *sample.State, changes uint64) bool {
	if v.err == nil || changes != v.after.seen {
		return false
	}
	id := ""
	if st != nil {
		id = st.ID
	}
	return !v.after.known || id == v.after.left
}

// sampleRefusal reports whether err only says the record did not allow the
// job: another job runs, or a set (or an unfinished one) is in place.
// The status shows that from the record itself, and keeps showing it
// right, so it is not kept as the job's error.
func sampleRefusal(err error) bool {
	return errors.Is(err, sample.ErrBusy) || errors.Is(err, sample.ErrAlreadyLoaded) || errors.Is(err, sample.ErrPartial)
}

// start begins a background job, refusing when one is already running. The
// work runs under base, which ends only when the process stops, so it
// carries on after the request returns, and a progress callback records
// the latest step for the status reply. When the work fails, after reads
// which shared record it left behind.
func (j *sampleJob) start(base context.Context, op string, work func(ctx context.Context, prog sample.ProgressFn) error, after func(ctx context.Context) sampleAfter) bool {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return false
	}
	j.running = true
	j.op = op
	j.prog = sample.Progress{Op: op}
	j.err = nil
	j.after = sampleAfter{}
	j.mu.Unlock()

	go func() {
		err := work(base, func(p sample.Progress) {
			j.mu.Lock()
			j.prog = p
			j.mu.Unlock()
		})
		if sampleRefusal(err) {
			err = nil
		}
		var left sampleAfter
		if err != nil && after != nil {
			left = after(context.WithoutCancel(base))
		}
		j.mu.Lock()
		j.running = false
		j.err = err
		j.after = left
		j.mu.Unlock()
	}()
	return true
}

// sampleLeft reads the shared sample-data record after a job failed.
func (s *Server) sampleLeft(ctx context.Context) sampleAfter {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := s.Sample.Status(ctx)
	a := sampleAfter{known: err == nil, seen: s.Sample.Changes()}
	if st != nil {
		a.left = st.ID
	}
	return a
}

// sampleBase is the context sample-data jobs run under.
func (s *Server) sampleBase() context.Context {
	if s.Background != nil {
		return s.Background
	}
	return context.Background()
}

// sampleStatus is the GET /api/sample reply: whether the feature is
// available, whether a set is loaded (or a load stopped part way), what a
// running job is doing, and the stories and counts so the card can show
// what to try.
type sampleStatus struct {
	Available bool `json:"available"`
	Loaded    bool `json:"loaded"`
	// Partial says a load stopped part way: what it wrote should be removed.
	Partial bool   `json:"partial,omitempty"`
	Running bool   `json:"running"`
	Op      string `json:"op,omitempty"`
	Phase   string `json:"phase,omitempty"`
	Percent int    `json:"percent,omitempty"`
	// Where says, in a sentence, where a job this server did not start
	// runs: another server that shares the OpenSearch, or the command line.
	Where string `json:"where,omitempty"`
	// Error says in plain English what went wrong with the last job this
	// server ran and what to do; ErrorDetail is the technical text.
	Error       string            `json:"error,omitempty"`
	ErrorDetail string            `json:"error_detail,omitempty"`
	State       *sample.State     `json:"state,omitempty"`
	Sizes       []sample.Size     `json:"sizes,omitempty"`
	CannotFire  map[string]string `json:"cannot_fire,omitempty"`
	// NoData says no events at all arrived in the last 7 days, so the
	// pages can point a new admin at the sample data.
	NoData bool `json:"no_data,omitempty"`
}

func (s *Server) handleSampleStatus(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeJSON(w, http.StatusOK, sampleStatus{Available: false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	st, act, err := s.Sample.Current(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	job := s.sampleJob.snapshot()
	// A load or removal made on another server, or with the command line,
	// reaches this server's copies of the sample's context (its threat
	// intel and asset lists) as soon as the record shows it.
	fctx, fcancel := context.WithTimeout(r.Context(), 5*time.Second)
	if err := s.Sample.Follow(fctx, st, act); err != nil {
		s.Log.Debug("could not bring the sample data's context up to date here", "err", err)
	}
	fcancel()
	resp := sampleStatus{
		Available:  true,
		Loaded:     st != nil && !st.Partial,
		Partial:    st != nil && st.Partial,
		Running:    job.running,
		Op:         job.op,
		Phase:      job.prog.Phase,
		Percent:    job.prog.Percent,
		State:      st,
		Sizes:      sample.Sizes,
		CannotFire: s.Sample.CannotFire(),
	}
	// A job in another process (another server, the command line, or this
	// server before a restart in place) reports through the loader's record.
	if !job.running && act != nil {
		resp.Running, resp.Op, resp.Phase, resp.Percent = true, act.Op, act.Phase, act.Percent
		resp.Where = sampleWhere(act)
	}
	if resp.Running {
		// While a load runs, its state is partial by design.
		resp.Partial = false
	} else if job.errorApplies(st, s.Sample.Changes()) {
		// This server's last job failed, and nobody has loaded or removed
		// since: say what went wrong.
		resp.Error, resp.ErrorDetail = sampleErrorText(job.op, job.err, st)
	}
	if st == nil && !resp.Running {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		resp.NoData = s.Sample.EventsSince(ctx, 7*24*time.Hour) == 0
		cancel()
	}
	writeJSON(w, http.StatusOK, resp)
}

// sampleWhere says where a job this server did not start runs.
func sampleWhere(a *sample.Activity) string {
	switch {
	case a.Command && a.Server != "":
		return "Started with the signalith sample-data command on " + a.Server + "."
	case a.Command:
		return "Started with the signalith sample-data command."
	case a.Server != "":
		return "Started on the server " + a.Server + "."
	}
	return ""
}

// sampleErrorText puts a failed job's error in plain English with what to
// do next, given the record st it left, and keeps the technical text for a
// Details disclosure.
func sampleErrorText(op string, err error, st *sample.State) (string, string) {
	what := "load the sample data"
	if op == "remove" {
		what = "remove the sample data"
	}
	next := " Try again."
	switch {
	case st != nil && st.Partial && st.Removing:
		next = " Use Finish removing to take out the rest."
	case st != nil && st.Partial:
		next = " Remove what was loaded, then load it again."
	}
	var ue *url.Error
	var se *store.Error
	var old *sample.OldJobsServerError
	var msg string
	switch {
	case errors.Is(err, sample.ErrUnnamedLoad):
		return "The record of the sample data did not say which load it was, so Signalith could not tell sample events, findings and investigations from yours and deleted none of them. It removed the sample threat intel and asset entries and cleared the record. Findings from an earlier load, and its investigation \"" + sample.CaseTitle + "\", may still be on the Findings and Cases pages: close them there by hand. Its sample events stay until retention deletes them; detections ignore them. You can load the sample data again.", ""
	case errors.As(err, &old):
		return sampleOldJobsServerText(old), err.Error()
	case errors.Is(err, sample.ErrBusy):
		return "Another sample-data load or removal is running. Wait for it to finish.", ""
	case errors.Is(err, sample.ErrTakenOver):
		msg = "This server lost touch with OpenSearch for a while, so another server took the job over."
	case errors.Is(err, sample.ErrAlreadyLoaded):
		return "Sample data is already loaded. Remove it before loading again.", ""
	case errors.Is(err, sample.ErrPartial):
		return "The last load or removal did not finish. Remove what is left, then load again.", ""
	case store.NoAnswer(err):
		msg = "OpenSearch didn't answer in time, so Signalith could not " + what + ". Check the Health page."
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		msg = "Signalith stopped before it could " + what + "."
	case errors.As(err, &ue):
		msg = "Signalith lost its connection to OpenSearch and could not " + what + ". Check the Health page."
	case store.RefusalOf(err) == store.RefusedNotInitialized:
		msg = "OpenSearch's security settings aren't loaded, so it refuses every request and Signalith could not " + what + ". The Health page says what to do."
	case store.IsClusterBlock(err):
		msg = "OpenSearch is refusing changes (it may be low on disk space), so Signalith could not " + what + ". Check the Health page."
	case errors.As(err, &se) && (se.Status == http.StatusTooManyRequests || se.Status >= 500):
		msg = "OpenSearch was too busy to " + what + ". Check the Health page."
	case errors.Is(err, sample.ErrNothingWritten):
		msg = "OpenSearch did not accept any of the sample events, so nothing was loaded. Check the Health page."
	default:
		msg = "Something went wrong and Signalith could not " + what + "."
	}
	return msg + next, err.Error()
}

// sampleOldJobsServerText says why a load is refused while the server
// that runs the background jobs runs an older version.
func sampleOldJobsServerText(e *sample.OldJobsServerError) string {
	return "The server that runs the background jobs, " + e.Name + ", runs an older version of Signalith that would mix the sample data with your own. Upgrade every server to this version, then load the sample data."
}

type sampleLoadRequest struct {
	Size sample.Size `json:"size"`
}

func (s *Server) handleSampleLoad(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeError(w, http.StatusServiceUnavailable, errSampleOff)
		return
	}
	var req sampleLoadRequest
	if err := readStrict(r, &req); err != nil {
		// An empty body is fine; default the size.
		req = sampleLoadRequest{}
	}
	if req.Size == "" {
		req.Size = sample.SizeStandard
	}
	if !req.Size.Valid() {
		writeError(w, http.StatusBadRequest, errors.New("size must be \"standard\" or \"small\""))
		return
	}
	if !s.sampleFree(w, r, true) {
		return
	}
	loader := s.Sample
	size := req.Size
	user := userOf(r)
	started := s.sampleJob.start(s.sampleBase(), "load", func(ctx context.Context, prog sample.ProgressFn) error {
		_, err := loader.Load(ctx, size, prog)
		if err != nil {
			s.Log.Warn("sample data load failed", "audit", true, "by", user, "size", size, "err", err)
		}
		return err
	}, s.sampleLeft)
	if !started {
		sampleBusy(w)
		return
	}
	s.audit(r, "sample data load started", "size", size)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "op": "load", "size": size})
}

func (s *Server) handleSampleRemove(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeError(w, http.StatusServiceUnavailable, errSampleOff)
		return
	}
	if !s.sampleFree(w, r, false) {
		return
	}
	loader := s.Sample
	user := userOf(r)
	started := s.sampleJob.start(s.sampleBase(), "remove", func(ctx context.Context, prog sample.ProgressFn) error {
		_, err := loader.Remove(ctx, prog)
		switch {
		case errors.Is(err, sample.ErrUnnamedLoad):
			s.Log.Warn("sample data record named no load: cleared it, deleted no events, findings or investigations", "audit", true, "by", user)
		case err != nil:
			s.Log.Warn("sample data remove failed", "audit", true, "by", user, "err", err)
		}
		return err
	}, s.sampleLeft)
	if !started {
		sampleBusy(w)
		return
	}
	s.audit(r, "sample data remove started")
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "op": "remove"})
}

// sampleFree answers 409 and reports false when a job runs anywhere, or
// when the state does not allow the step: a load needs nothing loaded, a
// removal needs something loaded (complete or partial). The loader checks
// again when it starts, so two servers asked at once cannot both go ahead.
func (s *Server) sampleFree(w http.ResponseWriter, r *http.Request, load bool) bool {
	if s.sampleJob.snapshot().running {
		sampleBusy(w)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	st, act, err := s.Sample.Current(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}
	if act != nil {
		sampleBusy(w)
		return false
	}
	switch {
	case load && st != nil && st.Partial && st.Removing:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "The last removal did not finish. Finish removing the sample data first.", "code": "partial"})
		return false
	case load && st != nil && st.Partial:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "The last load did not finish. Remove what it loaded first.", "code": "partial"})
		return false
	case load && st != nil:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "Sample data is already loaded. Remove it first.", "code": "already_loaded"})
		return false
	case !load && st == nil:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "There is no sample data to remove.", "code": "not_loaded"})
		return false
	}
	if load {
		var old *sample.OldJobsServerError
		err := s.Sample.CheckJobsServer(ctx)
		switch {
		case errors.As(err, &old):
			writeJSON(w, http.StatusConflict, map[string]any{"error": sampleOldJobsServerText(old), "code": "old_jobs_server"})
			return false
		case err != nil:
			writeError(w, http.StatusInternalServerError, err)
			return false
		}
	}
	return true
}

func sampleBusy(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "A sample-data load or removal is already running. Wait for it to finish.", "code": "busy"})
}
