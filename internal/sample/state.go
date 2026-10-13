package sample

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A load's bookkeeping lives in OpenSearch, in one document of the runtime
// index (<prefix>_runtime, where servers that share one OpenSearch find
// each other), not in a file of one server. Every server, and the signalith
// sample-data command on any computer, sees the same load:
//
//   - The document is created when a load starts, before anything else is
//     written, so even a load that stops part way can be removed. Creating
//     it is also what keeps to one load at a time: a second load, on any
//     server, finds it there and is refused.
//   - While a load or removal runs, the document holds its progress and a
//     heartbeat, so every server shows it and none starts another. A job
//     whose document stopped changing for a minute (its process ended
//     mid-job) may be taken over by a removal. That minute is measured the
//     way the job lease measures it: by how long the reader has seen the
//     same version, on its own monotonic clock. Clocks of different
//     computers are never compared, so a computer whose clock is wrong
//     cannot take a running job for stopped.
//   - A removal marks the state partial as it takes the document over, so
//     a removal that stops part way shows as unfinished, not as loaded. It
//     deletes the document last, once everything is gone.

var (
	// ErrBusy means another load or removal is running: on this server, on
	// another server that shares the OpenSearch, or in a signalith
	// sample-data command.
	ErrBusy = errors.New("a sample-data load or removal is already running")
	// ErrTakenOver means another server took the job over after this one's
	// heartbeat stopped reaching OpenSearch for a minute.
	ErrTakenOver = errors.New("another server took over this sample-data job after this one lost touch with OpenSearch")
	// errNoDocs means the loader was built without an OpenSearch client.
	errNoDocs = errors.New("sample data needs OpenSearch, which this loader was not given")
)

// OldJobsServerError means the server that runs the background jobs runs
// a version of Signalith from before the sample data: its scheduled
// detections and threat intel downloads would not leave the sample out.
type OldJobsServerError struct {
	Name    string // the server's name
	Version string // its version, when known
}

func (e *OldJobsServerError) Error() string {
	v := ""
	if e.Version != "" {
		v = " (version " + e.Version + ")"
	}
	return fmt.Sprintf("the server that runs the background jobs, %s%s, runs a version of Signalith that does not keep sample data apart; upgrade every server before loading sample data", e.Name, v)
}

const (
	stateID   = "sample:data"
	stateKind = "sample_data"
	heartbeat = 5 * time.Second
	// StaleJob is how long a running job's document must stand unchanged,
	// as one reader sees it, before that reader takes the job for stopped.
	// A running job rewrites it every few seconds.
	StaleJob = time.Minute
	// docTimeout bounds one read or write of the document.
	docTimeout = 15 * time.Second
)

// endTries is how often a job tries to settle its document when it ends,
// and endBackoff the wait before the second try, doubled after each.
var (
	endTries   = 4
	endBackoff = time.Second
)

// processID names this process in the jobs it runs. A job recorded by this
// server under another process ID was left by an earlier run of this
// server (it was restarted, or stopped), so it is not running.
var processID = newToken()

func newToken() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Docs reads and writes a document with its version, so two servers never
// overwrite each other's changes. *store.Client has it.
type Docs interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
}

// Activity is a running load or removal, as every server sees it.
type Activity struct {
	Op      string `json:"op"`    // "load" or "remove"
	Phase   string `json:"phase"` // plain-English step
	Percent int    `json:"percent"`
	// Server names where it runs: the server's name, or the computer's
	// when the signalith sample-data command runs it (Command).
	Server  string `json:"server,omitempty"`
	Command bool   `json:"command,omitempty"`
	// Node is the node ID of the server that runs it ("" for the
	// command), and Process the process that runs it there.
	Node    string    `json:"node,omitempty"`
	Process string    `json:"process,omitempty"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	// Beat is when the job last wrote its document, by the clock of the
	// computer that runs it. It is for showing only: whether the job still
	// runs is never judged from it.
	Beat time.Time `json:"beat"`
}

// stateDoc is the document. In OpenSearch its state and job sit under
// "body", which the runtime index stores without indexing: its top-level
// fields have types of their own there (state, for one, is a server's
// state, a keyword).
type stateDoc struct {
	Kind  string
	State *State
	Job   *Activity
	// Owner is the random ID of the load or removal that wrote the
	// document last. A job whose write was refused finds out from it
	// whether the document is still its own: a write whose answer was
	// lost may have gone through after all.
	Owner string
}

type stateBody struct {
	State *State    `json:"state"`
	Job   *Activity `json:"job,omitempty"`
	Owner string    `json:"owner,omitempty"`
}

func (d stateDoc) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string    `json:"kind"`
		Body stateBody `json:"body"`
	}{d.Kind, stateBody{d.State, d.Job, d.Owner}})
}

func (d *stateDoc) UnmarshalJSON(b []byte) error {
	var raw struct {
		Kind string    `json:"kind"`
		Body stateBody `json:"body"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*d = stateDoc{Kind: raw.Kind, State: raw.Body.State, Job: raw.Body.Job, Owner: raw.Body.Owner}
	return nil
}

func (l *Loader) index() string { return cluster.RuntimeIndex(l.Prefix) }

// observation is the document as this loader last saw it.
type observation struct {
	seen bool
	ver  store.Version
	// since is when this version was first seen, on the monotonic clock.
	since time.Time
	// set is the sample set recorded ("" for none), and changes counts how
	// often a read found it different from the read before.
	setSeen bool
	set     string
	changes uint64
}

// mono returns the time on this process's monotonic clock.
func (l *Loader) mono() time.Time {
	if l.clock != nil {
		return l.clock()
	}
	return time.Now()
}

// read returns the document, or nil when there is none.
func (l *Loader) read(ctx context.Context) (*stateDoc, store.Version, error) {
	if l.Docs == nil {
		return nil, store.Version{}, errNoDocs
	}
	ctx, cancel := context.WithTimeout(ctx, docTimeout)
	defer cancel()
	src, v, found, err := l.Docs.Get(ctx, l.index(), stateID)
	if err != nil {
		return nil, store.Version{}, err
	}
	if !found {
		l.noteSet("")
		return nil, store.Version{}, nil
	}
	var d stateDoc
	if err := json.Unmarshal(src, &d); err != nil {
		return nil, store.Version{}, fmt.Errorf("reading the sample-data bookkeeping in %s: %w", l.index(), err)
	}
	if d.State == nil {
		// Never written so; treat it as a load that did not finish, which
		// Remove clears. With no load ID to find sample data by, Remove
		// deletes no events, findings or investigations (see Remove).
		d.State = &State{Partial: true}
	}
	l.noteSet(d.State.ID)
	return &d, v, nil
}

// noteSet notes the sample set a read found ("" for none).
func (l *Loader) noteSet(id string) {
	l.obsMu.Lock()
	defer l.obsMu.Unlock()
	if l.obs.setSeen && l.obs.set != id {
		l.obs.changes++
	}
	l.obs.setSeen, l.obs.set = true, id
}

// Changes counts how often this loader's reads found a different sample
// set recorded than the read before (another set, or none where there was
// one): a load or removal happened in between, here or elsewhere. A
// server reads the document at least every minute (WatchLists), and every
// second while a page shows a job.
func (l *Loader) Changes() uint64 {
	l.obsMu.Lock()
	defer l.obsMu.Unlock()
	return l.obs.changes
}

// running reports whether the job recorded in d, read at version v, may
// still be running. One that this server's node recorded from another
// process is not: that process ended. Any other runs until this loader
// has seen the document stand unchanged at one version for StaleJob.
func (l *Loader) running(d *stateDoc, v store.Version) bool {
	if d == nil || d.Job == nil {
		return false
	}
	if a := d.Job; l.NodeID != "" && a.Node == l.NodeID && a.Process != processID {
		return false
	}
	return !l.stood(v)
}

// stood reports whether this loader has seen the document at version v,
// unchanged, for StaleJob. It starts the count at a version it had not
// seen before.
func (l *Loader) stood(v store.Version) bool {
	l.obsMu.Lock()
	defer l.obsMu.Unlock()
	now := l.mono()
	if !l.obs.seen || !l.obs.ver.Same(v) {
		l.obs.seen, l.obs.ver, l.obs.since = true, v, now
		return false
	}
	return now.Sub(l.obs.since) >= StaleJob
}

// Current returns the sample's state, nil when none is loaded (a state with
// Partial set is a load or removal that did not finish), and the load or
// removal running now in any process, nil when none is.
func (l *Loader) Current(ctx context.Context) (*State, *Activity, error) {
	d, v, err := l.read(ctx)
	if err != nil || d == nil {
		return nil, nil, err
	}
	var act *Activity
	if l.running(d, v) {
		act = d.Job
	}
	return d.State, act, nil
}

// Status returns the sample's state, or nil when none is loaded. A state
// with Partial set is a load or removal that did not finish.
func (l *Loader) Status(ctx context.Context) (*State, error) {
	st, _, err := l.Current(ctx)
	return st, err
}

// Activity returns the running load or removal, from any process, or nil
// when none is running (or it cannot be told).
func (l *Loader) Activity(ctx context.Context) *Activity {
	_, act, err := l.Current(ctx)
	if err != nil {
		return nil
	}
	return act
}

// JobWatch is what WatchJob found out about the job in the document.
type JobWatch int

const (
	// JobNone: no load or removal is recorded as running (any more).
	JobNone JobWatch = iota
	// JobRunning: the document changed while watched, so the job runs.
	JobRunning
	// JobStopped: the job is not running: its document stood still for
	// StaleJob, or it was left by an earlier run of this server.
	JobStopped
	// JobUnknown: the time to watch ran out first.
	JobUnknown
)

// WatchJob reads the document every second for at most limit, to tell
// whether the load or removal it records is still running. The command
// line uses it: unlike a server, it has not been reading the document all
// along. It returns the job as last read, nil when none is recorded.
func (l *Loader) WatchJob(ctx context.Context, limit time.Duration) (JobWatch, *Activity, error) {
	end := l.mono().Add(limit)
	var first store.Version
	seen := false
	for {
		d, v, err := l.read(ctx)
		switch {
		case err != nil:
			return JobUnknown, nil, err
		case d == nil || d.Job == nil:
			return JobNone, nil, nil
		case !l.running(d, v):
			return JobStopped, d.Job, nil
		case seen && !v.Same(first):
			return JobRunning, d.Job, nil
		case !l.mono().Before(end):
			return JobUnknown, d.Job, nil
		}
		if !seen {
			first, seen = v, true
		}
		if err := l.pause(ctx, time.Second); err != nil {
			return JobUnknown, d.Job, err
		}
	}
}

// pause waits d, or until ctx ends.
func (l *Loader) pause(ctx context.Context, d time.Duration) error {
	if l.sleep != nil {
		return l.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// refusal says why a load cannot start while the document d, read at
// version v, exists.
func (l *Loader) refusal(d *stateDoc, v store.Version) error {
	switch {
	case l.running(d, v):
		return ErrBusy
	case d.State.Partial:
		return ErrPartial
	}
	return ErrAlreadyLoaded
}

// CheckJobsServer refuses a load while the server that runs the background
// jobs (the job lease's holder) runs a version from before the sample
// data, with an *OldJobsServerError: its scheduled detections would raise
// findings and risk from the sample that Remove cannot tell from yours,
// and its feed downloads would delete the sample's threat intel. When no
// server holds the lease, or its holder's heartbeat is gone or says it
// stopped, no server runs those jobs now, and the load may go ahead.
func (l *Loader) CheckJobsServer(ctx context.Context) error {
	if l.Docs == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, docTimeout)
	defer cancel()
	src, _, found, err := l.Docs.Get(ctx, l.index(), cluster.LeaseDocID)
	if err != nil || !found {
		return err
	}
	var lease cluster.LeaseDoc
	if err := json.Unmarshal(src, &lease); err != nil || lease.Holder == "" {
		return nil
	}
	src, _, found, err = l.Docs.Get(ctx, l.index(), cluster.NodeDocID(lease.Holder))
	if err != nil || !found {
		return err
	}
	var hb cluster.Heartbeat
	if err := json.Unmarshal(src, &hb); err != nil {
		return nil
	}
	if hb.State == cluster.StateStopped || slices.Contains(hb.Features, cluster.FeatureSampleData) {
		return nil
	}
	name := hb.Name
	if name == "" {
		name = lease.HolderName
	}
	return &OldJobsServerError{Name: name, Version: hb.Version}
}

func (l *Loader) newActivity(op string) *Activity {
	now := time.Now().UTC()
	return &Activity{Op: op, Server: l.Server, Command: l.Command, Node: l.NodeID, Process: processID,
		PID: os.Getpid(), Started: now, Beat: now}
}

// jobs counts the jobs of this process that have not settled their
// document yet, for WaitJobs.
var jobs sync.WaitGroup

// WaitJobs waits, for at most d, for the loads and removals this process
// runs to settle their documents once they have been told to stop. A
// server that stops calls it, so the others see at once that its job did
// not finish. It reports whether they all did.
func WaitJobs(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		jobs.Wait()
		close(done)
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// job is a load or removal holding the document. Heartbeat times are
// wall-clock times (never the loader's Now, which tests fix), for showing.
type job struct {
	l *Loader
	// cancel stops the job's work when another process took it over.
	cancel context.CancelCauseFunc
	token  string

	mu      sync.Mutex
	doc     stateDoc
	ver     store.Version
	written time.Time
	lost    bool
	stop    chan struct{}
	done    chan struct{}
}

func (l *Loader) newJob(cancel context.CancelCauseFunc, st *State, op string) *job {
	token := newToken()
	return &job{l: l, cancel: cancel, token: token,
		doc: stateDoc{Kind: stateKind, State: st, Job: l.newActivity(op), Owner: token}}
}

// startLoad creates the document for a new load holding st, or says why
// it cannot: ErrAlreadyLoaded, ErrPartial or ErrBusy.
func (l *Loader) startLoad(ctx context.Context, cancel context.CancelCauseFunc, st *State) (*job, error) {
	if err := cluster.EnsureRuntime(ctx, l.OS, l.Prefix); err != nil {
		return nil, fmt.Errorf("preparing the %s index: %w", l.index(), err)
	}
	cp := *st
	j := l.newJob(cancel, &cp, "load")
	wctx, done := context.WithTimeout(ctx, docTimeout)
	v, err := l.Docs.Create(wctx, l.index(), stateID, j.doc, false)
	done()
	if errors.Is(err, store.ErrExists) {
		d, v, rerr := l.read(ctx)
		switch {
		case rerr != nil:
			return nil, rerr
		case d == nil:
			return nil, ErrBusy // removed just now; the next try will do
		}
		return nil, l.refusal(d, v)
	}
	if err != nil {
		return nil, fmt.Errorf("recording the sample-data load in %s: %w", l.index(), err)
	}
	j.ver = v
	j.start()
	return j, nil
}

// startRemove takes the document over for a removal. It returns no job
// when nothing is loaded, and ErrBusy while another job runs. The state
// it writes is partial and says a removal started, so if the removal
// stops part way, every server shows it as unfinished rather than loaded.
func (l *Loader) startRemove(ctx context.Context, cancel context.CancelCauseFunc) (*job, error) {
	d, v, err := l.read(ctx)
	if err != nil || d == nil {
		return nil, err
	}
	if l.running(d, v) {
		return nil, ErrBusy
	}
	st := *d.State
	st.Partial, st.Removing = true, true
	j := l.newJob(cancel, &st, "remove")
	wctx, done := context.WithTimeout(ctx, docTimeout)
	nv, err := l.Docs.PutIf(wctx, l.index(), stateID, j.doc, v, false)
	done()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil // removed meanwhile
	case errors.Is(err, store.ErrConflict):
		return nil, ErrBusy
	case err != nil:
		return nil, fmt.Errorf("recording the sample-data removal in %s: %w", l.index(), err)
	}
	j.ver = nv
	j.start()
	return j, nil
}

// state returns a copy of the state the job holds.
func (j *job) state() *State {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := *j.doc.State
	return &cp
}

func (j *job) start() {
	jobs.Add(1)
	j.stop, j.done = make(chan struct{}), make(chan struct{})
	j.written = time.Now()
	go j.beat()
}

func (j *job) beat() {
	defer close(j.done)
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-j.stop:
			return
		case <-t.C:
			j.mu.Lock()
			_ = j.writeLocked()
			j.mu.Unlock()
		}
	}
}

// holder is who holds the document, as a read after a refused write found.
type holder int

const (
	heldByOther holder = iota
	heldByJob
	holderGone
)

// whoHolds reads the document after a write of the job's was refused as a
// conflict. When the job still owns it (an earlier write whose answer was
// lost went through after the read that should have told), the job takes
// its version and carries on. The caller holds j.mu.
func (j *job) whoHolds() (holder, error) {
	d, v, err := j.l.read(context.Background())
	switch {
	case err != nil:
		return heldByOther, err
	case d == nil:
		return holderGone, nil
	case d.Owner != j.token:
		return heldByOther, nil
	}
	j.ver = v
	return heldByJob, nil
}

// putLocked writes the document over the version written last.
func (j *job) putLocked() (store.Version, error) {
	ctx, cancel := context.WithTimeout(context.Background(), docTimeout)
	defer cancel()
	return j.l.Docs.PutIf(ctx, j.l.index(), stateID, j.doc, j.ver, false)
}

// writeLocked writes the document with a new heartbeat; the caller holds
// j.mu. A write that finds the document changed by another process, or
// gone, means it took the job over: the job's work is stopped. Any other
// failure is tried again on the next heartbeat.
func (j *job) writeLocked() error {
	if j.lost {
		return ErrTakenOver
	}
	if j.doc.Job != nil {
		j.doc.Job.Beat = time.Now().UTC()
	}
	v, err := j.putLocked()
	if errors.Is(err, store.ErrConflict) {
		h, rerr := j.whoHolds()
		switch {
		case rerr != nil:
			return rerr // cannot tell now; the next write tries again
		case h == heldByJob:
			v, err = j.putLocked()
		}
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return j.loseLocked()
	}
	if err != nil {
		return err
	}
	j.ver, j.written = v, time.Now()
	return nil
}

func (j *job) loseLocked() error {
	j.lost = true
	j.cancel(ErrTakenOver)
	j.l.log().Warn("sample data: another process took this job over; stopping", "index", j.l.index())
	return ErrTakenOver
}

// deleteLocked deletes the document, once a removal is done.
func (j *job) deleteLocked() error {
	del := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), docTimeout)
		defer cancel()
		return j.l.Docs.DeleteIf(ctx, j.l.index(), stateID, j.ver, true)
	}
	err := del()
	if errors.Is(err, store.ErrConflict) {
		h, rerr := j.whoHolds()
		switch {
		case rerr != nil:
			return rerr
		case h == holderGone:
			return nil
		case h == heldByJob:
			err = del()
		}
	}
	switch {
	case err == nil, errors.Is(err, store.ErrNotFound):
		return nil
	case errors.Is(err, store.ErrConflict):
		return j.loseLocked()
	}
	return err
}

// set records the job's progress. It is written out when the step changed
// or a couple of seconds have passed, so the other servers can show it.
func (j *job) set(phase string, pct int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.doc.Job == nil {
		return
	}
	changed := phase != j.doc.Job.Phase
	j.doc.Job.Phase, j.doc.Job.Percent = phase, pct
	if changed || time.Since(j.written) >= 2*time.Second {
		_ = j.writeLocked()
	}
}

// save records the load's state as it is now.
func (j *job) save(st *State) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := *st
	j.doc.State = &cp
	return j.writeLocked()
}

// end stops the heartbeat and settles the document: it keeps st with no
// job running, or, after a finished removal (st nil), is deleted.
// OpenSearch may be busy right then, so a failed try is repeated a few
// times before giving up.
func (j *job) end(st *State) error {
	defer jobs.Done()
	close(j.stop)
	<-j.done
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lost {
		return ErrTakenOver
	}
	// From here no progress is written: the job is over.
	j.doc.Job = nil
	if st != nil {
		cp := *st
		j.doc.State = &cp
	}
	wait := endBackoff
	for try := 1; ; try++ {
		var err error
		if st != nil {
			err = j.writeLocked()
		} else {
			err = j.deleteLocked()
		}
		if err == nil || errors.Is(err, ErrTakenOver) || try >= endTries {
			return err
		}
		j.l.log().Debug("sample data: could not settle the job's record; trying again", "err", err)
		time.Sleep(wait)
		wait *= 2
	}
}

// takenOver turns the error of a job's work, stopped because another
// process took the job over, into ErrTakenOver.
func takenOver(ctx context.Context, err error) error {
	if err != nil && errors.Is(context.Cause(ctx), ErrTakenOver) {
		return ErrTakenOver
	}
	return err
}
