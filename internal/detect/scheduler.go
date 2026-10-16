package detect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Runner executes parsed queries; *search.Engine implements it.
type Runner interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// Scheduler runs enabled detections on their schedules.
//
// Each detection runs once per slot of its schedule (see SlotAt), and
// each run searches the lookback that ends at its slot. The server that
// runs the detections keeps, per detection, a watermark: the last slot
// that was run. Slots missed while no server ran the detections are run
// later, oldest first, up to CatchUp back; older ones are skipped and
// recorded. Finding and risk IDs come from the slot, so a slot run twice
// (after a takeover, say) raises nothing twice.
type Scheduler struct {
	Library  *Library
	Engine   Runner
	Findings findings.Store
	// Risk stores risk events; nil disables risk.
	Risk RiskStore
	// Assets adds business context and scales risk; nil means none.
	Assets *assets.Store
	Log    *slog.Logger
	// MaxFindingsPerRun caps the findings one run can raise (default 100),
	// so a noisy rule cannot flood the queue.
	MaxFindingsPerRun int
	// Tick is how often the scheduler checks for due detections (default 15s).
	Tick time.Duration
	// Now is the wall clock, for times people read (when a run started).
	Now func() time.Time
	// ClusterNow is the time slots and throttles are worked out with:
	// OpenSearch's clock as this server measures it, so every server
	// agrees on them. Nil uses Now.
	ClusterNow func() time.Time
	// Workers is how many detections run at once (default 4), so one slow
	// detection cannot hold up the others.
	Workers int
	// SampleMark, when set, makes runs read only the documents of that
	// sample-data load and marks every finding and risk event they write
	// with it. The sample-data backfill uses a throwaway Scheduler with it
	// set. The live scheduler leaves it empty: its runs leave all sample
	// documents out and use only the user's own asset and identity lists,
	// so nothing it writes ever comes from sample data. See ScopeSample.
	SampleMark string
	// Timeout caps one run. Zero gives each detection its schedule
	// interval, between MinRunTimeout and MaxRunTimeout, so a run cannot
	// last into its next one.
	Timeout time.Duration
	// Allowed, when set, says whether this server may still run the
	// schedule: with several servers, only the one that runs the
	// background jobs may. It is asked before each scheduled run and
	// before each finding or risk event it writes, so a server that lost
	// that role stops at once.
	Allowed func() bool
	// CatchUp is how far back missed slots are run (detections.catch_up):
	// zero means DefaultCatchUp, and a negative value runs only the
	// current slot. SetCatchUp changes it.
	CatchUp time.Duration
	// Runtime keeps the run state and throttle documents, in the index
	// RuntimeIndex; nil keeps them in memory, for tests and throwaway
	// schedulers. Epoch is the job lease's epoch, written into them, so a
	// server that lost the lease cannot write over a newer leader's state;
	// NodeID names this server in them.
	Runtime      RunStore
	RuntimeIndex string
	Epoch        func() int64
	NodeID       string

	mu sync.Mutex
	// flags are this server's running and waiting runs.
	flags map[string]runFlags
	// det is the leader's copy of the run state, read once per epoch
	// (loadedEpoch); nil until read, or after this server stopped running
	// the schedule.
	det         map[string]*detEntry
	loadedEpoch int64
	// firstStart says the run state, when last read, had no detstate
	// documents at all: the dispatch after that read starts each enabled
	// rule at its current slot rather than its next one.
	firstStart bool
	// noFirstStart turns that off, for tests that start from a new rule.
	noFirstStart bool
	cache        *statusCache
	memRuns      RunStore
	houseAt      time.Time
	workers      chan struct{}
	spare        chan struct{}
}

type runFlags struct{ running, queued bool }

// Bounds of the default run timeout.
const (
	MinRunTimeout = time.Minute
	MaxRunTimeout = 5 * time.Minute
)

// Catch-up limits.
const (
	// DefaultCatchUp is detections.catch_up when it is not set.
	DefaultCatchUp = 6 * time.Hour
	// MaxCatchUp is the most detections.catch_up may be.
	MaxCatchUp = 7 * 24 * time.Hour
	// maxSlotsPerTick is how many missed slots of one rule run per tick.
	maxSlotsPerTick = 48
	// maxAttempts is how many times a slot that times out is run before
	// the watermark moves past it.
	maxAttempts = 3
	// fallbackWindow is how long after a run state is first written
	// throttles also ask the findings and risk indices, which held them
	// before throttles were documents.
	fallbackWindow = 7 * 24 * time.Hour
	// housekeepEvery is how often the run state of deleted rules is
	// looked at, and goneFor how long after a rule was deleted its run
	// state and throttles are removed.
	housekeepEvery = 10 * time.Minute
	goneFor        = 24 * time.Hour
)

// Error kinds of a run (RunState.ErrorKind).
const (
	// ErrorQuery is a rule that cannot run as written: the slot is not
	// run again, and the next one uses the fixed rule.
	ErrorQuery = "query"
	// ErrorTimeout is a run stopped at its timeout: the slot is tried
	// again, up to three times.
	ErrorTimeout = "timeout"
	// ErrorTransient is OpenSearch not answering, or too busy: the slot
	// is tried again.
	ErrorTransient = "transient"
)

// RuleError is a detection that cannot run as written: its query or its
// durations do not parse.
type RuleError struct{ Err error }

func (e *RuleError) Error() string { return e.Err.Error() }
func (e *RuleError) Unwrap() error { return e.Err }

// searchError is an error of a run's search, as opposed to one of the
// writes that follow it: only a search OpenSearch refuses as a bad
// request says the rule itself is wrong.
type searchError struct{ Err error }

func (e *searchError) Error() string { return e.Err.Error() }
func (e *searchError) Unwrap() error { return e.Err }

// ErrorKind classifies a run's error: ErrorQuery when the rule itself is
// wrong (its query does not parse, or OpenSearch refuses its search as a
// bad request), ErrorTransient otherwise (connection problems, 429, 5xx,
// timeouts of one request, a cancelled run, and any failed write of a
// finding, risk event or throttle, so the slot is run again). A run that
// ran out of its own time is ErrorTimeout, which only the scheduler can
// tell.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	var re *RuleError
	var qe *search.QueryError
	var pe *query.Error
	var se *store.Error
	var sr *searchError
	switch {
	case errors.As(err, &re), errors.As(err, &qe), errors.As(err, &pe):
		return ErrorQuery
	case errors.As(err, &sr) && errors.As(sr.Err, &se) && se.Status == http.StatusBadRequest:
		return ErrorQuery
	}
	return ErrorTransient
}

// Behind reports whether d, with run state st, is falling behind its
// schedule at now: its next slot ended longer than its schedule interval
// ago and it is not running, or a run in the last hour started that
// late.
func Behind(d *Detection, st RunState, now time.Time) bool {
	sched, err := ParseDuration(d.Schedule)
	if err != nil || !d.Enabled {
		return false
	}
	if !st.Running && !st.NextRun.IsZero() && now.Sub(st.NextRun) > sched {
		return true
	}
	return !st.LastLate.IsZero() && now.Sub(st.LastLate) < time.Hour
}

// RunState is what the pages show about a detection's runs.
type RunState struct {
	LastRun time.Time `json:"last_run,omitzero"`
	// NextRun is the end of the next slot to run; LastSlot the last one
	// run (the watermark).
	NextRun      time.Time `json:"next_run,omitzero"`
	LastSlot     time.Time `json:"last_slot,omitzero"`
	LastDuration int64     `json:"last_duration_ms"`
	LastResults  int       `json:"last_results"`
	LastFindings int       `json:"last_findings"`
	// LastRisk, LastThrottled and LastDuplicates count the last run's
	// risk events, results held back by a throttle, and findings that
	// were already raised for the slot.
	LastRisk       int    `json:"last_risk"`
	LastThrottled  int    `json:"last_throttled"`
	LastDuplicates int    `json:"last_duplicates"`
	LastError      string `json:"last_error,omitempty"`
	// ErrorKind is ErrorQuery, ErrorTimeout or ErrorTransient.
	ErrorKind string `json:"error_kind,omitempty"`
	// TimedOut says the last run was stopped for taking longer than its
	// timeout; LastError says how long that was.
	TimedOut bool `json:"timed_out,omitempty"`
	Capped   bool `json:"capped,omitempty"`
	Running  bool `json:"running,omitempty"`
	// Lag is how long after its slot ended the last scheduled run
	// started. LateRuns counts the runs that started more than one
	// schedule interval late, LastLate is when the latest one did.
	Lag      int64     `json:"lag_ms,omitempty"`
	LateRuns int       `json:"late_runs,omitempty"`
	LastLate time.Time `json:"last_late,omitzero"`
	// Skipped is the latest stretch of missed slots older than
	// detections.catch_up, which were not run.
	Skipped *Skipped `json:"skipped,omitempty"`
	// LastSuppressed is how many results of the last run an exception
	// matched.
	LastSuppressed int `json:"last_suppressed,omitempty"`
	// Node is the server that wrote the run state.
	Node string `json:"node,omitempty"`
	// Manual is the last "Run now", on any server.
	Manual *ManualRun `json:"manual,omitempty"`
	// StatusError says the run state could not be read just now.
	StatusError string `json:"status_error,omitempty"`

	queued bool // waiting for a worker
}

// RunResult reports one run.
type RunResult struct {
	Results   int                 `json:"results"`
	Findings  []*findings.Finding `json:"findings"`
	Risk      int                 `json:"risk_events"`
	Throttled int                 `json:"throttled"`
	// Duplicates counts findings the slot had already raised, in an
	// earlier run of the same slot.
	Duplicates int `json:"duplicates"`
	// Suppressed counts the results an exception matched.
	Suppressed int       `json:"suppressed,omitempty"`
	Capped     bool      `json:"capped,omitempty"`
	Earliest   time.Time `json:"earliest"`
	Latest     time.Time `json:"latest"`
}

// ErrNotAllowed stops a scheduled run on a server that no longer runs the
// background jobs.
var ErrNotAllowed = errors.New("stopped: this server no longer runs the background jobs, another one does")

// scheduledKey marks the context of a scheduled run, which Allowed fences.
type scheduledKey struct{}

// allowed reports whether a run under ctx may go on.
func (s *Scheduler) allowed(ctx context.Context) bool {
	if s.Allowed == nil || ctx.Value(scheduledKey{}) == nil {
		return true
	}
	return s.Allowed()
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// SetMaxFindingsPerRun changes the cap on findings, for runs that start
// after it returns.
func (s *Scheduler) SetMaxFindingsPerRun(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MaxFindingsPerRun = n
}

// SetCatchUp changes how far back missed slots are run, from the next
// tick on, as detections.catch_up says: zero turns catching up off.
func (s *Scheduler) SetCatchUp(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d <= 0 {
		d = -1
	}
	s.CatchUp = d
}

// CatchUpLimit is how far back missed slots are run; zero runs only the
// current slot.
func (s *Scheduler) CatchUpLimit() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.CatchUp == 0:
		return DefaultCatchUp
	case s.CatchUp < 0:
		return 0
	}
	return min(s.CatchUp, MaxCatchUp)
}

func (s *Scheduler) setFlags(id string, f runFlags) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flags == nil {
		s.flags = map[string]runFlags{}
	}
	if f == (runFlags{}) {
		delete(s.flags, id)
		return
	}
	s.flags[id] = f
}

// Start runs due detections until ctx is cancelled, at most Workers at a
// time so a burst of schedules cannot overload OpenSearch, while a slow
// one leaves the other workers free. It returns once the runs it started
// have stopped.
func (s *Scheduler) Start(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = 15 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		s.dispatch(ctx, &wg)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue runs every enabled detection whose slots are due, at most
// Workers at a time, and waits for them.
func (s *Scheduler) RunDue(ctx context.Context) {
	var wg sync.WaitGroup
	s.dispatch(ctx, &wg)
	wg.Wait()
}

// batch is the slots of one rule that one tick runs, oldest first.
type batch struct {
	d     *Detection
	sched time.Duration
	slots []time.Time
	// last is the watermark before the batch; current says the batch is
	// just the current slot.
	last    time.Time
	current bool
}

// dispatch starts the due slots of every detection that is not already
// running or waiting. Rules whose only due slot is the current one go
// first, the longest overdue first; then the rules catching up, oldest
// watermark first, on the workers the current ones leave free. Each
// rule's slots run in order, one at a time.
func (s *Scheduler) dispatch(ctx context.Context, wg *sync.WaitGroup) {
	ctx = context.WithValue(ctx, scheduledKey{}, true)
	if !s.allowed(ctx) {
		// Another server runs the schedule now: should this one take it
		// back, it reads the run state that one left.
		s.dropStates()
		return
	}
	if err := s.loadStates(ctx); err != nil {
		s.log().Warn("detections wait until their run state can be read", "err", err)
		return
	}
	s.mu.Lock()
	epoch, first := s.loadedEpoch, s.firstStart
	s.firstStart = false
	if s.workers == nil {
		n := s.Workers
		if n <= 0 {
			n = 4
		}
		s.workers, s.spare = make(chan struct{}, n), make(chan struct{}, max(n-1, 1))
	}
	workers, spare := s.workers, s.spare
	s.mu.Unlock()
	s.housekeep(ctx, epoch)

	now := s.clusterNow()
	limit := s.CatchUpLimit()
	var current, catchup []batch
	for _, d := range s.Library.List() {
		b, ok := s.plan(ctx, d, now, limit, epoch, first)
		if !ok {
			continue
		}
		if b.current {
			current = append(current, b)
		} else {
			catchup = append(catchup, b)
		}
	}
	sort.Slice(current, func(i, j int) bool {
		a, b := current[i], current[j]
		if oa, ob := now.Sub(a.slots[0]), now.Sub(b.slots[0]); oa != ob {
			return oa > ob
		}
		return a.d.ID < b.d.ID
	})
	sort.Slice(catchup, func(i, j int) bool {
		a, b := catchup[i], catchup[j]
		if !a.last.Equal(b.last) {
			return a.last.Before(b.last)
		}
		return a.d.ID < b.d.ID
	})

	// Catch-up waits until every current run has a worker.
	var started sync.WaitGroup
	gate := make(chan struct{})
	started.Add(len(current))
	wg.Add(1)
	go func() {
		defer wg.Done()
		started.Wait()
		close(gate)
	}()
	for _, b := range append(current, catchup...) {
		s.setFlags(b.d.ID, runFlags{queued: true})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.setFlags(b.d.ID, runFlags{})
			var once sync.Once
			if b.current {
				defer once.Do(started.Done)
			}
			s.runBatch(ctx, b, epoch, workers, spare, gate, func() { once.Do(started.Done) })
		}()
	}
}

// runBatch runs a rule's slots in order, taking a worker for each, and
// stops at the first that does not move the watermark on.
func (s *Scheduler) runBatch(ctx context.Context, b batch, epoch int64, workers, spare chan struct{}, gate <-chan struct{}, got func()) {
	for _, slot := range b.slots {
		if !b.current {
			select {
			case <-gate:
			case <-ctx.Done():
				return
			}
			select {
			case spare <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case workers <- struct{}{}:
		case <-ctx.Done():
			if !b.current {
				<-spare
			}
			return
		}
		if b.current {
			got()
		}
		ok := ctx.Err() == nil && s.allowed(ctx) && s.epoch() == epoch
		var err error
		if ok {
			s.setFlags(b.d.ID, runFlags{running: true})
			err = s.runSlot(ctx, b.d, b.sched, slot, !b.current, epoch)
			s.setFlags(b.d.ID, runFlags{queued: true})
		}
		<-workers
		if !b.current {
			<-spare
		}
		if !ok || err != nil {
			return
		}
	}
}

// plan works out the slots of d that are due at now (cluster time). It
// also writes the run state changes that need no run: a rule turned off,
// a new, re-enabled or rescheduled rule (whose watermark starts at the
// current slot, so it runs from its next one and nothing is replayed),
// and missed slots older than the catch-up limit, which are skipped.
// first is the first start with no run state at all (an upgrade): each
// enabled rule then runs its current slot at once, and nothing older.
func (s *Scheduler) plan(ctx context.Context, d *Detection, now time.Time, limit time.Duration, epoch int64, first bool) (batch, bool) {
	sched, err := ParseDuration(d.Schedule)
	if err != nil || sched < time.Second {
		return batch{}, false
	}
	S := slotLength(sched)
	s.mu.Lock()
	busy := s.flags[d.ID] != (runFlags{})
	s.mu.Unlock()
	if busy {
		return batch{}, false
	}
	e, ok := s.entry(d.ID)
	if !ok {
		e = detEntry{doc: DetState{DetectionID: d.ID, Created: s.now().UTC()}}
	}
	if !d.Enabled {
		// Recorded once, so turning it back on starts it afresh. A rule
		// that never ran needs nothing: with no run state it starts
		// afresh anyway, and most content pack rules are never turned on.
		if ok && (e.doc.Enabled || !e.doc.GoneSince.IsZero()) {
			e.doc.Enabled, e.doc.Schedule, e.doc.GoneSince = false, d.Schedule, time.Time{}
			s.save(ctx, e, epoch)
		}
		return batch{}, false
	}
	cur := SlotAt(d.ID, S, now)
	recorded, rerr := ParseDuration(e.doc.Schedule)
	if !ok || !e.doc.Enabled || !e.doc.GoneSince.IsZero() || rerr != nil || slotLength(recorded) != S {
		e.doc.Enabled, e.doc.Schedule, e.doc.GoneSince = true, d.Schedule, time.Time{}
		e.doc.LastSlot, e.doc.NextSlot = cur, NextSlot(d.ID, S, cur)
		e.doc.Skipped, e.doc.Attempts = Skipped{}, 0
		if !ok && first {
			// The first start after the upgrade: the current slot runs
			// now, over the lookback up to it, as every start did before.
			e.doc.LastSlot, e.doc.NextSlot = cur.Add(-S), cur
		}
		if !s.save(ctx, e, epoch) || !(!ok && first) {
			return batch{}, false
		}
		return batch{d: d, sched: S, slots: []time.Time{cur}, last: cur.Add(-S), current: true}, true
	}
	last := e.doc.LastSlot
	if !last.Before(cur) {
		return batch{}, false
	}
	floor := cur.Add(-S)
	if limit > 0 {
		floor = now.Add(-limit)
	}
	if !NextSlot(d.ID, S, last).After(floor) {
		to := SlotAt(d.ID, S, floor)
		if !to.Before(cur) {
			to = cur.Add(-S)
		}
		if to.After(last) {
			e.doc.Skipped = Skipped{From: last, To: to, At: s.now().UTC(), Count: slotsBetween(d.ID, S, last, to)}
			e.doc.LastSlot, e.doc.NextSlot, e.doc.Attempts = to, NextSlot(d.ID, S, to), 0
			s.log().Warn(fmt.Sprintf("detections were not running from %s to %s; %d runs of %q skipped",
				last.UTC().Format("2006-01-02 15:04 UTC"), to.UTC().Format("2006-01-02 15:04 UTC"), e.doc.Skipped.Count, d.Title),
				"detection", d.ID, "catch_up", limit)
			if !s.save(ctx, e, epoch) {
				return batch{}, false
			}
			last = to
		}
	}
	slots := Slots(d.ID, S, last, cur, maxSlotsPerTick)
	if len(slots) == 0 {
		return batch{}, false
	}
	return batch{d: d, sched: S, slots: slots, last: last, current: len(slots) == 1 && slots[0].Equal(cur)}, true
}

// save writes a run state change that needs no run, worked out under
// epoch, and reports whether it was written as asked.
func (s *Scheduler) save(ctx context.Context, e detEntry, epoch int64) bool {
	adopted, err := s.writeState(ctx, e, epoch)
	if err != nil {
		s.log().Warn("could not write the detection run state", "detection", e.doc.DetectionID, "err", err)
		return false
	}
	return !adopted
}

// runSlot runs one slot of d and moves the watermark on when the slot is
// done: its writes all succeeded, or the rule cannot run as written, or
// it timed out maxAttempts times. A transient error leaves the watermark,
// so the slot runs again; the error is returned so the batch stops.
func (s *Scheduler) runSlot(ctx context.Context, d *Detection, sched time.Duration, slot time.Time, catchup bool, epoch int64) error {
	e, ok := s.entry(d.ID)
	if !ok {
		return errStaleEpoch
	}
	if !e.doc.LastSlot.Before(slot) {
		return nil
	}
	start, cstart := s.now(), s.clusterNow()
	timeout := s.RunTimeout(d)
	// The scheduler bounds its own searches, so they do not wait behind
	// analysts' searches.
	rctx, cancel := context.WithTimeout(search.Background(ctx), timeout)
	// The findings and risk indices are asked for as long as a finding or
	// risk event written before the upgrade can still hold a group back:
	// fallbackWindow, or the rule's own throttle window when that is
	// longer.
	fallback := !e.doc.Created.IsZero() && start.Sub(e.doc.Created) < max(fallbackWindow, throttleWindow(d))
	res, err := s.run(rctx, d, runSpec{at: slot, slot: slot, raised: start, fallback: fallback})
	timedOut := err != nil && errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	cancel()
	if ctx.Err() != nil || errors.Is(err, ErrNotAllowed) {
		// The lease was lost, or the server is stopping: the next leader
		// runs the slot again.
		if err == nil {
			err = ctx.Err()
		}
		return err
	}
	st := e.doc
	st.LastRun, st.LastDurationMS = start.UTC(), s.now().Sub(start).Milliseconds()
	kind := ErrorKind(err)
	if timedOut {
		kind = ErrorTimeout
		err = fmt.Errorf("timed out after %s, so this run was stopped; narrow the query or shorten its lookback so it finishes in time", timeout)
	}
	advance := false
	switch kind {
	case "":
		advance = true
		st.LastResults, st.LastFindings, st.LastRisk = res.Results, len(res.Findings), res.Risk
		st.LastThrottled, st.LastDuplicates, st.LastSuppressed, st.Capped = res.Throttled, res.Duplicates, res.Suppressed, res.Capped
		st.LastError, st.ErrorKind, st.TimedOut, st.Attempts = "", "", false, 0
	case ErrorQuery:
		advance = true
		st.LastResults, st.LastFindings, st.LastRisk, st.LastThrottled, st.LastDuplicates, st.LastSuppressed, st.Capped = 0, 0, 0, 0, 0, 0, false
		st.LastError, st.ErrorKind, st.TimedOut, st.Attempts = err.Error(), kind, false, 0
	case ErrorTimeout:
		st.Attempts++
		st.LastError, st.ErrorKind, st.TimedOut = err.Error(), kind, true
		if st.Attempts >= maxAttempts {
			advance, st.Attempts = true, 0
		}
	default:
		st.LastError, st.ErrorKind = err.Error(), kind
	}
	if advance {
		st.LastSlot, st.NextSlot = slot, NextSlot(d.ID, sched, slot)
		lag := cstart.Sub(slot)
		st.LagMS = lag.Milliseconds()
		if lag > sched {
			st.LateRuns++
			st.LastLate = start.UTC()
			if !catchup {
				s.log().Warn("detection ran late: every worker was busy", "detection", d.ID, "late", lag.Round(time.Second), "schedule", d.Schedule)
			}
		}
	}
	if _, werr := s.writeState(ctx, detEntry{doc: st, ver: e.ver, read: e.read}, epoch); werr != nil {
		s.log().Warn("could not write the detection run state; the slot runs again", "detection", d.ID, "err", werr)
		return werr
	}
	if err != nil {
		s.log().Warn("detection failed", "detection", d.ID, "slot", slot.Format(time.RFC3339), "kind", kind, "err", err)
		if !advance {
			return err
		}
		return nil
	}
	if len(res.Findings) > 0 || res.Risk > 0 {
		s.log().Info("detection fired", "detection", d.ID, "slot", slot.Format(time.RFC3339), "findings", len(res.Findings),
			"risk_events", res.Risk, "throttled", res.Throttled, "duplicates", res.Duplicates)
	}
	return nil
}

// housekeep marks the run state of rules no longer in the library, and a
// day later removes it with the rule's "Run now" record and throttles.
// A deleted rule that has only a "Run now" record gets a run state marked
// deleted, so the same happens to it.
func (s *Scheduler) housekeep(ctx context.Context, epoch int64) {
	now := s.now()
	s.mu.Lock()
	if !s.houseAt.IsZero() && now.Sub(s.houseAt) < housekeepEvery {
		s.mu.Unlock()
		return
	}
	s.houseAt = now
	ids := make([]string, 0, len(s.det))
	for id := range s.det {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	have := map[string]bool{}
	for _, d := range s.Library.List() {
		have[d.ID] = true
	}
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	// A rule only ever run with "Run now" while turned off has a "Run now"
	// record and throttles but no run state: it gets one, marked deleted,
	// so it is removed with them.
	rs, idx := s.runStore()
	manual, err := rs.SearchDocs(ctx, idx, map[string]any{"term": map[string]any{"kind": kindDetManual}})
	if err != nil {
		s.log().Warn("could not read the Run now records of detections", "err", err)
	}
	for _, doc := range manual {
		var m manualDoc
		if json.Unmarshal(doc.Source, &m) != nil || m.DetectionID == "" || have[m.DetectionID] || known[m.DetectionID] {
			continue
		}
		known[m.DetectionID] = true
		s.save(ctx, detEntry{doc: DetState{DetectionID: m.DetectionID, Created: now.UTC(), GoneSince: now.UTC()}}, epoch)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if have[id] {
			continue
		}
		e, ok := s.entry(id)
		if !ok {
			continue
		}
		if e.doc.GoneSince.IsZero() {
			e.doc.GoneSince = now.UTC()
			s.save(ctx, e, epoch)
			continue
		}
		if now.Sub(e.doc.GoneSince) >= goneFor {
			if err := s.forget(ctx, id, e); err != nil {
				s.log().Warn("could not remove the run state of a deleted detection", "detection", id, "err", err)
			}
		}
	}
}

// forget removes a deleted rule's run state, "Run now" record and
// throttles.
func (s *Scheduler) forget(ctx context.Context, id string, e detEntry) error {
	rs, idx := s.runStore()
	if err := rs.DeleteIf(ctx, idx, detStateID(id), e.ver, false); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.mu.Lock()
	delete(s.det, id)
	if s.cache != nil {
		delete(s.cache.det, id)
		delete(s.cache.manual, id)
	}
	s.mu.Unlock()
	if _, v, found, err := rs.Get(ctx, idx, detManualID(id)); err != nil {
		return err
	} else if found {
		if err := rs.DeleteIf(ctx, idx, detManualID(id), v, false); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	docs, err := rs.SearchDocs(ctx, idx, map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": kindThrottle}},
		map[string]any{"term": map[string]any{"detection_id": id}},
	}}})
	if err != nil {
		return err
	}
	for _, d := range docs {
		if err := rs.DeleteIf(ctx, idx, d.ID, d.Version, false); err != nil && !store.IsConflict(err) && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// RunTimeout is how long one run of d may take.
func (s *Scheduler) RunTimeout(d *Detection) time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	sched, err := ParseDuration(d.Schedule)
	if err != nil {
		return MaxRunTimeout
	}
	return min(max(sched, MinRunTimeout), MaxRunTimeout)
}

// RunAt runs one detection as if the clock were `at`: it searches
// [at-lookback, at] and stamps the findings and risk events it raises
// with that time, without touching the detection's schedule or run state
// or the live scheduler. The sample-data backfill uses it to raise
// findings and risk for events placed in the past, so the queue, the
// Risk page and the dashboards show a realistic timeline straight away.
// It throttles as before throttles were documents.
func (s *Scheduler) RunAt(ctx context.Context, d *Detection, at time.Time) (*RunResult, error) {
	timeout := s.RunTimeout(d)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Background so the backfill's searches do not wait behind analysts'.
	return s.run(search.Background(rctx), d, runSpec{at: at, raised: at, legacy: true})
}

// Window returns the time range the run of a slot ending at end
// searches: the detection's lookback up to end.
func Window(d *Detection, end time.Time) (time.Time, time.Time, error) {
	lb, err := ParseDuration(d.Lookback)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return end.Add(-lb), end, nil
}

// Preview runs a detection's query over its lookback window without
// raising findings, for "Test" in the UI.
func (s *Scheduler) Preview(ctx context.Context, d *Detection) (*search.Result, error) {
	q, _, _, err := s.prepare(d, s.clusterNow())
	if err != nil {
		return nil, err
	}
	return s.Engine.Execute(ctx, q)
}

func (s *Scheduler) prepare(d *Detection, end time.Time) (*query.Query, time.Time, time.Time, error) {
	q, err := query.Parse(d.Query)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	earliest, latest, err := Window(d, end)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	q.Earliest = earliest.UTC().Format(time.RFC3339)
	q.Latest = latest.UTC().Format(time.RFC3339)
	return q, earliest, latest, nil
}

// ScopeSample limits a detection's search by the sample-data marker
// (datamodel.SampleField). The sample backfill (mark set) reads only its
// own load's documents, so it can never stamp real activity as sample
// data. The live scheduler (mark empty) leaves every sample document out:
// the backfill has already run the detections over them, and a live run
// over them would raise findings and risk that carry no marker, which
// would look real and outlive the sample's removal.
func ScopeSample(q *query.Query, mark string) {
	var f query.Expr = &query.Not{Child: &query.Compare{Field: datamodel.SampleField, Op: "=", Value: "*"}}
	if mark != "" {
		f = &query.Compare{Field: datamodel.SampleField, Op: "=", Value: mark}
	}
	if q.Search == nil {
		q.Search = f
		return
	}
	q.Search = &query.And{Children: []query.Expr{q.Search, f}}
}

// lists is the asset and identity context a run uses. Live runs read only
// the user's own lists: the sample data's overlay describes its own made-up
// hosts and users, and must never shape what is stored about real ones.
func (s *Scheduler) lists() *assets.Store {
	if s.Assets == nil || s.SampleMark != "" {
		return s.Assets
	}
	return s.Assets.Own()
}

// runSpec says how one run goes.
type runSpec struct {
	// at is where the search window ends, and the time throttles and
	// risk events carry; slot is the same for a scheduled run, zero for
	// others. raised is the wall-clock time the run started.
	at, slot, raised time.Time
	// legacy throttles by asking the findings and risk indices, with
	// random IDs and no throttle documents (the sample backfill).
	legacy bool
	// manual is "Run now".
	manual bool
	// fallback also asks the findings and risk indices once for a group
	// with no throttle document yet. Only events written before
	// throttles were documents need it: a run writes a risk event only
	// after its group's throttle document, which the next slot reads.
	fallback bool
}

func (s *Scheduler) run(ctx context.Context, d *Detection, spec runSpec) (*RunResult, error) {
	q, earliest, latest, err := s.prepare(d, spec.at)
	if err != nil {
		return nil, &RuleError{Err: err}
	}
	// Scope the search by the sample marker for this run only: findings
	// keep the detection's own query for their drilldown.
	own := q.Search
	ScopeSample(q, s.SampleMark)
	lists := s.lists()
	res, err := s.Engine.Execute(ctx, q)
	q.Search = own
	if err != nil {
		return nil, &searchError{Err: err}
	}
	out := &RunResult{Results: len(res.Rows), Earliest: earliest, Latest: latest, Findings: []*findings.Finding{}}
	s.mu.Lock()
	maxF := s.MaxFindingsPerRun
	s.mu.Unlock()
	if maxF <= 0 {
		maxF = 100
	}
	window := throttleWindow(d)
	slotted := !spec.slot.IsZero()
	seen := map[string]bool{}
	for _, row := range res.Rows {
		if d.Suppressing(row, spec.at) != nil {
			out.Suppressed++
			continue
		}
		key := GroupKey(d, row)
		if s.SampleMark != "" {
			key = sampleGroupKey(key, s.SampleMark)
		}
		if seen[key] {
			out.Throttled++
			continue
		}
		seen[key] = true
		riskOnly := d.Risk != nil && d.Risk.Only
		// Findings an earlier run of the slot raised count too: rows come
		// in the same order every run, so a run of the slot again stops
		// where the first one did.
		if len(out.Findings)+out.Duplicates >= maxF || out.Risk >= maxF*4 {
			out.Capped = true
			break
		}
		if !s.allowed(ctx) {
			return nil, ErrNotAllowed
		}
		fid := ""
		if !riskOnly {
			fid = NewID(spec.raised)
			if slotted {
				fid = SlotFindingID(d.ID, key, spec.slot)
			}
		}
		if window > 0 {
			exists := func() (bool, error) {
				since := spec.at.Add(-window)
				if riskOnly {
					if s.Risk == nil {
						return false, nil
					}
					return s.Risk.Exists(ctx, d.ID, key, since)
				}
				return s.Findings.Exists(ctx, d.ID, key, since)
			}
			var held bool
			if spec.legacy {
				held, err = exists()
			} else {
				var fb func() (bool, error)
				if spec.fallback {
					fb = exists
				}
				var proceed bool
				proceed, err = s.claim(ctx, d, key, spec.slot, spec.at, window, fid, fb)
				held = !proceed
			}
			if err != nil {
				return nil, err
			}
			if held {
				out.Throttled++
				continue
			}
		}
		if !s.allowed(ctx) {
			return nil, ErrNotAllowed
		}
		if d.Risk != nil && s.Risk != nil {
			evs := RiskEvents(d, row, key, lists, spec.at)
			for i := range evs {
				if s.SampleMark != "" {
					evs[i].Sample = s.SampleMark
				}
				if slotted {
					evs[i].ID = RiskEventID(d.ID, key, spec.slot, evs[i].ObjectType, evs[i].Object)
				}
			}
			if err := s.Risk.Write(ctx, evs); err != nil {
				return nil, err
			}
			out.Risk += len(evs)
		}
		if riskOnly {
			continue
		}
		f := NewFinding(d, q, row, key, earliest, latest, spec.slot, spec.raised)
		f.ID = fid
		f.Sample = s.SampleMark
		f.Context = EntityContext(lists, f.Entities)
		f.Urgency = Urgency(f.Severity, f.Context)
		err := s.Findings.Create(ctx, f)
		if slotted && errors.Is(err, findings.ErrExists) {
			// An earlier run of this slot raised it.
			out.Duplicates++
			continue
		}
		// A write whose answer was lost is settled by the store, so a
		// random ID is taken only by another finding: this one gets a
		// new ID.
		for try := 0; !slotted && errors.Is(err, findings.ErrExists) && try < 3; try++ {
			f.ID = NewID(spec.raised)
			err = s.Findings.Create(ctx, f)
		}
		if err != nil {
			return nil, err
		}
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}

// throttleWindow is how long a finding or risk event of d holds its
// group back; zero means no throttle.
func throttleWindow(d *Detection) time.Duration {
	if d.Throttle.Window == "" {
		return 0
	}
	w, _ := ParseDuration(d.Throttle.Window)
	return w
}

// SlotFindingID is the ID of the finding a slot raises for a group key:
// the slot's end in UTC, then a hash of the rule, the key and the slot.
// It sorts by time like NewID, and every server, and every run of the
// slot, works out the same one.
func SlotFindingID(ruleID, groupKey string, slot time.Time) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d", ruleID, groupKey, slot.Unix()))
	return slot.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(h[:])[:8]
}

// RiskEventID is the ID of the risk event a slot writes about one object.
func RiskEventID(ruleID, groupKey string, slot time.Time, objType, object string) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d\x00%s\x00%s", ruleID, groupKey, slot.Unix(), objType, strings.ToLower(object)))
	return hex.EncodeToString(h[:])[:24]
}

// GroupKey is the throttle key for a result row.
func GroupKey(d *Detection, row map[string]any) string {
	h := sha256.New()
	h.Write([]byte(d.ID))
	if len(d.Throttle.Fields) > 0 {
		for _, f := range d.Throttle.Fields {
			fmt.Fprintf(h, "\x00%s=%v", f, row[f])
		}
	} else {
		// Whole row, minus the time so the same activity seen by two
		// overlapping runs is one finding.
		b, _ := json.Marshal(withoutTime(row))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// sampleGroupKey gives the sample backfill throttle keys of its own, so
// a sample finding or risk event about a host or user that shares a name
// with a real one never holds back the real one (or the other way round).
func sampleGroupKey(key, mark string) string {
	h := sha256.Sum256([]byte(key + "\x00" + mark))
	return hex.EncodeToString(h[:])[:32]
}

func withoutTime(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		if k != "_time" {
			out[k] = v
		}
	}
	return out
}

// EntityFields are the result columns copied into a finding's entities.
var EntityFields = []string{"user", "src_user", "src", "src_host", "dest", "dest_host", "host", "process_name", "object", "member", "risk_object", "risk_object_type"}

func entities(row map[string]any) map[string]any {
	ents := map[string]any{}
	for _, f := range EntityFields {
		if v, ok := row[f]; ok && v != nil && fmt.Sprint(v) != "" {
			ents[f] = v
		}
	}
	return ents
}

// NewFinding builds the finding for one result row. A scheduled run
// passes its slot: the finding then gets the slot's ID (SlotFindingID)
// and is created at the slot's end, and raisedAt records when it was
// actually raised. Other runs pass a zero slot: the finding gets a random
// ID and is created at raisedAt.
func NewFinding(d *Detection, q *query.Query, row map[string]any, key string, earliest, latest, slot, raisedAt time.Time) *findings.Finding {
	result := make(map[string]any, len(row))
	for k, v := range row {
		if s, ok := v.(string); ok && len(s) > 8192 {
			v = s[:8192] + "…"
		}
		result[k] = v
	}
	ents := entities(row)
	id, created := NewID(raisedAt), raisedAt.UTC()
	var at *time.Time
	var raised time.Time
	if !slot.IsZero() {
		id, created, raised = SlotFindingID(d.ID, key, slot), slot.UTC(), raisedAt.UTC()
		at = &created
	}
	return &findings.Finding{
		ID:          id,
		DetectionID: d.ID,
		Title:       RenderTitle(d.Title, row),
		Description: d.Description,
		Credit:      d.Origin.Credit(),
		Severity:    d.Severity,
		Urgency:     d.Severity,
		Status:      findings.StatusNew,
		MITRE:       append([]string(nil), d.MITRE...),
		Entities:    ents,
		Result:      result,
		Query:       Drilldown(q, row).String(),
		Earliest:    earliest.UTC().Format(time.RFC3339),
		Latest:      latest.UTC().Format(time.RFC3339),
		GroupKey:    key,
		Slot:        at,
		RaisedAt:    raised,
		Created:     created,
		Updated:     created,
	}
}

// NewID returns a sortable, unique finding ID.
func NewID(now time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func withTerm(q *query.Query, t query.Expr) *query.Query {
	if q.Search == nil {
		q.Search = t
	} else {
		q.Search = &query.And{Children: []query.Expr{q.Search, t}}
	}
	return q
}

// Drilldown returns the search that shows the events behind a result row:
// the detection's filter plus the row's group-by values, without the
// transforming commands. Event queries drill down to themselves.
func Drilldown(q *query.Query, row map[string]any) *query.Query {
	var by []string
	if len(q.Commands) > 0 {
		switch c := q.Commands[0].(type) {
		case *query.Stats:
			by = c.By
		case *query.Top:
			by = append(append(by, c.Fields...), c.By...)
		case *query.ThreatMatch:
			// The events behind a threat match are those with the matched value.
			out := &query.Query{Search: q.Search, Datamodel: q.Datamodel, Index: q.Index}
			f, _ := row["threat_match_field"].(string)
			if v, ok := row["threat_match_value"]; ok && v != nil && f != "" {
				return withTerm(out, &query.Compare{Field: f, Op: "=", Value: fmt.Sprint(v)})
			}
			return out
		default:
			return &query.Query{Search: q.Search, Datamodel: q.Datamodel, Index: q.Index}
		}
	}
	out := &query.Query{Datamodel: q.Datamodel, Index: q.Index}
	var parts []query.Expr
	if q.Search != nil {
		parts = append(parts, q.Search)
	}
	for _, f := range by {
		if v, ok := row[f]; ok && v != nil {
			parts = append(parts, &query.Compare{Field: f, Op: "=", Value: fmt.Sprint(v)})
		}
	}
	switch len(parts) {
	case 0:
	case 1:
		out.Search = parts[0]
	default:
		out.Search = &query.And{Children: parts}
	}
	return out
}
