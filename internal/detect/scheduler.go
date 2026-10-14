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
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Runner executes parsed queries; *search.Engine implements it.
type Runner interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// Scheduler runs enabled detections on their schedules.
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
	Now  func() time.Time
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

	mu    sync.Mutex
	state map[string]*RunState
	slots chan struct{}
}

// Bounds of the default run timeout.
const (
	MinRunTimeout = time.Minute
	MaxRunTimeout = 5 * time.Minute
)

// Bounds of how far back a run that is behind searches (see CatchUp).
const (
	MinCatchUp = time.Hour
	MaxCatchUp = 24 * time.Hour
)

// CatchUp is how far back a run may search when the detection's last
// successful run ended longer than its lookback ago: ten lookbacks, at
// least MinCatchUp and at most MaxCatchUp, and never less than the
// lookback itself. A run over a much wider window than usual could time
// out in turn, and then keep timing out as the gap grew; past the limit
// the gap is counted in RunState.Unsearched and logged instead.
func CatchUp(lookback time.Duration) time.Duration {
	return max(lookback, min(max(10*lookback, MinCatchUp), MaxCatchUp))
}

// Behind reports whether d, with run state st, is falling behind its
// schedule at now: it has been due for longer than its schedule
// interval, or a run in the last hour started that late. Only the server
// that runs the schedule can tell.
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

// RunState is what the UI shows about a detection's last run.
type RunState struct {
	LastRun      time.Time `json:"last_run,omitzero"`
	NextRun      time.Time `json:"next_run,omitzero"`
	LastDuration int64     `json:"last_duration_ms"`
	LastResults  int       `json:"last_results"`
	LastFindings int       `json:"last_findings"`
	LastError    string    `json:"last_error,omitempty"`
	// TimedOut says the last run was stopped for taking longer than its
	// timeout; LastError says how long that was.
	TimedOut bool `json:"timed_out,omitempty"`
	Running  bool `json:"running,omitempty"`
	// SearchedTo is the end of the window the last successful run
	// searched. The next run searches on from there (see Window), so a run
	// that starts late, or after failed runs, does not skip the events in
	// between. It is kept in memory: after a restart, on a server that
	// takes over the schedule, or once the detection is turned back on,
	// the first run searches its lookback as before.
	SearchedTo time.Time `json:"searched_to,omitzero"`
	// Lag is how long after it was due the last scheduled run started:
	// with every worker busy, a due detection waits. LateRuns counts the
	// scheduled runs since the server started that began more than one
	// schedule interval late, LastLate is when the latest one did, and
	// Timeouts counts the runs stopped at their timeout.
	Lag      int64     `json:"lag_ms,omitempty"`
	LateRuns int       `json:"late_runs,omitempty"`
	LastLate time.Time `json:"last_late,omitzero"`
	Timeouts int       `json:"timeouts,omitempty"`
	// Unsearched is how much time, since the server started, no run
	// searched because the detection fell further behind than its
	// catch-up limit (see CatchUp).
	Unsearched int64 `json:"unsearched_ms,omitempty"`
	// LastSuppressed is how many results of the last run an exception
	// matched.
	LastSuppressed int `json:"last_suppressed,omitempty"`

	queued bool // waiting for a worker
}

// RunResult reports one run.
type RunResult struct {
	Results   int                 `json:"results"`
	Findings  []*findings.Finding `json:"findings"`
	Risk      int                 `json:"risk_events"`
	Throttled int                 `json:"throttled"`
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

// Status returns the run state of every detection that has run.
func (s *Scheduler) Status() map[string]RunState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]RunState, len(s.state))
	for id, st := range s.state {
		out[id] = *st
	}
	return out
}

func (s *Scheduler) stateFor(id string) *RunState {
	if s.state == nil {
		s.state = map[string]*RunState{}
	}
	st, ok := s.state[id]
	if !ok {
		st = &RunState{}
		s.state[id] = st
	}
	return st
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

// RunDue runs every enabled detection whose next run time has passed, at
// most Workers at a time, and waits for them.
func (s *Scheduler) RunDue(ctx context.Context) {
	var wg sync.WaitGroup
	s.dispatch(ctx, &wg)
	wg.Wait()
}

// dispatch starts every due detection that is not already running or
// waiting; each waits for a free worker.
func (s *Scheduler) dispatch(ctx context.Context, wg *sync.WaitGroup) {
	ctx = context.WithValue(ctx, scheduledKey{}, true)
	if !s.allowed(ctx) {
		// Another server runs the schedule now: should this one take it
		// back, its runs start from their lookback, not from where they
		// stopped here, so they do not search again what the other did.
		s.mu.Lock()
		for _, st := range s.state {
			st.SearchedTo = time.Time{}
		}
		s.mu.Unlock()
		return
	}
	now := s.now()
	var due []*Detection
	s.mu.Lock()
	if s.slots == nil {
		n := s.Workers
		if n <= 0 {
			n = 4
		}
		s.slots = make(chan struct{}, n)
	}
	slots := s.slots
	for _, d := range s.Library.List() {
		if !d.Enabled {
			// Turned back on, it starts from its lookback, rather than
			// catching up on the time it was off.
			if st := s.state[d.ID]; st != nil {
				st.SearchedTo = time.Time{}
			}
			continue
		}
		st := s.stateFor(d.ID)
		if st.Running || st.queued || (!st.NextRun.IsZero() && now.Before(st.NextRun)) {
			continue
		}
		st.queued = true
		due = append(due, d)
	}
	// The longest overdue first (those that never ran have no next run).
	next := make(map[string]time.Time, len(due))
	for _, d := range due {
		next[d.ID] = s.state[d.ID].NextRun
	}
	s.mu.Unlock()
	sort.Slice(due, func(i, j int) bool {
		a, b := next[due[i].ID], next[due[j].ID]
		if !a.Equal(b) {
			return a.Before(b)
		}
		return due[i].ID < due[j].ID
	})
	for _, d := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				s.mu.Lock()
				s.stateFor(d.ID).queued = false
				s.mu.Unlock()
			}()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			if ctx.Err() != nil || !s.allowed(ctx) {
				return
			}
			// The scheduler bounds its own searches, so they do not wait
			// behind analysts' searches.
			if _, err := s.Run(search.Background(ctx), d); err != nil {
				s.log().Warn("detection failed", "detection", d.ID, "err", err)
			}
		}()
	}
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

// Run executes one detection now and raises findings. It searches from
// where its last successful run stopped, or its lookback if that is
// later (see Window). It also records the run state, how late a
// scheduled run started, and schedules the next run. A run that takes
// longer than RunTimeout is stopped and reported as timed out.
func (s *Scheduler) Run(ctx context.Context, d *Detection) (*RunResult, error) {
	start := s.now()
	sched, schedErr := ParseDuration(d.Schedule)
	s.mu.Lock()
	st := s.stateFor(d.ID)
	st.Running = true
	since := st.SearchedTo
	// Lateness counts for scheduled runs only: "Run now" is not due.
	if ctx.Value(scheduledKey{}) != nil {
		st.Lag = 0
		if !st.NextRun.IsZero() && start.After(st.NextRun) {
			late := start.Sub(st.NextRun)
			st.Lag = late.Milliseconds()
			if schedErr == nil && late > sched {
				st.LateRuns++
				st.LastLate = start
				s.log().Warn("detection ran late: every worker was busy", "detection", d.ID, "late", late.Round(time.Second), "schedule", d.Schedule)
			}
		}
	}
	s.mu.Unlock()

	timeout := s.RunTimeout(d)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	res, err := s.run(rctx, d, start, since)
	// Failed after its own deadline passed (not the caller's): however the
	// error reads, the run ran out of time.
	timedOut := err != nil && errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	cancel()
	if timedOut {
		err = fmt.Errorf("timed out after %s, so this run was stopped; narrow the query or shorten its lookback so it finishes in time", timeout)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st.Running = false
	st.LastRun = start
	st.LastDuration = s.now().Sub(start).Milliseconds()
	st.TimedOut = timedOut
	if timedOut {
		st.Timeouts++
	}
	if schedErr == nil {
		st.NextRun = start.Add(sched)
	}
	if err != nil {
		st.LastError = err.Error()
		return nil, err
	}
	// The window starts after the checkpoint only when it was further back
	// than the catch-up limit.
	if !since.IsZero() && res.Earliest.After(since) {
		gap := res.Earliest.Sub(since)
		st.Unsearched += gap.Milliseconds()
		s.log().Warn("detection fell too far behind: events in a gap were not searched", "detection", d.ID,
			"from", since.UTC().Format(time.RFC3339), "to", res.Earliest.UTC().Format(time.RFC3339), "gap", gap.Round(time.Second))
	}
	if res.Latest.After(st.SearchedTo) {
		st.SearchedTo = res.Latest
	}
	st.LastError = ""
	st.LastResults = res.Results
	st.LastFindings = len(res.Findings)
	st.LastSuppressed = res.Suppressed
	if len(res.Findings) > 0 || res.Risk > 0 {
		s.log().Info("detection fired", "detection", d.ID, "findings", len(res.Findings), "risk_events", res.Risk, "throttled", res.Throttled)
	}
	return res, nil
}

// RunAt runs one detection as if the clock were `at`: it searches
// [at-lookback, at] and stamps the findings and risk events it raises
// with that time, without touching the detection's schedule or run state
// or the live scheduler. The sample-data backfill uses it to raise
// findings and risk for events placed in the past, so the queue, the
// Risk page and the dashboards show a realistic timeline straight away.
func (s *Scheduler) RunAt(ctx context.Context, d *Detection, at time.Time) (*RunResult, error) {
	timeout := s.RunTimeout(d)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Background so the backfill's searches do not wait behind analysts'.
	return s.run(search.Background(rctx), d, at, time.Time{})
}

// Window returns the time range a run at now searches: its lookback, or,
// when since (the end of the last successful run's window) is further
// back, from since, but no further back than CatchUp. A zero since
// means no earlier run.
func Window(d *Detection, now, since time.Time) (time.Time, time.Time, error) {
	lb, err := ParseDuration(d.Lookback)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	earliest := now.Add(-lb)
	if !since.IsZero() && since.Before(earliest) {
		earliest = later(since, now.Add(-CatchUp(lb)))
	}
	return earliest, now, nil
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Preview runs a detection's query over its lookback window without
// raising findings, for "Test" in the UI.
func (s *Scheduler) Preview(ctx context.Context, d *Detection) (*search.Result, error) {
	q, _, _, err := s.prepare(d, s.now(), time.Time{})
	if err != nil {
		return nil, err
	}
	return s.Engine.Execute(ctx, q)
}

func (s *Scheduler) prepare(d *Detection, now, since time.Time) (*query.Query, time.Time, time.Time, error) {
	q, err := query.Parse(d.Query)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	earliest, latest, err := Window(d, now, since)
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

func (s *Scheduler) run(ctx context.Context, d *Detection, now, since time.Time) (*RunResult, error) {
	q, earliest, latest, err := s.prepare(d, now, since)
	if err != nil {
		return nil, err
	}
	// Scope the search by the sample marker for this run only: findings
	// keep the detection's own query for their drilldown.
	own := q.Search
	ScopeSample(q, s.SampleMark)
	lists := s.lists()
	res, err := s.Engine.Execute(ctx, q)
	q.Search = own
	if err != nil {
		return nil, err
	}
	out := &RunResult{Results: len(res.Rows), Earliest: earliest, Latest: latest, Findings: []*findings.Finding{}}
	s.mu.Lock()
	maxF := s.MaxFindingsPerRun
	s.mu.Unlock()
	if maxF <= 0 {
		maxF = 100
	}
	window := time.Duration(0)
	if d.Throttle.Window != "" {
		window, _ = ParseDuration(d.Throttle.Window)
	}
	seen := map[string]bool{}
	for _, row := range res.Rows {
		if d.Suppressing(row, now) != nil {
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
		if window > 0 {
			var dup bool
			var err error
			if riskOnly {
				if s.Risk != nil {
					dup, err = s.Risk.Exists(ctx, d.ID, key, now.Add(-window))
				}
			} else {
				dup, err = s.Findings.Exists(ctx, d.ID, key, now.Add(-window))
			}
			if err != nil {
				return nil, err
			}
			if dup {
				out.Throttled++
				continue
			}
		}
		if len(out.Findings) >= maxF || out.Risk >= maxF*4 {
			out.Capped = true
			break
		}
		if !s.allowed(ctx) {
			return nil, ErrNotAllowed
		}
		if d.Risk != nil && s.Risk != nil {
			evs := RiskEvents(d, row, key, lists, now)
			if s.SampleMark != "" {
				for i := range evs {
					evs[i].Sample = s.SampleMark
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
		f := NewFinding(d, q, row, key, earliest, latest, now)
		f.Sample = s.SampleMark
		f.Context = EntityContext(lists, f.Entities)
		f.Urgency = Urgency(f.Severity, f.Context)
		// A write whose answer was lost is settled by the store, so the
		// ID is taken only by another finding: this one gets a new ID.
		err := s.Findings.Create(ctx, f)
		for try := 0; errors.Is(err, findings.ErrExists) && try < 3; try++ {
			f.ID = NewID(now)
			err = s.Findings.Create(ctx, f)
		}
		if err != nil {
			return nil, err
		}
		out.Findings = append(out.Findings, f)
	}
	return out, nil
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

// NewFinding builds the finding for one result row.
func NewFinding(d *Detection, q *query.Query, row map[string]any, key string, earliest, latest, now time.Time) *findings.Finding {
	result := make(map[string]any, len(row))
	for k, v := range row {
		if s, ok := v.(string); ok && len(s) > 8192 {
			v = s[:8192] + "…"
		}
		result[k] = v
	}
	ents := entities(row)
	return &findings.Finding{
		ID:          NewID(now),
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
		Created:     now.UTC(),
		Updated:     now.UTC(),
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
