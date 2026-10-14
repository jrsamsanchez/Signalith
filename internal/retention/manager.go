package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for the schedule.
const (
	DefaultInterval = time.Hour
	// DefaultRestoreDays is how long a restored day stays searchable when
	// the restore does not say.
	DefaultRestoreDays = 14
	MaxRestoreDays     = 365

	firstRunDelay = 2 * time.Minute
	diskCheck     = 5 * time.Minute
	importBatch   = 500
	importBytes   = 8 << 20
)

// Errors for jobs that cannot start.
var (
	ErrBusy      = errors.New("a retention run is already in progress; try again when it finishes")
	ErrRestoring = errors.New("archived days are being restored; try again when that finishes")
	// ErrReadOnly is returned on servers that do not run retention.
	ErrReadOnly = errors.New("this server doesn't run retention, because detections.scheduler is off here: the server that runs the background jobs does, with its own settings; make changes there")
	// ErrOpenSearch wraps failures to read OpenSearch, so callers can tell
	// them from bad settings.
	ErrOpenSearch = errors.New("OpenSearch could not be read")
)

// ReadOnlyError is returned on a server that may run retention but does
// not now, because another server that shares its OpenSearch runs the
// background jobs. It is an ErrReadOnly.
type ReadOnlyError struct {
	// Holder is the server that runs them, or "" when none does yet.
	Holder string
}

func (e *ReadOnlyError) Error() string {
	if e.Holder == "" {
		return "this server doesn't run retention right now, and no server runs the background jobs at the moment; the Servers page says why"
	}
	return "this server doesn't run retention right now: " + e.Holder + " runs it, with its own settings; make changes there"
}

func (e *ReadOnlyError) Is(target error) bool { return target == ErrReadOnly }

// maxGuardPasses is how many times one run lets the disk guard choose
// again after days it chose could not be deleted, for example because
// their archive failed.
const maxGuardPasses = 3

// Manager plans and enforces retention, and serves the Data retention
// page: overview, previews, settings changes and restores.
type Manager struct {
	Cluster Cluster
	Prefix  string
	// Config is what signalith.yaml says; Store holds what the page saved
	// (or, when servers share their settings, the shared policies, with
	// Config left empty).
	Config  Config
	Store   PolicyStore
	Archive *Archive
	// HistoryFile keeps the last run and recent actions, unless History
	// is set: then History keeps them (the audit records of servers that
	// share one OpenSearch).
	HistoryFile string
	History     HistorySink
	// Interval is how often Start enforces policies; default 1h.
	Interval time.Duration
	Log      *slog.Logger
	// Now returns the current time; tests set it.
	Now func() time.Time
	// ReadOnly is set on servers that do not run the detection scheduler.
	// Retention runs on the server that does, with the settings saved
	// there, so these only show retention: settings changes, runs and
	// restores are refused.
	ReadOnly bool
	// Leader, when set, says whether this server runs retention now: of
	// the servers that share one OpenSearch, only the one that holds the
	// background jobs does. When it does not, the others behave as with
	// ReadOnly, and holder names the server that does.
	Leader func() (runs bool, holder string)
	// Fence, when set, is asked before every step that changes data in
	// OpenSearch; the step runs only when it returns nil. It confirms that
	// this server still holds the background jobs.
	Fence func(ctx context.Context) error
	// Claim, when set, is asked after Fence before each step that changes
	// an index (step names it: compact, archive, delete, thaw, restore,
	// delete_records). It records the step with this server's lease
	// epoch, and refuses it when a server with a later epoch claimed the
	// index, so a server that lost the background jobs without knowing
	// stops before it changes anything.
	Claim func(ctx context.Context, index, step string) error
	// CanArchive, when set, says whether this server can write archives
	// now, and why not: runs hold back the steps that archive until it
	// can, rather than delete days unarchived.
	CanArchive func() (bool, string)
	// Jobs, when set, shares the progress of restores with the servers
	// that do not run them.
	Jobs JobStore
	// ArchiveOn, when set, names the servers that can archive (servers
	// that share one OpenSearch say so in their heartbeats).
	ArchiveOn func() []string
	// Shared is set when the policies are the servers' shared ones: then
	// any server may change them (ReadOnly and Leader only keep it from
	// running retention and restoring).
	Shared bool
	// Hold, when set, says whether the policies wait to be confirmed, and
	// why: until they are, runs only take the disk guard's steps, and
	// freeze, archive and delete nothing else. ConfirmHold confirms them.
	Hold        func() (held bool, why string)
	ConfirmHold func(ctx context.Context, by string) error
	// OnSettings, when set, is called with the settings in effect after
	// this server changed them.
	OnSettings func(Settings)

	initOnce sync.Once
	hist     HistorySink
	// job is held by a run or a restore, so they never overlap. It is
	// released through release, which hands it to a queued run.
	job sync.Mutex

	mu        sync.Mutex
	automatic bool
	current   string // "run" or "restore" while a job holds job
	nextRun   time.Time
	baseCtx   context.Context
	restores  []*RestoreStatus
	// queued is a run asked for while another job held job; it starts as
	// soon as that job ends.
	queued *queuedRun
	// guardPaused is when the disk guard last could not get the disk under
	// its limit; it then waits for the next scheduled run instead of
	// starting runs every few minutes.
	guardPaused    time.Time
	guardPausedWhy string
	// liveInterval replaces Interval once SetInterval changed it (in
	// nanoseconds; 0 is none), and reschedule tells Start.
	liveInterval atomic.Int64
	reschedule   chan struct{}
}

type queuedRun struct{ trigger, by string }

// maxRestores is how many restores the archive view remembers.
const maxRestores = 50

// PolicyStore keeps the policies changed on the page: *Store in a file,
// or the shared policies of servers that share one OpenSearch.
type PolicyStore interface {
	// Get returns the saved settings, and an error when they cannot be
	// used (runs then do nothing until it is fixed).
	Get() (Saved, error)
	// Update changes them with change, checking the result.
	Update(change func(*Saved)) error
}

// VersionedStore is a PolicyStore whose changes can be made only if
// nobody changed the policies since a page read them.
type VersionedStore interface {
	PolicyStore
	// ETag is the version of the policies now, "" when unknown.
	ETag() string
	// UpdateIf is Update, refused when the version is no longer etag.
	UpdateIf(etag string, change func(*Saved)) error
}

// ErrNoHold is a confirmation when nothing waits for one.
var ErrNoHold = errors.New("the retention policies do not wait to be confirmed")

// held reports whether the policies wait to be confirmed, and why.
func (m *Manager) held() (bool, string) {
	if m.Hold == nil {
		return false, ""
	}
	return m.Hold()
}

// ETag is the version of the saved policies, for a page that changes
// them only if nobody else did meanwhile; "" when the store has none.
func (m *Manager) ETag() string {
	if v, ok := m.Store.(VersionedStore); ok {
		return v.ETag()
	}
	return ""
}

// Confirm confirms policies that wait to be confirmed, so runs enforce
// them in full again.
func (m *Manager) Confirm(ctx context.Context, by string) error {
	if held, _ := m.held(); !held || m.ConfirmHold == nil {
		return ErrNoHold
	}
	return m.ConfirmHold(ctx, by)
}

// readOnly returns why this server cannot change retention now, or nil.
func (m *Manager) readOnly() error {
	if m.ReadOnly {
		return ErrReadOnly
	}
	if m.Leader != nil {
		if runs, holder := m.Leader(); !runs {
			return &ReadOnlyError{Holder: holder}
		}
	}
	return nil
}

// fence checks, before a step that changes data, that this server may
// still take it.
func (m *Manager) fence(ctx context.Context) error {
	if m.Fence == nil {
		return nil
	}
	if err := m.Fence(ctx); err != nil {
		return fmt.Errorf("refused: this server no longer runs retention (%w)", err)
	}
	return nil
}

// step checks, before a step that changes index, that this server may
// still take it, and claims the index for it.
func (m *Manager) step(ctx context.Context, index, step string) error {
	if err := m.fence(ctx); err != nil {
		return err
	}
	if m.Claim == nil {
		return nil
	}
	if err := m.Claim(ctx, index, step); err != nil {
		return fmt.Errorf("refused: another server runs retention now (%w)", err)
	}
	return nil
}

// JobStore shares the restores' progress between servers.
type JobStore interface {
	// Save records the restores this server runs, newest last.
	Save(ctx context.Context, restores []RestoreStatus) error
	// Load returns the restores the server that runs them recorded.
	Load(ctx context.Context) ([]RestoreStatus, error)
}

func (m *Manager) init() {
	m.initOnce.Do(func() {
		if m.History != nil {
			m.hist = m.History
		} else {
			m.hist = loadHistory(m.HistoryFile)
		}
		if m.Log == nil {
			m.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		if m.Archive == nil {
			m.Archive = &Archive{}
		}
		m.reschedule = make(chan struct{}, 1)
	})
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) interval() time.Duration {
	if d := time.Duration(m.liveInterval.Load()); d > 0 {
		return d
	}
	if m.Interval > 0 {
		return m.Interval
	}
	return DefaultInterval
}

func (m *Manager) ctx() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.baseCtx != nil {
		return m.baseCtx
	}
	return context.Background()
}

func (m *Manager) setCurrent(what string) {
	m.mu.Lock()
	m.current = what
	m.mu.Unlock()
}

// release ends a job. A queued run takes the job over at once, so nothing
// else can slip in between.
func (m *Manager) release() {
	m.mu.Lock()
	q := m.queued
	m.queued = nil
	if q == nil {
		m.job.Unlock()
		m.mu.Unlock()
		return
	}
	// It shows as running from now, not only once its goroutine starts.
	m.current = "run"
	m.mu.Unlock()
	go func() {
		defer m.release()
		_, _ = m.run(m.ctx(), q.trigger, q.by)
	}()
}

// Job returns the job in progress: "run", "restore", or "" when none.
func (m *Manager) Job() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != "" {
		return m.current
	}
	for _, r := range m.restores {
		if r.State == RestoreQueued || r.State == RestoreRunning {
			return "restore"
		}
	}
	if m.queued != nil {
		return "run"
	}
	return ""
}

// Wait waits for a run or restore in progress to end, once the context
// given to Start has ended, and drops a queued run. The server calls it
// before it restarts, so two managers never work on the cluster at once.
func (m *Manager) Wait() {
	m.init()
	m.mu.Lock()
	m.queued = nil
	m.mu.Unlock()
	m.job.Lock()
	m.job.Unlock()
}

func (m *Manager) busy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == "restore" {
		return ErrRestoring
	}
	return ErrBusy
}

// Settings returns the settings in effect. When the page's settings file
// has errors it is returned too, and runs do nothing until it is fixed.
func (m *Manager) Settings() (Settings, error) {
	var saved Saved
	var err error
	if m.Store != nil {
		saved, err = m.Store.Get()
	}
	return Effective(m.Config, saved), err
}

// Fingerprint returns hashes of the retention settings in effect on this
// server and, while any policy archives, of its archive folder's name
// (Archive.StoreID; else ""). Servers that share one OpenSearch compare
// them, so one whose settings differ from those of the server that runs
// retention, or that keeps archives in another folder, does not take
// retention over by itself.
func (m *Manager) Fingerprint() (settings, archives string) {
	hash := func(v any) string {
		b, _ := json.Marshal(v)
		sum := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	s, err := m.Settings()
	if err != nil {
		return hash(map[string]string{"error": err.Error()}), ""
	}
	settings = hash(map[string]any{"default": s.Default, "policies": s.Policies, "guard": s.Guard})
	archiving := s.Default.Archive
	for _, p := range s.Policies {
		archiving = archiving || p.Archive
	}
	if !archiving || m.Archive == nil {
		return settings, ""
	}
	id, err := m.Archive.StoreID()
	if err != nil {
		return settings, hash(map[string]string{"error": err.Error()})
	}
	return settings, hash(map[string]string{"store_id": id})
}

// state is a snapshot plus what the overview needs besides the plan.
type state struct {
	snap     Snapshot
	records  map[string]IndexInfo
	diskErr  string
	archives []Manifest
	archErr  string
	archProb []string
}

func (m *Manager) snapshot(ctx context.Context) (*state, error) {
	m.init()
	st := &state{snap: Snapshot{Now: m.now(), Prefix: m.Prefix}, records: map[string]IndexInfo{}}
	all, err := m.Cluster.Indices(ctx, m.Prefix+"-*,"+m.Prefix+"_*")
	if err != nil {
		return nil, fmt.Errorf("%w: could not list indices: %w", ErrOpenSearch, err)
	}
	for _, ix := range all {
		if cat, _, ok := ParseIndex(m.Prefix, ix.Name); strings.HasPrefix(ix.Name, m.Prefix+"-") || ok && isMonthly(cat) {
			st.snap.Indices = append(st.snap.Indices, ix)
		} else {
			st.records[ix.Name] = ix
		}
	}
	if d, err := m.Cluster.Disk(ctx); err != nil {
		st.diskErr = err.Error()
	} else if nb, err := m.Cluster.NodeBytes(ctx, m.Prefix+"-*", d.Node); err != nil {
		// Without it the guard cannot tell what a deletion frees on the
		// full disk, so it waits rather than guess.
		st.diskErr = "could not read where shards are: " + err.Error()
	} else {
		st.snap.Disk, st.snap.NodeBytes = d, nb
	}
	list, problems, err := m.Archive.List()
	if err != nil {
		st.archErr = err.Error()
	}
	st.archives, st.archProb = list, problems
	st.snap.Archives = archivesByIndex(list)
	return st, nil
}

// planRecords counts the findings and cases the policies would delete.
// Findings in an investigation are kept as long as the investigation is:
// a case holds only the IDs of its findings.
func (m *Manager) planRecords(ctx context.Context, s Settings, now time.Time) ([]RecordStep, error) {
	out := []RecordStep{}
	for _, id := range []string{Findings, Cases} {
		pol, src := s.For(id)
		if pol.KeepDays <= 0 {
			continue
		}
		step := RecordStep{
			Category: id, Index: RecordIndex(m.Prefix, id), KeepDays: pol.KeepDays, Source: src,
			Before: now.Add(-time.Duration(pol.KeepDays) * 24 * time.Hour),
			Reason: fmt.Sprintf("Resolved or closed, and unchanged for more than %s", days(pol.KeepDays)),
		}
		if id == Findings {
			ids, err := m.Cluster.CaseIDs(ctx, RecordIndex(m.Prefix, Cases))
			if err != nil {
				return out, fmt.Errorf("could not list investigations, so no findings are deleted: %w", err)
			}
			step.keepCases = ids
			step.Reason = fmt.Sprintf("Resolved or closed, unchanged for more than %s, and in no investigation", days(pol.KeepDays))
		}
		n, err := m.Cluster.CountClosed(ctx, step.Index, step.Before, step.keepCases)
		if err != nil {
			return out, fmt.Errorf("could not count closed %s: %w", id, err)
		}
		if n > 0 {
			step.Count = n
			out = append(out, step)
		}
	}
	return out, nil
}

// plan plans indices and records. An error means findings or cases could
// not be checked; the plan still covers everything else.
func (m *Manager) plan(ctx context.Context, s Settings, st *state) (*Plan, error) {
	p := PlanIndices(st.snap, s)
	recs, err := m.planRecords(ctx, s, st.snap.Now)
	p.Records = recs
	return p, err
}

// Run plans and enforces retention once. It returns ErrBusy or
// ErrRestoring when another job is going.
func (m *Manager) Run(ctx context.Context, trigger, by string) (*Run, error) {
	m.init()
	if !m.job.TryLock() {
		return nil, m.busy()
	}
	defer m.release()
	return m.run(ctx, trigger, by)
}

// RunAsync starts a run in the background, for "Run now".
func (m *Manager) RunAsync(trigger, by string) error {
	m.init()
	if err := m.readOnly(); err != nil {
		return err
	}
	if !m.job.TryLock() {
		return m.busy()
	}
	// Running from now: a page asked at once, or a caller waiting for the
	// run to end, must not see it as not started yet.
	m.setCurrent("run")
	go func() {
		defer m.release()
		_, _ = m.run(m.ctx(), trigger, by)
	}()
	return nil
}

// Apply results.
const (
	ApplyStarted = "started"
	// ApplyQueued: a run or restore is going; a new run starts when it ends.
	ApplyQueued = "queued"
)

// ApplySoon starts a run after a settings change, so the change applies
// now. When a run or restore is going, it queues a run that starts as soon
// as that ends; a run in progress also re-reads the settings before each
// step, so it never deletes what the new settings keep.
func (m *Manager) ApplySoon(trigger, by string) (string, error) {
	m.init()
	if err := m.readOnly(); err != nil {
		return "", err
	}
	m.mu.Lock()
	if m.job.TryLock() {
		m.current = "run" // running from now; see RunAsync
		m.mu.Unlock()
		go func() {
			defer m.release()
			_, _ = m.run(m.ctx(), trigger, by)
		}()
		return ApplyStarted, nil
	}
	m.queued = &queuedRun{trigger: trigger, by: by}
	m.mu.Unlock()
	return ApplyQueued, nil
}

// run does one run; the caller holds m.job.
func (m *Manager) run(ctx context.Context, trigger, by string) (*Run, error) {
	m.setCurrent("run")
	defer m.setCurrent("")
	run := &Run{Started: m.now(), Trigger: trigger, By: by, Errors: []string{}}
	finish := func(err error) (*Run, error) {
		if err != nil {
			run.Errors = append(run.Errors, err.Error())
			m.Log.Warn("retention run failed", "err", err)
		}
		run.Finished = m.now()
		if err := m.hist.Record(context.WithoutCancel(ctx), run); err != nil {
			m.Log.Warn("could not save the retention history", "file", m.HistoryFile, "err", err)
		}
		return run, err
	}
	s, err := m.Settings()
	if err != nil {
		return finish(fmt.Errorf("retention is paused until the settings file is fixed: %w", err))
	}
	today := startOfDay(m.now())
	// skip holds days that failed in this run, so the guard can choose
	// others in its next pass.
	skip := map[string]string{}
	attempted := map[string]bool{}
	guardFailed := false
	for pass := 0; pass < maxGuardPasses; pass++ {
		st, err := m.snapshot(ctx)
		if err != nil {
			if pass == 0 {
				return finish(err)
			}
			run.Errors = append(run.Errors, err.Error())
			break
		}
		st.snap.Skip = skip
		var plan *Plan
		if pass == 0 {
			plan, err = m.plan(ctx, s, st)
			if err != nil {
				run.Errors = append(run.Errors, err.Error())
			}
		} else {
			plan = PlanIndices(st.snap, s)
		}
		g := plan.Guard
		run.Guard = &g
		switch g.State {
		case GuardOver:
			m.Log.Warn("retention: disk is above the guard limit; deleting the oldest days",
				"percent", g.Percent, "limit", g.Threshold, "days", g.PlannedDays, "bytes", g.PlannedBytes)
		case GuardShort:
			m.Log.Error("retention: disk is above the guard limit and deleting old days cannot get it under; add disk space",
				"percent", g.Percent, "limit", g.Threshold, "min_days", g.MinDays, "can_free_bytes", g.CanFreeBytes,
				"need_bytes", g.NeedBytes, "days", g.PlannedDays)
		}
		wanted := m.stillWanted(s, st.snap)
		guardFailed = false
		hold, why := m.held()
		if hold && pass == 0 {
			m.Log.Info("retention: the policies wait to be confirmed, so only the disk guard acts", "why", why)
		}
		for _, d := range plan.Steps() {
			if ctx.Err() != nil {
				break
			}
			// Later passes only let the guard pick other days, and so do
			// policies that wait to be confirmed.
			if attempted[d.Index] || ((pass > 0 || hold) && d.Rule != RuleGuard) {
				continue
			}
			d, ok, why := wanted(d)
			if !ok {
				run.Skipped++
				m.Log.Info("retention: step skipped", "action", d.Action, "index", d.Index, "why", why)
				continue
			}
			attempted[d.Index] = true
			act := m.apply(ctx, d, today)
			m.record(run, act)
			if act.Error != "" {
				run.Errors = append(run.Errors, act.Index+": "+act.Error)
				if d.Removes() {
					skip[d.Index] = "it could not be " + map[bool]string{true: "archived", false: "deleted"}[act.Action == ActionArchive] + " earlier in this run"
					if d.Rule == RuleGuard {
						guardFailed = true
					}
				}
				continue
			}
			run.FreedBytes += act.Freed
			switch act.Action {
			case ActionCompact:
				run.Compacted++
			case ActionArchive:
				run.Archived++
			case ActionDelete:
				run.Deleted++
			}
		}
		if pass == 0 && !hold {
			m.deleteRecords(ctx, run, plan.Records)
		}
		if !guardFailed || ctx.Err() != nil {
			break
		}
		m.Log.Warn("retention: days the disk guard chose could not be deleted; it chooses again")
	}
	switch {
	case guardFailed:
		m.pauseGuard("days it chose could not be deleted (see the errors)")
	case run.Guard != nil && run.Guard.State == GuardShort:
		m.pauseGuard("deleting old days cannot get the disk under its limit")
	default:
		m.pauseGuard("")
	}
	if err := ctx.Err(); err != nil {
		return finish(fmt.Errorf("the run was stopped: %w", err))
	}
	if run.Compacted+run.Archived+run.Deleted > 0 || run.DeletedRecords > 0 {
		m.Log.Info("retention run finished", "compacted", run.Compacted, "archived", run.Archived,
			"deleted", run.Deleted, "records", run.DeletedRecords, "freed_bytes", run.FreedBytes, "errors", len(run.Errors))
	}
	return finish(nil)
}

// deleteRecords deletes resolved and closed findings and cases. Like index
// steps, each re-reads the settings first and never deletes more than they
// now say.
func (m *Manager) deleteRecords(ctx context.Context, run *Run, recs []RecordStep) {
	for _, r := range recs {
		if ctx.Err() != nil {
			return
		}
		cur, err := m.Settings()
		if err != nil {
			run.Skipped++
			continue
		}
		pol, _ := cur.For(r.Category)
		switch {
		case pol.KeepDays <= 0:
			run.Skipped++
			continue
		case pol.KeepDays > r.KeepDays:
			r.KeepDays = pol.KeepDays
			r.Before = m.now().Add(-time.Duration(pol.KeepDays) * 24 * time.Hour)
		}
		if err := m.step(ctx, r.Index, ActionDeleteRecords); err != nil {
			run.Errors = append(run.Errors, r.Category+": "+err.Error())
			return
		}
		n, err := m.Cluster.DeleteClosed(ctx, r.Index, r.Before, r.keepCases)
		act := Action{Time: m.now(), Action: ActionDeleteRecords, Category: r.Category, Docs: n, Rule: RuleRecords, Reason: r.Reason}
		if err != nil {
			act.Error = err.Error()
			run.Errors = append(run.Errors, r.Category+": "+err.Error())
		}
		run.DeletedRecords += n
		m.record(run, act)
	}
}

// stillWanted re-reads the settings before each step of a run, so a
// correction saved while the run works takes effect at once: a step the
// new settings no longer call for is skipped. It never adds work; the run
// that the save queued does that. The snapshot is the one the run planned
// from, so the check sees what a run started with the new settings would.
func (m *Manager) stillWanted(s Settings, snap Snapshot) func(Decision) (Decision, bool, string) {
	cur := s
	var now map[string]Decision
	return func(d Decision) (Decision, bool, string) {
		latest, err := m.Settings()
		if err != nil {
			return d, false, "the settings file has errors now"
		}
		if !reflect.DeepEqual(latest, cur) {
			cur = latest
			now = map[string]Decision{}
			for _, x := range PlanIndices(snap, latest).Decisions {
				now[x.Index] = x
			}
		}
		if now == nil {
			return d, true, ""
		}
		nd, ok := now[d.Index]
		switch {
		case !ok:
			return d, false, "the index is no longer planned"
		case d.Action == ActionArchive && nd.Removes():
			return d, true, ""
		case d.Removes() && nd.Removes():
			// Archive if the new settings say so.
			return nd, true, ""
		case d.Action == ActionCompact && nd.Action == ActionCompact:
			return d, true, ""
		}
		return d, false, "the settings saved during this run no longer call for it"
	}
}

// pauseGuard stops the disk check from starting runs until the next
// scheduled one; an empty reason ends the pause.
func (m *Manager) pauseGuard(why string) {
	m.mu.Lock()
	m.guardPaused, m.guardPausedWhy = m.now(), why
	if why == "" {
		m.guardPaused = time.Time{}
	}
	m.mu.Unlock()
}

// record logs an action and adds it to the history.
func (m *Manager) record(run *Run, act Action) {
	if act.Error != "" {
		m.Log.Warn("retention action failed", "action", act.Action, "index", act.Index, "category", act.Category, "err", act.Error)
	} else {
		m.Log.Info("retention: "+act.Action, "index", act.Index, "category", act.Category, "reason", act.Reason,
			"bytes", act.Bytes, "docs", act.Docs, "file", act.File)
	}
	if run != nil && run.Trigger != "" && act.By == "" {
		act.By = run.By
	}
	if err := m.hist.Record(m.ctx(), nil, act); err != nil {
		m.Log.Warn("could not save the retention history", "file", m.HistoryFile, "err", err)
	}
}

// apply carries out one decision. It re-checks the index name and day,
// so a planner bug can never delete today's data or another prefix's.
func (m *Manager) apply(ctx context.Context, d Decision, today time.Time) Action {
	act := Action{Time: m.now(), Action: d.Action, Category: d.Category, Index: d.Index, Day: d.Day,
		Bytes: d.Bytes, Rule: d.Rule, Reason: d.Reason}
	cat, day, ok := ParseIndex(m.Prefix, d.Index)
	switch {
	case !ok || cat != d.Category:
		act.Error = "refused: not a Signalith daily or monthly index"
		return act
	case d.Removes() && !day.Before(today):
		act.Error = "refused: today's and future days are never deleted"
		return act
	case isMonthly(cat) && (d.Action == ActionCompact || !monthEnd(day).Before(today)):
		act.Error = "refused: the current month is never deleted, and monthly indices are never compacted"
		return act
	case d.Action == ActionCompact && !day.Before(today.AddDate(0, 0, -1)):
		act.Error = "refused: today and yesterday are never compacted"
		return act
	}
	if d.Action == ActionArchive && m.CanArchive != nil {
		if ok, why := m.CanArchive(); !ok {
			act.Error = "held back: this server cannot archive now (" + why + "), so the day was kept"
			return act
		}
	}
	if err := m.step(ctx, d.Index, d.Action); err != nil {
		act.Error = err.Error()
		return act
	}
	var err error
	switch {
	case d.Action == ActionCompact:
		err = m.compact(ctx, d, &act)
	case d.Action == ActionArchive:
		err = m.archiveAndDelete(ctx, d, &act)
	case d.verify:
		err = m.verifiedDelete(ctx, d, &act)
	default:
		act.Docs = d.Docs
		if err = m.Cluster.DeleteIndex(ctx, d.Index); err == nil {
			act.Freed = d.Bytes
		}
	}
	if err != nil {
		act.Error = err.Error()
	}
	act.Time = m.now()
	return act
}

func (m *Manager) compact(ctx context.Context, d Decision, act *Action) error {
	if err := m.Cluster.BlockWrites(ctx, d.Index, true); err != nil {
		return fmt.Errorf("could not make the index read-only: %w", err)
	}
	if err := m.Cluster.ForceMerge(ctx, d.Index); err != nil {
		return fmt.Errorf("could not merge the index: %w", err)
	}
	if after, err := m.Cluster.Indices(ctx, d.Index); err == nil && len(after) == 1 {
		act.Freed = max(d.Bytes-after[0].Bytes, 0)
	}
	return nil
}

// freeze blocks writes to an index and refreshes it, so a count and an
// export see every event it will ever hold: events written in the last
// seconds before the block only show after a refresh. An index under
// OpenSearch's flood-stage block takes no writes and refuses setting
// changes, but can still be refreshed. It reports whether it set the
// block, which thaw undoes when the index is kept after all.
func (m *Manager) freeze(ctx context.Context, d Decision) (bool, error) {
	set := false
	if !d.writesBlocked {
		if err := m.Cluster.BlockWrites(ctx, d.Index, true); err != nil {
			return false, fmt.Errorf("could not make the index read-only before archiving it, so it was kept: %w", err)
		}
		set = true
	}
	if err := m.Cluster.Refresh(ctx, d.Index); err != nil {
		m.thaw(ctx, d, set)
		return false, fmt.Errorf("could not refresh the index before archiving it, so it was kept: %w", err)
	}
	return set, nil
}

// thaw lifts the write block freeze set on an index that is kept, so it
// keeps taking late events.
func (m *Manager) thaw(ctx context.Context, d Decision, set bool) {
	if !set {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := m.step(cctx, d.Index, "thaw"); err != nil {
		m.Log.Warn("retention: did not make a kept index writable again", "index", d.Index, "err", err)
		return
	}
	if err := m.Cluster.BlockWrites(cctx, d.Index, false); err != nil {
		m.Log.Warn("retention: could not make a kept index writable again", "index", d.Index, "err", err)
	}
}

func (m *Manager) archiveAndDelete(ctx context.Context, d Decision, act *Action) error {
	set, err := m.freeze(ctx, d)
	if err != nil {
		return err
	}
	if err := m.archiveFrozen(ctx, d, act); err != nil {
		if act.File == "" {
			m.thaw(ctx, d, set)
		}
		return err
	}
	return nil
}

// archiveFrozen archives a frozen index and deletes it.
func (m *Manager) archiveFrozen(ctx context.Context, d Decision, act *Action) error {
	n, err := m.Cluster.Count(ctx, d.Index)
	if err != nil {
		return fmt.Errorf("could not count its events, so it was kept: %w", err)
	}
	est := d.primary
	if est <= 0 {
		est = d.Bytes
	}
	man, err := m.Archive.Write(ctx, m.Cluster, Source{Index: d.Index, UUID: d.uuid, Category: d.Category, Day: d.Day,
		Bytes: d.Bytes, Estimate: est / 2}, n)
	if err != nil {
		return fmt.Errorf("archiving failed, so the index was kept: %w", err)
	}
	act.File, act.Docs = man.File, man.Docs
	// The export may have taken long: check again before deleting.
	if err := m.step(ctx, d.Index, ActionDelete); err != nil {
		return fmt.Errorf("archived to %s, but the index was not deleted: %w", man.File, err)
	}
	if err := m.Cluster.DeleteIndex(ctx, d.Index); err != nil {
		return fmt.Errorf("archived to %s, but deleting the index failed: %w", man.File, err)
	}
	act.Freed = d.Bytes
	return nil
}

// verifiedDelete deletes an index in a category that archives, when the
// archive already holds it or it looked empty. It first freezes and counts
// the index: if it holds more than the archive does, because events
// arrived since, it is archived again instead.
func (m *Manager) verifiedDelete(ctx context.Context, d Decision, act *Action) error {
	set, err := m.freeze(ctx, d)
	if err != nil {
		return err
	}
	n, err := m.Cluster.Count(ctx, d.Index)
	if err != nil {
		m.thaw(ctx, d, set)
		return fmt.Errorf("could not count its events, so it was kept: %w", err)
	}
	if n > d.archived {
		act.Action = ActionArchive
		act.Reason = strings.TrimSuffix(d.Reason, " (already archived)")
		if err := m.archiveFrozen(ctx, d, act); err != nil {
			if act.File == "" {
				m.thaw(ctx, d, set)
			}
			return err
		}
		return nil
	}
	act.Docs = n
	if err := m.step(ctx, d.Index, ActionDelete); err != nil {
		m.thaw(ctx, d, set)
		return err
	}
	if err := m.Cluster.DeleteIndex(ctx, d.Index); err != nil {
		m.thaw(ctx, d, set)
		return err
	}
	act.Freed = d.Bytes
	return nil
}

// SetInterval changes how often Start enforces policies, at once: the
// next run comes one new interval after the last one, or now when that
// is past. retention.interval is shared by the servers of a cluster and
// applies without a restart.
func (m *Manager) SetInterval(d time.Duration) {
	m.init()
	if d <= 0 || d == m.interval() {
		return
	}
	m.liveInterval.Store(int64(d))
	select {
	case m.reschedule <- struct{}{}:
	default:
	}
}

// Start enforces retention every Interval until ctx ends, and checks the
// disk every few minutes so the guard can act between runs. Only the
// server that runs the detection scheduler calls it.
func (m *Manager) Start(ctx context.Context) {
	m.init()
	m.mu.Lock()
	m.automatic, m.baseCtx, m.nextRun = true, ctx, m.now().Add(firstRunDelay)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.automatic = false
		m.mu.Unlock()
	}()
	timer := time.NewTimer(firstRunDelay)
	defer timer.Stop()
	check := time.NewTicker(diskCheck)
	defer check.Stop()
	scheduled := func(trigger string) {
		if _, err := m.Run(ctx, trigger, ""); errors.Is(err, ErrBusy) || errors.Is(err, ErrRestoring) {
			m.Log.Info("retention run skipped; another job is in progress", "trigger", trigger)
		}
	}
	// lastRun is when the last scheduled run ended; zero before the first,
	// which comes a moment after the start whatever the interval.
	var lastRun time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			scheduled(TriggerSchedule)
			lastRun = m.now()
			m.mu.Lock()
			m.nextRun = lastRun.Add(m.interval())
			m.mu.Unlock()
			timer.Reset(m.interval())
		case <-m.reschedule:
			if lastRun.IsZero() {
				continue
			}
			next := lastRun.Add(m.interval())
			if now := m.now(); next.Before(now) {
				next = now
			}
			m.mu.Lock()
			m.nextRun = next
			m.mu.Unlock()
			timer.Reset(next.Sub(m.now()))
		case <-check.C:
			if m.guardTripped(ctx) {
				scheduled(TriggerGuard)
			}
		}
	}
}

// guardTripped reports whether the disk is over the guard's limit. After
// a run in which the guard could not get the disk under its limit, it
// waits for the next scheduled run instead of retrying every few minutes.
func (m *Manager) guardTripped(ctx context.Context) bool {
	s, err := m.Settings()
	if err != nil || !s.Guard.IsEnabled() {
		return false
	}
	if _, paused := m.guardPause(); paused {
		return false
	}
	d, err := m.Cluster.Disk(ctx)
	return err == nil && d.Percent() > float64(s.Guard.MaxDiskPercent)
}

// guardPause returns when the guard's pause ends, if it is paused.
func (m *Manager) guardPause() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.guardPaused.IsZero() {
		return time.Time{}, false
	}
	until := m.guardPaused.Add(m.interval())
	return until, m.now().Before(until)
}

// ---- settings changes ----

// SetPolicy saves a category's own policy, or with nil goes back to the
// default.
func (m *Manager) SetPolicy(id string, p *Policy) error { return m.SetPolicyIf(id, p, "") }

// SetPolicyIf is SetPolicy, refused when the policies are no longer at
// version etag ("" saves whatever their version).
func (m *Manager) SetPolicyIf(id string, p *Policy, etag string) error {
	return m.change(Change{Category: id, Policy: p}, etag, func(sv *Saved) {
		delete(sv.From, "policies."+id)
		if p == nil {
			delete(sv.Policies, id)
			return
		}
		if sv.Policies == nil {
			sv.Policies = map[string]Policy{}
		}
		sv.Policies[id] = *p
	})
}

// SetDefault saves the default policy for event categories.
func (m *Manager) SetDefault(p Policy) error { return m.SetDefaultIf(p, "") }

// SetDefaultIf is SetDefault at version etag (see SetPolicyIf).
func (m *Manager) SetDefaultIf(p Policy, etag string) error {
	return m.change(Change{Default: &p}, etag, func(sv *Saved) {
		sv.Default = &p
		delete(sv.From, "default")
	})
}

// SetGuard saves the disk guard settings.
func (m *Manager) SetGuard(g Guard) error { return m.SetGuardIf(g, "") }

// SetGuardIf is SetGuard at version etag (see SetPolicyIf).
func (m *Manager) SetGuardIf(g Guard, etag string) error {
	g = g.Normalized()
	return m.change(Change{Guard: &g}, etag, func(sv *Saved) {
		sv.Guard = &g
		delete(sv.From, "guard")
	})
}

func (m *Manager) change(ch Change, etag string, save func(*Saved)) error {
	if !m.Shared {
		// A server's own files are only used by it, so only the server
		// that runs retention may change them.
		if err := m.readOnly(); err != nil {
			return err
		}
	}
	if m.Store == nil {
		return errors.New("retention settings cannot be saved on this server")
	}
	cur, err := m.Settings()
	if err != nil {
		return err
	}
	if _, err := cur.apply(ch); err != nil {
		return err
	}
	if v, ok := m.Store.(VersionedStore); ok && etag != "" {
		err = v.UpdateIf(etag, save)
	} else {
		err = m.Store.Update(save)
	}
	if err != nil {
		return err
	}
	if m.OnSettings != nil {
		if s, err := m.Settings(); err == nil {
			m.OnSettings(s)
		}
	}
	return nil
}

// ---- previews ----

// Preview is what saving a settings change does. Saving starts a run, so
// besides what the change itself does (Summary, Steps, Records) it lists
// what the current settings already call for and the new ones still do
// (Due): that is done too, at once.
type Preview struct {
	Summary     Summary      `json:"summary"`
	Steps       []Decision   `json:"steps"`
	Records     []RecordStep `json:"records"`
	Due         Summary      `json:"due"`
	DueSteps    []Decision   `json:"due_steps"`
	DueRecords  []RecordStep `json:"due_records"`
	DeletesData bool         `json:"deletes_data"`
	Guard       GuardStatus  `json:"guard"`
	Notes       []string     `json:"notes"`
}

// Preview plans a change without saving it.
func (m *Manager) Preview(ctx context.Context, ch Change) (*Preview, error) {
	cur, err := m.Settings()
	if err != nil {
		return nil, err
	}
	next, err := cur.apply(ch)
	if err != nil {
		return nil, err
	}
	st, err := m.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	before, _ := m.plan(ctx, cur, st)
	after, err := m.plan(ctx, next, st)
	if err != nil {
		after.Notes = append(after.Notes, err.Error())
	}
	was := map[string]string{}
	for _, d := range before.Steps() {
		was[d.Index] = d.Action
	}
	steps, due := []Decision{}, []Decision{}
	for _, d := range after.Steps() {
		if was[d.Index] == d.Action {
			due = append(due, d)
		} else {
			steps = append(steps, d)
		}
	}
	recs, dueRecs := []RecordStep{}, []RecordStep{}
	for _, r := range after.Records {
		var had int64
		for _, b := range before.Records {
			if b.Category == r.Category {
				had = b.Count
			}
		}
		if n := min(had, r.Count); n > 0 {
			d := r
			d.Count = n
			dueRecs = append(dueRecs, d)
		}
		if r.Count > had {
			r.Count -= had
			recs = append(recs, r)
		}
	}
	sum, dueSum := Summarize(steps, recs), Summarize(due, dueRecs)
	return &Preview{Summary: sum, Steps: steps, Records: recs, Due: dueSum, DueSteps: due, DueRecords: dueRecs,
		DeletesData: sum.DeletesData() || dueSum.DeletesData(), Guard: after.Guard, Notes: after.Notes}, nil
}

// ---- overview ----

// Overview is everything the Data retention page shows.
type Overview struct {
	Categories []CategoryView `json:"categories"`
	Default    DefaultView    `json:"default"`
	Guard      GuardView      `json:"guard"`
	// Disk is the fullest OpenSearch data disk; nil when it could not be read.
	Disk      *Disk  `json:"disk"`
	DiskError string `json:"disk_error,omitempty"`
	// TotalBytes and TotalDocs add up every category.
	TotalBytes int64 `json:"total_bytes"`
	TotalDocs  int64 `json:"total_docs"`
	// DiskBlocked counts indices OpenSearch made read-only because the
	// disk passed its flood-stage watermark.
	DiskBlocked int            `json:"disk_blocked"`
	Archive     ArchiveSummary `json:"archive"`
	Schedule    ScheduleView   `json:"schedule"`
	// Pending is what the next run would do with the current settings.
	Pending Summary  `json:"pending"`
	Notes   []string `json:"notes"`
	LastRun *Run     `json:"last_run"`
	Recent  []Action `json:"recent"`
	// RestoreQueued is set where restores asked on any server go to the
	// one that runs retention (servers that share their archives).
	RestoreQueued bool `json:"restore_queued,omitempty"`
	// HistorySource says where the history is kept: "file" on a server
	// of its own, "audit" when servers that share one OpenSearch keep it
	// as audit records.
	HistorySource string `json:"history_source"`
	// Unmanaged lists indices under the prefix that are not daily indices
	// of a known category; retention leaves them alone.
	Unmanaged []IndexInfo `json:"unmanaged"`
	// Error says OpenSearch could not be read; sizes are then missing.
	Error string `json:"error,omitempty"`
	// SettingsError says retention.yaml has errors; runs are paused.
	SettingsError string `json:"settings_error,omitempty"`
	// Hold is set while the policies wait to be confirmed: runs only take
	// the disk guard's steps until they are.
	Hold *HoldView `json:"hold,omitempty"`
	// ETag is the version of the saved policies, for If-Match.
	ETag string `json:"etag,omitempty"`
	// Shared is set when the policies are the servers' shared ones: any
	// server changes them, and the one that runs retention enforces them.
	Shared bool `json:"shared,omitempty"`
}

// HoldView says why the policies wait to be confirmed.
type HoldView struct {
	Reason string `json:"reason"`
}

// FromView is where a shared setting's value came from, for the page.
type FromView struct {
	Provenance
	Note string `json:"note"`
}

// from returns where the first of keys that has a record came from.
func (s Settings) from(keys ...string) *FromView {
	for _, k := range keys {
		if p, ok := s.From[k]; ok {
			return &FromView{Provenance: p, Note: p.Note()}
		}
	}
	return nil
}

// CategoryView is one row of the page's table.
type CategoryView struct {
	Category
	Bytes int64 `json:"bytes"`
	Docs  int64 `json:"docs"`
	// Days counts daily indices; OldestDay and NewestDay are YYYY-MM-DD,
	// empty when there is no data (for findings and cases: when the
	// oldest and newest were created).
	Days          int    `json:"days"`
	OldestDay     string `json:"oldest_day"`
	NewestDay     string `json:"newest_day"`
	CompactedDays int    `json:"compacted_days"`
	RestoredDays  int    `json:"restored_days"`
	Policy        Policy `json:"policy"`
	// Source is default, ui, config or feeds; Editable is false for
	// policies from signalith.yaml and for threat intel.
	Source   string    `json:"source"`
	Editable bool      `json:"editable"`
	Note     string    `json:"note,omitempty"`
	From     *FromView `json:"from,omitempty"`
	Pending  Summary   `json:"pending"`
}

// DefaultView is the default policy for event categories.
type DefaultView struct {
	Policy   Policy    `json:"policy"`
	Source   string    `json:"source"` // days, ui or config
	Editable bool      `json:"editable"`
	Note     string    `json:"note,omitempty"`
	From     *FromView `json:"from,omitempty"`
}

// GuardView is the disk guard's settings and what it sees.
type GuardView struct {
	Enabled        bool        `json:"enabled"`
	MaxDiskPercent int         `json:"max_disk_percent"`
	MinDays        int         `json:"min_days"`
	Source         string      `json:"source"` // builtin, ui or config
	Editable       bool        `json:"editable"`
	Note           string      `json:"note,omitempty"`
	From           *FromView   `json:"from,omitempty"`
	Status         GuardStatus `json:"status"`
	// PausedUntil is set while the disk check waits for the next scheduled
	// run, after a run in which the guard could not get the disk under its
	// limit; PauseReason says why.
	PausedUntil *time.Time `json:"paused_until,omitempty"`
	PauseReason string     `json:"pause_reason,omitempty"`
}

// ArchiveSummary describes the archive folder.
type ArchiveSummary struct {
	Dir      string   `json:"dir"`
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
	Error    string   `json:"error,omitempty"`
	Problems []string `json:"problems"`
	// Free is the space free in the archive folder, -1 when unknown.
	Free int64 `json:"free"`
	// SameDisk is true when the archive folder looks to be on the same
	// disk as OpenSearch's data (this server's disk has the same size).
	SameDisk bool `json:"same_disk,omitempty"`
	// HeldBack says why this server cannot archive now, so runs keep the
	// days they would archive; empty when it can.
	HeldBack string `json:"held_back,omitempty"`
	// On names the servers that can archive, when servers share one
	// OpenSearch.
	On []string `json:"on,omitempty"`
}

// ScheduleView says when retention runs.
type ScheduleView struct {
	Interval        string `json:"interval"`
	IntervalSeconds int64  `json:"interval_seconds"`
	// Automatic is false on servers that do not run the detection
	// scheduler; they only run when asked.
	Automatic bool `json:"automatic"`
	// ReadOnly is true on servers that do not run retention; the page
	// then only shows it.
	ReadOnly bool `json:"read_only"`
	// ReadOnlyWhy says why, naming the server that runs retention. RunsOn
	// names that server; NoRunner is true when none does right now.
	ReadOnlyWhy string     `json:"read_only_why,omitempty"`
	RunsOn      string     `json:"runs_on,omitempty"`
	NoRunner    bool       `json:"no_runner,omitempty"`
	Running     bool       `json:"running"`
	Current     string     `json:"current,omitempty"` // run or restore
	Queued      bool       `json:"queued,omitempty"`  // another run starts when this one ends
	NextRun     *time.Time `json:"next_run"`
}

const fromConfig = "From signalith.yaml"

// shortDuration prints 1h rather than 1h0m0s.
func shortDuration(d time.Duration) string {
	out := d.String()
	if strings.HasSuffix(out, "m0s") {
		out = strings.TrimSuffix(out, "0s")
	}
	if strings.HasSuffix(out, "h0m") {
		out = strings.TrimSuffix(out, "0m")
	}
	return out
}

// Overview gathers the page's data. It always returns something: when
// OpenSearch cannot be read, Error says so and sizes are missing.
func (m *Manager) Overview(ctx context.Context) *Overview {
	m.init()
	s, serr := m.Settings()
	ov := &Overview{Categories: []CategoryView{}, Notes: []string{}, Recent: []Action{}, Unmanaged: []IndexInfo{},
		Pending: Summary{Categories: []string{}}}
	if serr != nil {
		ov.SettingsError = serr.Error()
	}
	roErr := m.readOnly()
	canEdit := m.Store != nil && (roErr == nil || m.Shared)
	if held, why := m.held(); held {
		ov.Hold = &HoldView{Reason: why}
	}
	ov.Default = DefaultView{Policy: s.Default, Source: s.DefaultSource, Editable: s.DefaultSource != SourceConfig && canEdit}
	if s.DefaultSource == SourceConfig {
		ov.Default.Note = fromConfig
	}
	// retention.days gives the default policy only until one is saved.
	if s.DefaultSource == SourceDays {
		ov.Default.From = s.from("days")
	} else {
		ov.Default.From = s.from("default")
	}
	ov.Guard = GuardView{Enabled: s.Guard.IsEnabled(), MaxDiskPercent: s.Guard.MaxDiskPercent, MinDays: s.Guard.MinDays,
		Source: s.GuardSource, Editable: s.GuardSource != SourceConfig && canEdit}
	if s.GuardSource == SourceConfig {
		ov.Guard.Note = fromConfig
	}
	ov.Guard.From = s.from("guard")
	if until, paused := m.guardPause(); paused {
		ov.Guard.PausedUntil = &until
		m.mu.Lock()
		ov.Guard.PauseReason = m.guardPausedWhy
		m.mu.Unlock()
	}
	ov.ETag, ov.Shared = m.ETag(), m.Shared
	ov.HistorySource = m.hist.Source()
	if run, acts, err := m.hist.Recent(ctx); err != nil {
		ov.Notes = append(ov.Notes, "The retention history could not be read: "+err.Error())
	} else {
		ov.LastRun, ov.Recent = run, acts
	}
	ov.Archive = ArchiveSummary{Dir: m.Archive.Dir, Problems: []string{}, Free: -1}
	if m.CanArchive != nil {
		if ok, why := m.CanArchive(); !ok {
			ov.Archive.HeldBack = why
		}
	}
	if m.ArchiveOn != nil {
		ov.Archive.On = m.ArchiveOn()
	}
	iv := m.interval()
	m.mu.Lock()
	ov.Schedule = ScheduleView{Interval: shortDuration(iv), IntervalSeconds: int64(iv / time.Second),
		Automatic: m.automatic, ReadOnly: roErr != nil, Running: m.current != "", Current: m.current, Queued: m.queued != nil}
	if roErr != nil {
		why := roErr.Error()
		ov.Schedule.ReadOnlyWhy = strings.ToUpper(why[:1]) + why[1:] + "."
		var ro *ReadOnlyError
		if errors.As(roErr, &ro) {
			ov.Schedule.RunsOn, ov.Schedule.NoRunner = ro.Holder, ro.Holder == ""
		}
	}
	if m.automatic && !m.nextRun.IsZero() {
		next := m.nextRun
		ov.Schedule.NextRun = &next
	}
	m.mu.Unlock()

	st, err := m.snapshot(ctx)
	var plan *Plan
	if err != nil {
		ov.Error = err.Error()
		st = &state{snap: Snapshot{Now: m.now(), Prefix: m.Prefix}, records: map[string]IndexInfo{}}
		plan = PlanIndices(st.snap, s)
		ov.Guard.Status = GuardStatus{State: GuardUnknown, Threshold: s.Guard.MaxDiskPercent, MinDays: s.Guard.MinDays,
			Message: "OpenSearch could not be read."}
		if !s.Guard.IsEnabled() {
			ov.Guard.Status.State, ov.Guard.Status.Message = GuardOff, "The disk guard is off."
		}
	} else {
		plan, err = m.plan(ctx, s, st)
		if err != nil {
			ov.Notes = append(ov.Notes, err.Error())
		}
		ov.Guard.Status = plan.Guard
		ov.Disk, ov.DiskError = st.snap.Disk, st.diskErr
		ov.Notes = append(ov.Notes, plan.Notes...)
		for _, ma := range st.archives {
			ov.Archive.Files++
			ov.Archive.Bytes += ma.Bytes
		}
		ov.Archive.Error = st.archErr
		if st.archProb != nil {
			ov.Archive.Problems = st.archProb
		}
		if m.Archive.Dir != "" {
			if free, total, err := diskSpace(m.Archive.Dir); err == nil {
				ov.Archive.Free = free
				ov.Archive.SameDisk = st.snap.Disk != nil && total > 0 && total == st.snap.Disk.Total
			}
		}
	}
	if serr != nil {
		// Nothing is checked or deleted until the file is fixed.
		ov.Guard.Status = GuardStatus{State: GuardPaused, Threshold: s.Guard.MaxDiskPercent, MinDays: s.Guard.MinDays,
			Percent: ov.Guard.Status.Percent, Message: "The disk isn't checked until the settings file is fixed."}
	}
	steps := plan.Steps()
	ov.Pending = Summarize(steps, plan.Records)

	byCat := map[string]*CategoryView{}
	for _, c := range Categories() {
		pol, src := s.For(c.ID)
		cv := &CategoryView{Category: c, Policy: pol, Source: src,
			Editable: c.Kind != KindManaged && src != SourceConfig && canEdit}
		switch {
		case src == SourceConfig:
			cv.Note = fromConfig
		case c.Kind == KindManaged:
			cv.Note = "Managed by feeds"
		}
		if _, own := s.Policies[c.ID]; own {
			cv.From = s.from("policies." + c.ID)
		}
		var cs []Decision
		for _, d := range steps {
			if d.Category == c.ID {
				cs = append(cs, d)
			}
		}
		var cr []RecordStep
		for _, r := range plan.Records {
			if r.Category == c.ID {
				cr = append(cr, r)
			}
		}
		cv.Pending = Summarize(cs, cr)
		byCat[c.ID] = cv
	}
	for _, ix := range st.snap.Indices {
		cat, day, ok := ParseIndex(m.Prefix, ix.Name)
		if !ok {
			ov.Unmanaged = append(ov.Unmanaged, ix)
			continue
		}
		cv := byCat[cat]
		cv.Bytes += ix.Bytes
		cv.Docs += ix.Docs
		cv.Days++
		ds := day.Format(time.DateOnly)
		if cv.OldestDay == "" || ds < cv.OldestDay {
			cv.OldestDay = ds
		}
		if ds > cv.NewestDay {
			cv.NewestDay = ds
		}
		if ix.Compacted() {
			cv.CompactedDays++
		}
		if ix.RestoredUntil != "" && ix.RestoredUntil >= plan.Today {
			cv.RestoredDays++
		}
		if ix.DiskBlocked {
			ov.DiskBlocked++
		}
	}
	for _, id := range []string{Findings, Cases, Intel} {
		cv := byCat[id]
		if ix, ok := st.records[RecordIndex(m.Prefix, id)]; ok {
			cv.Bytes, cv.Docs = ix.Bytes, ix.Docs
			if ix.DiskBlocked {
				ov.DiskBlocked++
			}
			if id != Intel && ov.Error == "" {
				if lo, hi, err := m.Cluster.RecordRange(ctx, ix.Name); err == nil && !lo.IsZero() {
					cv.OldestDay, cv.NewestDay = lo.Format(time.DateOnly), hi.Format(time.DateOnly)
				}
			}
		}
	}
	for _, c := range Categories() {
		cv := byCat[c.ID]
		// "Other events" only shows once there are some, or a policy for them.
		// Neither do audit records, which only servers that share one
		// OpenSearch keep.
		if (c.ID == "other" || c.Kind == KindMonthly) && cv.Days == 0 && cv.Source == SourceDefault {
			continue
		}
		ov.TotalBytes += cv.Bytes
		ov.TotalDocs += cv.Docs
		ov.Categories = append(ov.Categories, *cv)
	}
	return ov
}

// ---- archive and restore ----

// RestoreStatus follows one restore.
type RestoreStatus struct {
	ID       string `json:"id"`
	Index    string `json:"index"`
	Category string `json:"category"`
	Day      string `json:"day"`
	// State is queued, running, done or failed.
	State     string     `json:"state"`
	Docs      int64      `json:"docs"`
	Restored  int64      `json:"restored"`
	KeepUntil string     `json:"keep_until"`
	Error     string     `json:"error,omitempty"`
	By        string     `json:"by,omitempty"`
	Queued    time.Time  `json:"queued"`
	Finished  *time.Time `json:"finished,omitempty"`
}

// Restore states.
const (
	RestoreQueued  = "queued"
	RestoreRunning = "running"
	RestoreDone    = "done"
	RestoreFailed  = "failed"
)

// ArchiveView is one archived day.
type ArchiveView struct {
	Manifest
	CategoryName string `json:"category_name"`
	// Searchable is true while the day is in OpenSearch, for example
	// after a restore; RestoredUntil is how long a restored day stays.
	Searchable    bool           `json:"searchable"`
	RestoredUntil string         `json:"restored_until,omitempty"`
	Restore       *RestoreStatus `json:"restore,omitempty"`
}

// ArchiveList is the archive tab's data.
type ArchiveList struct {
	Dir             string          `json:"dir"`
	Archives        []ArchiveView   `json:"archives"`
	Bytes           int64           `json:"bytes"`
	Docs            int64           `json:"docs"`
	Problems        []string        `json:"problems"`
	Restores        []RestoreStatus `json:"restores"`
	DefaultKeepDays int             `json:"default_keep_days"`
	MaxKeepDays     int             `json:"max_keep_days"`
	Error           string          `json:"error,omitempty"`
}

// Archives lists archived days with whether each is searchable now.
func (m *Manager) Archives(ctx context.Context) (*ArchiveList, error) {
	m.init()
	list, problems, err := m.Archive.List()
	if err != nil {
		return nil, fmt.Errorf("could not read the archive folder %s: %w", m.Archive.Dir, err)
	}
	out := &ArchiveList{Dir: m.Archive.Dir, Archives: []ArchiveView{}, Problems: []string{}, Restores: m.RestoreStatuses(ctx),
		DefaultKeepDays: DefaultRestoreDays, MaxKeepDays: MaxRestoreDays}
	if problems != nil {
		out.Problems = problems
	}
	live := map[string]IndexInfo{}
	if ixs, err := m.Cluster.Indices(ctx, m.Prefix+"-*,"+m.Prefix+"_*"); err != nil {
		out.Error = "could not check OpenSearch for restored days: " + err.Error()
	} else {
		for _, ix := range ixs {
			live[ix.Name] = ix
		}
	}
	latest := map[string]RestoreStatus{}
	for _, r := range out.Restores {
		if _, ok := latest[r.ID]; !ok {
			latest[r.ID] = r
		}
	}
	for _, man := range list {
		v := ArchiveView{Manifest: man}
		if c, ok := CategoryByID(man.Category); ok {
			v.CategoryName = c.Name
		}
		if ix, ok := live[man.Index]; ok {
			v.Searchable = true
			v.RestoredUntil = ix.RestoredUntil
		}
		if r, ok := latest[man.ID]; ok {
			v.Restore = &r
		}
		out.Bytes += man.Bytes
		out.Docs += man.Docs
		out.Archives = append(out.Archives, v)
	}
	return out, nil
}

// restoreStatuses returns recent restores, newest first.
func (m *Manager) restoreStatuses() []RestoreStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RestoreStatus, 0, len(m.restores))
	for i := len(m.restores) - 1; i >= 0; i-- {
		out = append(out, *m.restores[i])
	}
	return out
}

func (m *Manager) updateRestore(st *RestoreStatus, change func(*RestoreStatus)) {
	m.mu.Lock()
	change(st)
	m.mu.Unlock()
	m.saveJobs()
}

// saveJobs shares the restores' progress, when servers share it.
func (m *Manager) saveJobs() {
	if m.Jobs == nil {
		return
	}
	m.mu.Lock()
	list := make([]RestoreStatus, len(m.restores))
	for i, r := range m.restores {
		list[i] = *r
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(m.ctx()), 10*time.Second)
	defer cancel()
	if err := m.Jobs.Save(ctx, list); err != nil {
		m.Log.Debug("could not share the progress of restores", "err", err)
	}
}

// RestoreStatuses returns recent restores, newest first: this server's
// own, or, on a server that does not run them, those the server that
// does shared.
func (m *Manager) RestoreStatuses(ctx context.Context) []RestoreStatus {
	m.init()
	if m.Jobs != nil && m.readOnly() != nil {
		if list, err := m.Jobs.Load(ctx); err == nil {
			slices.Reverse(list)
			return list
		}
	}
	return m.restoreStatuses()
}

// restoreManifests checks a restore request and returns its archives.
func (m *Manager) restoreManifests(ids []string, keepDays int) ([]Manifest, int, error) {
	if keepDays == 0 {
		keepDays = DefaultRestoreDays
	}
	if keepDays < 1 || keepDays > MaxRestoreDays {
		return nil, 0, &PolicyError{Problems: []string{fmt.Sprintf("keep_days must be between 1 and %d", MaxRestoreDays)}}
	}
	if len(ids) == 0 {
		return nil, 0, &PolicyError{Problems: []string{"choose at least one archived day to restore"}}
	}
	var mans []Manifest
	for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
		man, err := m.Archive.Get(id)
		if err != nil {
			if errors.Is(err, ErrArchiveNotFound) {
				return nil, 0, fmt.Errorf("%w: %s", ErrArchiveNotFound, id)
			}
			return nil, 0, fmt.Errorf("%s: %w", id, err)
		}
		if cat, _, ok := ParseIndex(m.Prefix, man.Index); !ok || cat != man.Category {
			return nil, 0, &PolicyError{Problems: []string{fmt.Sprintf("%s was archived from %s, which is not a %s-* daily index on this server",
				id, man.Index, m.Prefix)}}
		}
		mans = append(mans, man)
	}
	return mans, keepDays, nil
}

// RestoreCheck is what restoring archived days does to OpenSearch's disk.
// Restored days are spared by size caps and the disk guard, so when they
// push the disk over the guard's limit, the guard makes room by deleting
// the oldest live days of other categories at the next run.
type RestoreCheck struct {
	Days int   `json:"days"`
	Docs int64 `json:"docs"`
	// Bytes is about what the days take in OpenSearch once restored: their
	// size when they were archived. Days still in OpenSearch add nothing.
	Bytes int64 `json:"bytes"`
	// Disk is the fullest data disk now, and PercentAfter its use after
	// the restore if every restored shard lands on it.
	Disk         *Disk       `json:"disk"`
	PercentAfter float64     `json:"percent_after"`
	Guard        GuardStatus `json:"guard"`
	// Steps are the live days the next run would delete to make room, and
	// Deletes counts them; Unarchived counts those not archived first.
	Steps      []Decision `json:"steps"`
	Deletes    Summary    `json:"deletes"`
	Unarchived int        `json:"unarchived"`
	// OverLimit is true when the restore takes the disk above the guard's
	// limit; Flood when it reaches OpenSearch's flood stage, where it stops
	// taking events.
	OverLimit bool `json:"over_limit"`
	Flood     bool `json:"flood"`
	// NeedsConfirm is true when the restore deletes live days or fills the
	// disk; Restore then refuses unless confirmed.
	NeedsConfirm bool   `json:"needs_confirm"`
	Message      string `json:"message,omitempty"`
}

// ConfirmError is returned by Restore when the restore needs to be
// confirmed; Check says why.
type ConfirmError struct{ Check *RestoreCheck }

func (e *ConfirmError) Error() string { return e.Check.Message }

// CheckRestore works out what restoring archived days would do, without
// restoring anything.
func (m *Manager) CheckRestore(ctx context.Context, ids []string, keepDays int) (*RestoreCheck, error) {
	m.init()
	mans, keepDays, err := m.restoreManifests(ids, keepDays)
	if err != nil {
		return nil, err
	}
	s, err := m.Settings()
	if err != nil {
		return nil, err
	}
	st, err := m.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	until := startOfDay(m.now()).AddDate(0, 0, keepDays).Format(time.DateOnly)
	before := PlanIndices(st.snap, s)
	sim := st.snap
	sim.Indices = slices.Clone(st.snap.Indices)
	if st.snap.NodeBytes != nil {
		sim.NodeBytes = maps.Clone(st.snap.NodeBytes)
	}
	chk := &RestoreCheck{Days: len(mans), Steps: []Decision{}}
	for _, man := range mans {
		chk.Docs += man.Docs
		i := slices.IndexFunc(sim.Indices, func(ix IndexInfo) bool { return ix.Name == man.Index })
		if i < 0 {
			sim.Indices = append(sim.Indices, IndexInfo{Name: man.Index, Health: "green"})
			i = len(sim.Indices) - 1
		}
		ix := &sim.Indices[i]
		if !slices.Contains(ix.RestoredFrom, man.ID) {
			ix.RestoredFrom = append(slices.Clone(ix.RestoredFrom), man.ID)
			// A day whose archive was written but whose index was not
			// deleted is still in OpenSearch: restoring it adds nothing.
			if ix.UUID == "" || ix.UUID != man.IndexUUID {
				ix.Bytes += man.IndexBytes
				ix.PrimaryBytes += man.IndexBytes
				ix.Docs += man.Docs
				chk.Bytes += man.IndexBytes
				if sim.NodeBytes != nil {
					sim.NodeBytes[man.Index] += man.IndexBytes
				}
			}
		}
		ix.RestoredUntil = until
	}
	if d := st.snap.Disk; d != nil {
		after := *d
		after.Available = max(after.Available-chk.Bytes, 0)
		sim.Disk = &after
		chk.Disk = d
		chk.PercentAfter = roundPercent(after.Percent())
		chk.Flood = after.Percent() >= FloodPercent && d.Percent() < FloodPercent
		chk.OverLimit = s.Guard.IsEnabled() && chk.Bytes > 0 && after.Percent() > float64(s.Guard.MaxDiskPercent)
	}
	plan := PlanIndices(sim, s)
	chk.Guard = plan.Guard
	was := map[string]bool{}
	for _, d := range before.Steps() {
		was[d.Index] = d.Removes()
	}
	for _, d := range plan.Steps() {
		if d.Removes() && !was[d.Index] {
			chk.Steps = append(chk.Steps, d)
			if d.Action != ActionArchive {
				chk.Unarchived++
			}
		}
	}
	chk.Deletes = Summarize(chk.Steps, nil)
	chk.NeedsConfirm = chk.Flood || chk.OverLimit || len(chk.Steps) > 0
	switch {
	case chk.Flood:
		chk.Message = fmt.Sprintf("Restoring %s (%s) could fill OpenSearch's disk to %.0f%%. At %d%% it stops taking new events. Free space first, or restore fewer days.",
			days(len(mans)), sizeString(chk.Bytes), chk.PercentAfter, FloodPercent)
	case len(chk.Steps) > 0:
		chk.Message = fmt.Sprintf("Restoring %s (%s) takes the disk to about %.0f%%, above the %d%% disk guard, so the next run deletes %s of live data (%s) to make room",
			days(len(mans)), sizeString(chk.Bytes), chk.PercentAfter, s.Guard.MaxDiskPercent, days(chk.Deletes.DeleteDays), sizeString(chk.Deletes.DeleteBytes))
		if chk.Unarchived > 0 {
			verb := "are"
			if chk.Unarchived == 1 {
				verb = "is"
			}
			chk.Message += fmt.Sprintf("; %d of them %s not archived and can't be brought back", chk.Unarchived, verb)
		}
		chk.Message += "."
	case chk.OverLimit:
		chk.Message = fmt.Sprintf("Restoring %s (%s) takes the disk to about %.0f%%, above the %d%% disk guard, and the guard can't free enough to get back under it. Free space first, or restore fewer days.",
			days(len(mans)), sizeString(chk.Bytes), chk.PercentAfter, s.Guard.MaxDiskPercent)
	}
	return chk, nil
}

// Restore queues archived days to be restored in the background, one
// after another and never during a run. Each stays searchable for
// keepDays (0 means DefaultRestoreDays) before retention may delete it
// again. Unless confirm is set, a restore that would make the disk guard
// delete live days, or fill the disk, is refused with a ConfirmError.
func (m *Manager) Restore(ctx context.Context, ids []string, keepDays int, by string, confirm bool) ([]RestoreStatus, error) {
	m.init()
	if err := m.readOnly(); err != nil {
		return nil, err
	}
	mans, keepDays, err := m.restoreManifests(ids, keepDays)
	if err != nil {
		return nil, err
	}
	if !confirm {
		chk, err := m.CheckRestore(ctx, ids, keepDays)
		if err != nil {
			return nil, err
		}
		if chk.NeedsConfirm {
			return nil, &ConfirmError{Check: chk}
		}
	}
	m.mu.Lock()
	for _, r := range m.restores {
		if (r.State == RestoreQueued || r.State == RestoreRunning) && slices.ContainsFunc(mans, func(x Manifest) bool { return x.ID == r.ID }) {
			m.mu.Unlock()
			return nil, fmt.Errorf("%s is already being restored", r.ID)
		}
	}
	until := startOfDay(m.now()).AddDate(0, 0, keepDays).Format(time.DateOnly)
	var sts []*RestoreStatus
	for _, man := range mans {
		st := &RestoreStatus{ID: man.ID, Index: man.Index, Category: man.Category, Day: man.Day, State: RestoreQueued,
			Docs: man.Docs, KeepUntil: until, By: by, Queued: m.now()}
		sts = append(sts, st)
		m.restores = append(m.restores, st)
	}
	if n := len(m.restores) - maxRestores; n > 0 {
		m.restores = slices.Delete(m.restores, 0, n)
	}
	out := make([]RestoreStatus, len(sts))
	for i, st := range sts {
		out[i] = *st
	}
	m.mu.Unlock()
	m.saveJobs()

	go func() {
		m.job.Lock()
		defer m.release()
		m.setCurrent("restore")
		defer m.setCurrent("")
		ctx := m.ctx()
		for i, man := range mans {
			st := sts[i]
			m.updateRestore(st, func(r *RestoreStatus) { r.State = RestoreRunning })
			n, err := m.RestoreArchive(ctx, man, until, func(done int64) {
				m.updateRestore(st, func(r *RestoreStatus) { r.Restored = done })
			})
			act := Action{Time: m.now(), Action: ActionRestore, Category: man.Category, Index: man.Index, Day: man.Day,
				Docs: n, File: man.File, By: by, Reason: "Restored from the archive; searchable until " + until}
			m.updateRestore(st, func(r *RestoreStatus) {
				now := m.now()
				r.Finished, r.Restored = &now, n
				r.State = RestoreDone
				if err != nil {
					r.State, r.Error = RestoreFailed, err.Error()
				}
			})
			if err != nil {
				act.Error = err.Error()
			}
			m.record(nil, act)
		}
	}()
	return out, nil
}

// RestoreArchive writes one archived day back into its index, which makes
// it searchable again, and marks the index so retention keeps it until
// the day given (YYYY-MM-DD). The file is checked in full first, so a
// damaged archive restores nothing. Restoring twice does not duplicate
// events. progress, when set, is called with the events restored so far.
func (m *Manager) RestoreArchive(ctx context.Context, man Manifest, until string, progress func(int64)) (int64, error) {
	m.init()
	if err := m.Archive.Verify(man); err != nil {
		return 0, fmt.Errorf("the archive file failed its check, so nothing was restored: %w", err)
	}
	if err := m.step(ctx, man.Index, ActionRestore); err != nil {
		return 0, err
	}
	if err := m.Cluster.CreateIndex(ctx, man.Index); err != nil {
		return 0, fmt.Errorf("could not create %s: %w", man.Index, err)
	}
	// A compacted index that came back with late events is read-only.
	if err := m.Cluster.BlockWrites(ctx, man.Index, false); err != nil {
		return 0, fmt.Errorf("could not make %s writable: %w", man.Index, err)
	}
	// Mark first, so a run that starts meanwhile keeps the index. The mark
	// also names every archive restored into the index, so retention knows
	// the archive holds its events and does not archive them again.
	from := []string{man.ID}
	if cur, err := m.Cluster.Indices(ctx, man.Index); err == nil && len(cur) == 1 {
		for _, id := range cur[0].RestoredFrom {
			if !slices.Contains(from, id) {
				from = append(from, id)
			}
		}
		slices.Sort(from)
	}
	if err := m.Cluster.MarkRestored(ctx, man.Index, until, from); err != nil {
		return 0, fmt.Errorf("could not mark %s as restored: %w", man.Index, err)
	}
	var done, size int64
	batch := make([]Doc, 0, importBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := m.Cluster.Import(ctx, man.Index, batch); err != nil {
			return err
		}
		done += int64(len(batch))
		batch, size = batch[:0], 0
		if progress != nil {
			progress(done)
		}
		return nil
	}
	err := m.Archive.Read(man, func(d Doc) error {
		batch = append(batch, d)
		size += int64(len(d.Source))
		if len(batch) >= importBatch || size >= importBytes {
			return flush()
		}
		return ctx.Err()
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		return done, fmt.Errorf("restored %d of %d events, then: %w; restoring again finishes the job without duplicates", done, man.Docs, err)
	}
	if err := m.Cluster.Refresh(ctx, man.Index); err != nil {
		return done, err
	}
	return done, nil
}

// WaitRestores waits until none of the archives ids is queued or being
// restored by this server, and returns their latest statuses. progress,
// when set, is called with the events restored so far and in all.
func (m *Manager) WaitRestores(ctx context.Context, ids []string, progress func(done, total int64)) ([]RestoreStatus, error) {
	m.init()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		latest := map[string]RestoreStatus{}
		for _, r := range m.restoreStatuses() {
			if _, ok := latest[r.ID]; !ok && slices.Contains(ids, r.ID) {
				latest[r.ID] = r
			}
		}
		var done, total int64
		busy := false
		out := make([]RestoreStatus, 0, len(latest))
		for _, id := range ids {
			r, ok := latest[id]
			if !ok {
				continue
			}
			out = append(out, r)
			done, total = done+r.Restored, total+r.Docs
			busy = busy || r.State == RestoreQueued || r.State == RestoreRunning
		}
		if progress != nil {
			progress(done, total)
		}
		if !busy {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-tick.C:
		}
	}
}
