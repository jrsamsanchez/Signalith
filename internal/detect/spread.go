package detect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// SpreadServer is a server as the Assigner sees it.
type SpreadServer struct {
	ID string
	// Spread: its version runs assigned buckets. Eligible: it may run
	// background work. Live: its heartbeat is current.
	Spread, Eligible, Live bool
	// Fingerprint is its fingerprint of this tenant's detection files,
	// "" when it does not run the tenant.
	Fingerprint string
	// ClockOffsetMS is OpenSearch's clock minus its own; nil when not
	// measured.
	ClockOffsetMS *int64
	// Released is, per bucket of this tenant it is handing over and has
	// no run of in flight, the detection epoch it held it under.
	Released map[int]int64
}

// MaxSpreadSkew is how far a server's clock may be from OpenSearch's for
// it to be given buckets.
const MaxSpreadSkew = 2 * time.Second

// Assigner keeps one tenant's assignment document, on the server running
// the background jobs. Each Step decides whether the tenant's detections
// are spread, and if so gives each bucket to its rendezvous owner among
// the servers that may run it, with a fresh detection epoch whenever a
// bucket changes hands.
type Assigner struct {
	Tenant       string
	Runtime      RunStore
	RuntimeIndex string
	// Self is this server's node ID; Lease the job lease epoch it holds,
	// and Allowed whether it still holds it.
	Self    string
	Lease   func() int64
	Allowed func() bool
	// On says whether spreading is wanted (detections.spread, at a cluster
	// level with the detection epoch counter).
	On func() bool
	// Servers returns this server and the others, this tenant's
	// fingerprints filled in.
	Servers func() []SpreadServer
	Now     func() time.Time
	// Budget, when set, is the cluster's detection search budget, written
	// in the assignment while the detections are spread.
	Budget func(ctx context.Context) int
	// Mono is a monotonic clock for MoveTimeout and JoinDelay;
	// time.Since when nil.
	Mono func() time.Duration
	// MoveTimeout and JoinDelay: DefaultMoveTimeout and DefaultJoinDelay
	// when zero.
	MoveTimeout, JoinDelay time.Duration
	Log                    *slog.Logger
	// Resume is called each time the leader's own scheduler may run the
	// tenant's rules again, before LeaderRuns turns true: it drops the
	// scheduler's copy of the run state, so the scheduler takes a fresh
	// detection epoch, bigger than the buckets' ones.
	Resume func()

	mu         sync.Mutex
	leaderRuns bool
	// Step's own: when each bucket being handed over started to be, and
	// since when each server could run buckets. Only Run's goroutine
	// steps.
	movingSince map[int]time.Duration
	liveSince   map[string]time.Duration
}

// LeaderRuns reports whether the leader's own scheduler may run the
// tenant's rules: only once an assignment without owners is in place.
// It turns false before the first assignment with owners is written,
// and when Run stops.
func (a *Assigner) LeaderRuns() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.leaderRuns
}

func (a *Assigner) setLeaderRuns(on bool) {
	a.mu.Lock()
	was := a.leaderRuns
	if !on {
		a.leaderRuns = false
	}
	a.mu.Unlock()
	if on && !was {
		if a.Resume != nil {
			a.Resume()
		}
		a.mu.Lock()
		a.leaderRuns = true
		a.mu.Unlock()
	}
}

func (a *Assigner) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run steps every tick until ctx ends; it is a job of the server running
// the background jobs. When it stops, the next holder's Assigner picks
// the assignment up from the document.
func (a *Assigner) Run(ctx context.Context, tick time.Duration) {
	defer a.setLeaderRuns(false)
	for {
		if err := a.Step(ctx); err != nil && ctx.Err() == nil {
			a.log().Warn("could not update the assignment of detections to servers", "tenant", a.Tenant, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
	}
}

// Default timings of graceful moves (see Assigner).
const (
	// DefaultMoveTimeout is how long a bucket being handed over waits for
	// its owner to release it before it moves anyway: longer than the
	// longest run (MaxRunTimeout) plus the fence time, so any run the
	// owner started has ended or fenced itself off by then.
	DefaultMoveTimeout = MaxRunTimeout + DefaultFollowMaxAge + 40*time.Second
	// DefaultJoinDelay is how long a server must stay able to run buckets
	// before it is given new ones, so one that starts and stops again
	// does not move buckets back and forth.
	DefaultJoinDelay = time.Minute
)

func (a *Assigner) mono() time.Duration {
	if a.Mono != nil {
		return a.Mono()
	}
	return time.Since(monoStart)
}

// candidate reports whether s may run the tenant's buckets now, given
// mine, the job holder's own fingerprint.
func candidate(s SpreadServer, mine string) bool {
	if !s.Live || !s.Spread || !s.Eligible || s.Fingerprint == "" || s.Fingerprint != mine || s.ClockOffsetMS == nil {
		return false
	}
	off := time.Duration(*s.ClockOffsetMS) * time.Millisecond
	return off <= MaxSpreadSkew && off >= -MaxSpreadSkew
}

// owners works out who should own each bucket: nobody when spreading is
// off or no server may run the tenant. A server that became able to run
// buckets less than JoinDelay ago gets none unless it already holds some.
func (a *Assigner) owners(on bool, servers []SpreadServer, cur *Assignment, now time.Duration) []string {
	out := make([]string, Buckets)
	var mine string
	for _, s := range servers {
		if s.ID == a.Self {
			mine = s.Fingerprint
		}
	}
	join := a.JoinDelay
	if join <= 0 {
		join = DefaultJoinDelay
	}
	// On the first step, the servers already able to run buckets count
	// as having been for long: this Assigner just could not see them yet.
	first := a.liveSince == nil
	seen := map[string]time.Duration{}
	var ids []string
	for _, s := range servers {
		if !candidate(s, mine) {
			continue
		}
		since, ok := a.liveSince[s.ID]
		switch {
		case first:
			since = now - join
		case !ok:
			since = now
		}
		seen[s.ID] = since
		holds := cur != nil && len(cur.Holds(s.ID)) > 0
		if now-since >= join || holds {
			ids = append(ids, s.ID)
		}
	}
	a.liveSince = seen
	if !on || len(ids) == 0 {
		return out
	}
	for b := range out {
		out[b] = Rendezvous(ids, a.Tenant, b)
	}
	return out
}

// spreadWanted reports whether spreading is wanted and every live server
// can take part: while one cannot, the leader runs every rule itself.
func (a *Assigner) spreadWanted(servers []SpreadServer) bool {
	if a.On == nil || !a.On() {
		return false
	}
	for _, s := range servers {
		if s.Live && !s.Spread {
			return false
		}
	}
	return true
}

// Step brings the tenant's assignment document up to date. A bucket
// whose owner is live is handed over gracefully: it is marked moving, the
// owner starts no new slot of it, and once the owner's heartbeat says it
// released it (no run of it in flight), or MoveTimeout passed, it goes to
// its new owner under a fresh detection epoch. A bucket whose owner is
// gone moves at once, as does every bucket when spreading turns off (the
// leader's scheduler then takes a bigger epoch than all of them).
func (a *Assigner) Step(ctx context.Context) error {
	if a.Allowed != nil && !a.Allowed() {
		return nil
	}
	lease := a.Lease()
	id := AssignmentID(a.Tenant)
	raw, ver, found, err := a.Runtime.Get(ctx, a.RuntimeIndex, id)
	if err != nil {
		return fmt.Errorf("could not read the assignment: %w", err)
	}
	var cur *Assignment
	if found {
		if cur, err = DecodeAssignment(raw, a.Tenant); err != nil {
			a.log().Warn("the assignment of detections to servers cannot be used; it is written again", "tenant", a.Tenant, "err", err)
			cur = nil
		} else if cur.LeaseEpoch > lease {
			a.setLeaderRuns(false)
			return fmt.Errorf("%w (a newer holder wrote the assignment)", ErrNotAllowed)
		}
	}
	servers := a.Servers()
	byID := map[string]SpreadServer{}
	for _, s := range servers {
		byID[s.ID] = s
	}
	now := a.mono()
	want := a.owners(a.spreadWanted(servers), servers, cur, now)
	spread := slices.ContainsFunc(want, func(n string) bool { return n != "" })
	if spread {
		// The leader's own scheduler stops before buckets are handed out,
		// so it takes no new detection epoch above theirs.
		a.setLeaderRuns(false)
	}
	timeout := a.MoveTimeout
	if timeout <= 0 {
		timeout = DefaultMoveTimeout
	}
	if a.movingSince == nil {
		a.movingSince = map[int]time.Duration{}
	}
	next := &Assignment{Kind: kindDetAssign, Tenant: a.Tenant, LeaseEpoch: lease, Owners: make([]BucketOwner, Buckets)}
	var moved []int
	for b, node := range want {
		var o BucketOwner
		if cur != nil {
			o = cur.Owners[b]
		}
		owner, live := byID[o.Node]
		switch {
		case node == "":
			// Spreading is off, or nobody may run the tenant.
		case o.Node == "":
			moved = append(moved, b)
		case o.Node == node && o.State == BucketMoving:
			// The move is no longer wanted: the owner keeps the bucket under
			// a fresh epoch, so a release of the old one, still in its
			// heartbeat, cannot end a later move while it runs slots again.
			moved = append(moved, b)
		case o.Node == node:
			next.Owners[b] = BucketOwner{Node: o.Node, DetEpoch: o.DetEpoch, State: BucketRun}
		case !live || !owner.Live:
			// Its owner is gone: nothing to wait for.
			moved = append(moved, b)
		case o.State == BucketMoving && (owner.Released[b] == o.DetEpoch || a.waited(b, now) >= timeout):
			moved = append(moved, b)
		default:
			a.waited(b, now)
			next.Owners[b] = BucketOwner{Node: o.Node, DetEpoch: o.DetEpoch, State: BucketMoving, To: node}
		}
	}
	for b := range a.movingSince {
		if next.Owners[b].State != BucketMoving {
			delete(a.movingSince, b)
		}
	}
	if len(moved) > 0 {
		first, err := claimEpochs(ctx, a.Runtime, a.RuntimeIndex, lease, a.Self, a.now(), len(moved))
		if err != nil {
			return err
		}
		for i, b := range moved {
			next.Owners[b] = BucketOwner{Node: want[b], DetEpoch: first + int64(i), State: BucketRun}
			delete(a.movingSince, b)
		}
	}
	if spread && a.Budget != nil {
		next.SearchBudget = min(max(a.Budget(ctx), 0), MaxSearchBudget)
	}
	if cur != nil && cur.LeaseEpoch == lease && cur.SearchBudget == next.SearchBudget && slices.Equal(cur.Owners, next.Owners) || !found && !spread {
		// Nothing to write (and no document is made while nothing was
		// ever spread).
		if !spread {
			a.setLeaderRuns(true)
		}
		return nil
	}
	if a.Allowed != nil && !a.Allowed() {
		return nil
	}
	if found {
		_, err = a.Runtime.PutIf(ctx, a.RuntimeIndex, id, next, ver, true)
	} else {
		_, err = a.Runtime.Create(ctx, a.RuntimeIndex, id, next, true)
	}
	if err != nil {
		if store.IsConflict(err) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("the assignment changed while it was written; trying again")
		}
		return fmt.Errorf("could not write the assignment: %w", err)
	}
	if len(moved) > 0 {
		a.log().Info("detection buckets assigned to servers", "tenant", a.Tenant, "moved", len(moved), "servers", len(owners(next)))
	}
	if !spread {
		// No owners any more: the leader runs every rule again.
		a.setLeaderRuns(true)
	}
	return nil
}

// waited returns how long bucket b has been being handed over, as this
// Assigner saw it (from now, the first time).
func (a *Assigner) waited(b int, now time.Duration) time.Duration {
	since, ok := a.movingSince[b]
	if !ok {
		a.movingSince[b] = now
		return 0
	}
	return now - since
}

func (a *Assigner) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// owners lists the servers owning buckets in a.
func owners(a *Assignment) []string {
	var out []string
	for _, o := range a.Owners {
		if o.Node != "" && !slices.Contains(out, o.Node) {
			out = append(out, o.Node)
		}
	}
	return out
}

// Follower reads, on every server, the tenant's assignment document, and
// tells the server's spread scheduler which buckets it runs (Owned). A
// server that could not read the document for MaxAge runs none: it may
// have been cut off while its buckets moved on.
type Follower struct {
	Tenant       string
	Self         string
	Runtime      RunStore
	RuntimeIndex string
	// MaxAge is how long a read stays good (the fence time, 20 seconds,
	// when zero).
	MaxAge time.Duration
	// Mono is a monotonic clock; time.Since when nil.
	Mono func() time.Duration
	Log  *slog.Logger

	mu     sync.Mutex
	holds  map[int]int64
	moving map[int]bool
	share  SpreadShare
	readAt time.Duration
	read   bool
}

// SpreadShare is a server's part of a tenant's buckets: how many it runs
// (Mine) of those assigned (Assigned), and the cluster search budget.
type SpreadShare struct {
	Mine, Assigned, Budget int
}

// DefaultFollowMaxAge is Follower.MaxAge when zero.
const DefaultFollowMaxAge = 20 * time.Second

var monoStart = time.Now()

func (f *Follower) mono() time.Duration {
	if f.Mono != nil {
		return f.Mono()
	}
	return time.Since(monoStart)
}

// Read reads the assignment document again. A document that cannot be
// read, or fails its checks, gives no buckets.
func (f *Follower) Read(ctx context.Context) error {
	sent := f.mono()
	raw, _, found, err := f.Runtime.Get(ctx, f.RuntimeIndex, AssignmentID(f.Tenant))
	if err != nil {
		return err
	}
	holds, moving := map[int]int64{}, map[int]bool{}
	var share SpreadShare
	if found {
		a, err := DecodeAssignment(raw, f.Tenant)
		if err != nil {
			f.set(holds, moving, share, sent)
			return err
		}
		holds = a.Holds(f.Self)
		for b := range holds {
			moving[b] = a.Owners[b].State == BucketMoving
		}
		share = SpreadShare{Mine: len(a.RunsOn(f.Self)), Budget: a.SearchBudget}
		for _, o := range a.Owners {
			if o.Node != "" && o.State == BucketRun {
				share.Assigned++
			}
		}
	}
	f.set(holds, moving, share, sent)
	return nil
}

func (f *Follower) set(holds map[int]int64, moving map[int]bool, share SpreadShare, at time.Duration) {
	f.mu.Lock()
	f.holds, f.moving, f.share, f.readAt, f.read = holds, moving, share, at, true
	f.mu.Unlock()
}

// Share returns this server's part of the tenant's buckets, while the
// last good read is recent enough.
func (f *Follower) Share() (SpreadShare, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.fresh() {
		return SpreadShare{}, false
	}
	return f.share, true
}

// PoolSize is how many workers a server's shared pool gets from its
// shares of every tenant it runs: its part of the search budget, at least
// one. DefaultPoolSize while no share says the budget.
func PoolSize(shares []SpreadShare) int {
	mine, assigned, budget := 0, 0, 0
	for _, s := range shares {
		mine, assigned, budget = mine+s.Mine, assigned+s.Assigned, max(budget, s.Budget)
	}
	if budget <= 0 || assigned <= 0 {
		return DefaultPoolSize
	}
	return min(max((budget*mine+assigned-1)/assigned, 1), budget)
}

// fresh reports whether the last good read is recent enough; f.mu held.
func (f *Follower) fresh() bool {
	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultFollowMaxAge
	}
	return f.read && f.mono()-f.readAt < maxAge
}

// Owned returns the buckets this server holds, with their detection
// epochs, while the last good read is recent enough: those it runs and
// those it is handing over (Moving), whose runs in flight may finish.
func (f *Follower) Owned() (map[int]int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.fresh() {
		return nil, false
	}
	return f.holds, true
}

// Moving reports whether this server is handing bucket b over.
func (f *Follower) Moving(b int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.moving[b]
}

// Released returns the buckets this server is handing over and has no
// run of in flight (busy reports one), with their detection epochs: its
// heartbeat says so, and the server running the background jobs then
// gives them to their new owner without waiting longer.
func (f *Follower) Released(busy func(bucket int) bool) map[int]int64 {
	f.mu.Lock()
	var mv []int
	if f.fresh() {
		for b, m := range f.moving {
			if m {
				mv = append(mv, b)
			}
		}
	}
	holds := f.holds
	f.mu.Unlock()
	out := map[int]int64{}
	for _, b := range mv {
		if !busy(b) {
			out[b] = holds[b]
		}
	}
	return out
}

// Run reads the document every tick until ctx ends.
func (f *Follower) Run(ctx context.Context, tick time.Duration) {
	for {
		if err := f.Read(ctx); err != nil && ctx.Err() == nil {
			l := f.Log
			if l == nil {
				l = slog.New(slog.DiscardHandler)
			}
			l.Warn("could not read which detections this server runs", "tenant", f.Tenant, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
	}
}
