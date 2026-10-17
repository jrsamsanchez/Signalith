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
	Log     *slog.Logger
	// Resume is called each time the leader's own scheduler may run the
	// tenant's rules again, before LeaderRuns turns true: it drops the
	// scheduler's copy of the run state, so the scheduler takes a fresh
	// detection epoch, bigger than the buckets' ones.
	Resume func()

	mu         sync.Mutex
	leaderRuns bool
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

// owners works out who should own each bucket: nobody when spreading is
// off or no server may run the tenant.
func (a *Assigner) owners(on bool) []string {
	out := make([]string, Buckets)
	if !on {
		return out
	}
	servers := a.Servers()
	var mine string
	for _, s := range servers {
		if s.ID == a.Self {
			mine = s.Fingerprint
		}
	}
	var ids []string
	for _, s := range servers {
		if !s.Live || !s.Spread || !s.Eligible || s.Fingerprint == "" || s.Fingerprint != mine || s.ClockOffsetMS == nil {
			continue
		}
		if off := time.Duration(*s.ClockOffsetMS) * time.Millisecond; off > MaxSpreadSkew || off < -MaxSpreadSkew {
			continue
		}
		ids = append(ids, s.ID)
	}
	if len(ids) == 0 {
		return out
	}
	for b := range out {
		out[b] = Rendezvous(ids, a.Tenant, b)
	}
	return out
}

// spreadWanted reports whether spreading is wanted and every live server
// can take part: while one cannot, the leader runs every rule itself.
func (a *Assigner) spreadWanted() bool {
	if a.On == nil || !a.On() {
		return false
	}
	for _, s := range a.Servers() {
		if s.Live && !s.Spread {
			return false
		}
	}
	return true
}

// Step brings the tenant's assignment document up to date.
func (a *Assigner) Step(ctx context.Context) error {
	if a.Allowed != nil && !a.Allowed() {
		return nil
	}
	lease := a.Lease()
	on := a.spreadWanted()
	want := a.owners(on)
	spread := slices.ContainsFunc(want, func(n string) bool { return n != "" })
	if spread {
		// The leader's own scheduler stops before buckets are handed out,
		// so it takes no new detection epoch above theirs.
		a.setLeaderRuns(false)
	}
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
	next := &Assignment{Kind: kindDetAssign, Tenant: a.Tenant, LeaseEpoch: lease, Owners: make([]BucketOwner, Buckets)}
	var moved []int
	for b, node := range want {
		switch {
		case node == "":
		case cur != nil && cur.Owners[b].Node == node && cur.Owners[b].State == BucketRun:
			next.Owners[b] = cur.Owners[b]
		default:
			moved = append(moved, b)
		}
	}
	if len(moved) > 0 {
		first, err := claimEpochs(ctx, a.Runtime, a.RuntimeIndex, lease, a.Self, a.now(), len(moved))
		if err != nil {
			return err
		}
		for i, b := range moved {
			next.Owners[b] = BucketOwner{Node: want[b], DetEpoch: first + int64(i), State: BucketRun}
		}
	}
	if cur != nil && cur.LeaseEpoch == lease && slices.Equal(cur.Owners, next.Owners) || !found && !spread {
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
	runs   map[int]int64
	readAt time.Duration
	read   bool
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
	runs := map[int]int64{}
	if found {
		a, err := DecodeAssignment(raw, f.Tenant)
		if err != nil {
			f.set(runs, sent)
			return err
		}
		runs = a.RunsOn(f.Self)
	}
	f.set(runs, sent)
	return nil
}

func (f *Follower) set(runs map[int]int64, at time.Duration) {
	f.mu.Lock()
	f.runs, f.readAt, f.read = runs, at, true
	f.mu.Unlock()
}

// Owned returns the buckets this server runs, with their detection
// epochs, while the last good read is recent enough.
func (f *Follower) Owned() (map[int]int64, bool) {
	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultFollowMaxAge
	}
	now := f.mono()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.read || now-f.readAt >= maxAge {
		return nil, false
	}
	return f.runs, true
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
