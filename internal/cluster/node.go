package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Options are what a Node needs.
type Options struct {
	Local   *Local
	Version string
	// Deployment says how the server runs: systemd, docker,
	// windows-service, or "".
	Deployment string
	Clock      Clock
	Timing     Timing
	Log        *slog.Logger
}

// Settings are this server's settings the cluster uses; each start of the
// server's components (an in-process restart too) passes them again.
type Settings struct {
	// Eligible is detections.scheduler: this server may run the
	// background jobs.
	Eligible bool
	NodeURL  string
	Listen   string
	Syslog   Syslog
	// Fingerprints works out the files fingerprints; nil has none.
	Fingerprints func() Fingerprints
}

// Node is this server in the cluster. It lives as long as the process:
// an in-process restart keeps it, with its identity, its lock, its
// heartbeat and its lease, and only points it at the new OpenSearch
// client.
//
// Two loops run: one writes the heartbeat and reads the other servers'
// (with the clock check), the other renews or watches the job lease, so a
// heartbeat that waits for OpenSearch never holds up a renewal. The lease
// stops its jobs at the fence time on a timer of its own.
type Node struct {
	local  *Local
	opts   Options
	clock  Clock
	timing Timing
	log    *slog.Logger
	lease  *Lease

	// hbMu lets one heartbeat write happen at a time.
	hbMu sync.Mutex

	mu       sync.Mutex
	client   *store.Client
	prefix   string
	endpoint string
	settings Settings
	// firstTarget is true until the identity check passed on the first
	// OpenSearch this process used: a conflict there stops the process.
	firstTarget bool
	// probation is true for a while after this process took over the
	// heartbeat of the folder's previous process (a crash restart): if
	// that process writes again, it still runs elsewhere and this folder
	// is a copy, so this process stops. It takes no jobs meanwhile.
	probation    bool
	probationEnd time.Duration
	hb           heartbeatState
	members      map[string]*member
	offset       *time.Duration
	offsetNext   time.Duration
	// fp are the files fingerprints worked out last; fpDone is closed when
	// the one being worked out now is ready (nil when none is).
	fp          Fingerprints
	fpNext      time.Duration
	fpSet       bool
	fpDone      chan struct{}
	fpSlowAt    time.Duration
	fpSlowFirst bool
	started     time.Time
	stopping    bool
	conflict    string
	// copySeen is a process started from a copy of this server's state
	// folder while this one runs, seen at copyAt.
	copySeen *Heartbeat
	copyAt   time.Duration
	// writesRefused is true while OpenSearch refuses writes (a full disk).
	writesRefused bool
	// lastContact is when OpenSearch last answered a heartbeat or a read,
	// and lastRead when the other servers were last read, on the
	// monotonic clock; contacted is false until OpenSearch first answered.
	lastContact time.Duration
	lastRead    time.Duration
	contacted   bool
	osLatency   time.Duration
	// lastErr is why OpenSearch did not take the last heartbeat, and
	// errLogged and errLoggedAt the error logged last, so a failure that
	// goes on is logged once a minute rather than at every try.
	lastErr     string
	lastErrRaw  error
	errLogged   string
	errLoggedAt time.Duration
	releasing   bool
	// paused says why this server's components are not running, so it
	// must not hold the jobs; Use clears it.
	paused string
	// security is this server's last security check, for its heartbeat.
	security SecuritySummary

	wake      chan struct{}
	leaseWake chan struct{}
	fatal     chan error
	cancel    context.CancelFunc
	loopDone  chan struct{}
	leaseDone chan struct{}
	stopOnce  sync.Once
}

// heartbeatState is this server's heartbeat on the current OpenSearch.
type heartbeatState struct {
	// checked is true once the identity check passed and the first
	// heartbeat was written.
	checked bool
	ver     store.Version
	next    time.Duration
}

// member is another server's heartbeat as this one last saw it.
type member struct {
	hb  Heartbeat
	ver store.Version
	// since is when this version was first seen, on the monotonic clock.
	since time.Duration
}

// New returns the node for an open state folder. Start starts it.
func New(o Options) *Node {
	if o.Clock == nil {
		o.Clock = NewRealClock()
	}
	if o.Timing == (Timing{}) {
		o.Timing = DefaultTiming
	}
	if o.Timing.FilesWait == 0 {
		o.Timing.FilesWait = DefaultTiming.FilesWait
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n := &Node{local: o.Local, opts: o, clock: o.Clock, timing: o.Timing, log: o.Log, firstTarget: true,
		members: map[string]*member{}, wake: make(chan struct{}, 1), leaseWake: make(chan struct{}, 1),
		fatal: make(chan error, 1), started: o.Clock.Now().UTC()}
	n.lease = &Lease{
		Self: Self{NodeID: o.Local.Identity.NodeID, Name: o.Local.Identity.Name, Version: o.Version,
			BootID: o.Local.BootID, LastBoot: o.Local.LastBoot},
		Clock: o.Clock, Timing: o.Timing, Log: o.Log,
		Target:        n.leaseTarget,
		Eligible:      n.mayTake,
		Fingerprints:  n.fingerprints,
		Defer:         n.leaveJobs,
		WritesRefused: n.refusingWrites,
		OnChange:      n.poke,
		OnTakeover:    n.tookOver,
	}
	return n
}

// ID and Name are this server's.
func (n *Node) ID() string   { return n.local.Identity.NodeID }
func (n *Node) Name() string { return n.local.Identity.Name }

// Lease returns the job lease, for the fence check before destructive
// steps.
func (n *Node) Lease() *Lease { return n.lease }

// Fatal receives an error when this server must not run at all: another
// running process uses its identity.
func (n *Node) Fatal() <-chan error { return n.fatal }

func (n *Node) leaseTarget() (*store.Client, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client == nil || !n.hb.checked {
		return nil, ""
	}
	return n.client, RuntimeIndex(n.prefix)
}

// poke wakes both loops, to write the heartbeat soon after a change and to
// look at the lease.
func (n *Node) poke() {
	n.mu.Lock()
	n.hb.next = 0
	n.mu.Unlock()
	select {
	case n.wake <- struct{}{}:
	default:
	}
	n.pokeLease()
}

func (n *Node) pokeLease() {
	select {
	case n.leaseWake <- struct{}{}:
	default:
	}
}

// Start starts the heartbeat and lease loops; they end when ctx does or
// at Stop. The jobs run under ctx.
func (n *Node) Start(ctx context.Context) {
	n.mu.Lock()
	if n.loopDone != nil {
		n.mu.Unlock()
		return
	}
	ctx, n.cancel = context.WithCancel(ctx)
	n.loopDone, n.leaseDone = make(chan struct{}), make(chan struct{})
	n.mu.Unlock()
	n.lease.SetBase(ctx)
	go n.loop(ctx)
	go n.leaseLoop(ctx)
}

// Use points the node at an OpenSearch client and index prefix, with this
// server's settings, at each start of its components. When the OpenSearch
// or the prefix changed, the lease held on the old one is given up first,
// and the identity is checked again on the new one.
func (n *Node) Use(c *store.Client, prefix string, s Settings) {
	n.mu.Lock()
	same := n.client != nil && n.prefix == prefix && n.endpoint == c.Endpoint()
	had := n.client != nil
	n.settings, n.paused = s, ""
	if same {
		n.client = c
		n.fpNext = 0
		n.mu.Unlock()
		if !s.Eligible {
			n.releaseAsync("detections.scheduler was turned off on this server")
		}
		n.poke()
		return
	}
	n.mu.Unlock()
	if had {
		n.lease.Release("this server moved to another OpenSearch or index prefix")
	}
	n.hbMu.Lock()
	n.mu.Lock()
	n.client, n.prefix, n.endpoint = c, prefix, c.Endpoint()
	n.hb, n.members, n.fpNext, n.offsetNext = heartbeatState{}, map[string]*member{}, 0, 0
	n.contacted, n.writesRefused, n.offset, n.lastErr, n.lastErrRaw = false, false, nil, "", nil
	if n.conflict != "" && !n.firstTarget {
		// A conflict on the old OpenSearch says nothing about the new one.
		n.conflict = ""
	}
	n.mu.Unlock()
	n.hbMu.Unlock()
	n.lease.Reset()
	n.poke()
}

// Pause gives the background jobs up, and keeps this server from taking
// them again until the next Use: its components could not start. Until
// then its heartbeat says it is down, and lists no syslog listeners,
// since nothing listens on them; its web address still answers, with a
// page that says it is down.
func (n *Node) Pause(why string) {
	n.mu.Lock()
	n.paused = why
	n.settings.Syslog = Syslog{}
	n.mu.Unlock()
	n.releaseAsync(why)
	n.poke()
}

// releaseAsync gives the lease up in the background, once.
func (n *Node) releaseAsync(reason string) {
	n.mu.Lock()
	if n.releasing || !n.lease.Holding() {
		n.mu.Unlock()
		return
	}
	n.releasing = true
	n.mu.Unlock()
	go func() {
		n.lease.Release(reason)
		n.mu.Lock()
		n.releasing = false
		n.mu.Unlock()
	}()
}

// SetSecurity keeps the summary of this server's last security check,
// which its next heartbeat carries.
func (n *Node) SetSecurity(s SecuritySummary) {
	n.mu.Lock()
	n.security = s
	n.mu.Unlock()
}

// SetJobs replaces the background jobs this server runs while it holds
// the lease. It waits for the old ones to end. Housekeeping is added.
func (n *Node) SetJobs(jobs []Job) {
	if jobs != nil {
		jobs = append(jobs, Job{Name: "housekeeping", Run: n.housekeeping})
	}
	n.lease.SetJobs(jobs)
}

// Stop gives the lease up gracefully (waiting for the jobs, at most a
// minute, while the lease loop keeps renewing it), writes a last
// heartbeat saying this server stopped, and stops the loops.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		n.mu.Lock()
		n.stopping = true
		n.mu.Unlock()
		n.lease.Release("the server is stopping")
		n.mu.Lock()
		cancel, done, leaseDone := n.cancel, n.loopDone, n.leaseDone
		n.mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
			<-leaseDone
		}
		n.mu.Lock()
		ok := n.hb.checked && n.conflict == ""
		n.mu.Unlock()
		if ok {
			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			n.writeHeartbeat(ctx, StateStopped)
			cancel()
		}
	})
}

// Close releases the state folder's lock. Call it last, after Stop.
func (n *Node) Close() { n.local.Close() }

func (n *Node) loop(ctx context.Context) {
	defer close(n.loopDone)
	for {
		wait := n.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-n.clock.After(wait):
		case <-n.wake:
		}
	}
}

// leaseLoop renews or watches the job lease, on its own, so nothing else
// this server waits for can delay a renewal.
func (n *Node) leaseLoop(ctx context.Context) {
	defer close(n.leaseDone)
	for {
		wait := n.lease.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-n.clock.After(wait):
		case <-n.leaseWake:
		}
	}
}

// tick does what is due and returns when the next thing is.
func (n *Node) tick(ctx context.Context) time.Duration {
	n.mu.Lock()
	c, prefix, hb, conflict := n.client, n.prefix, n.hb, n.conflict
	n.mu.Unlock()
	if c == nil {
		return time.Hour
	}
	now := n.clock.Mono()
	if !hb.checked {
		if conflict != "" {
			return n.timing.Heartbeat
		}
		if now < hb.next {
			return hb.next - now
		}
		if err := n.firstHeartbeat(ctx, c, prefix); err != nil {
			var ic *identityConflictError
			if errors.As(err, &ic) {
				return n.timing.Heartbeat
			}
			if ctx.Err() == nil {
				n.mu.Lock()
				n.lastErr, n.lastErrRaw = err.Error(), err
				n.hb.next = n.clock.Mono() + n.timing.Retry
				n.mu.Unlock()
				n.logFailure("could not write this server's heartbeat to OpenSearch, so it runs no background jobs; trying again", err)
			}
			return n.timing.Retry
		}
		n.pokeLease()
	}
	n.mu.Lock()
	if n.probation && now >= n.probationEnd {
		// Nobody else wrote this identity's heartbeat meanwhile: this
		// process is the folder's only one.
		n.probation, n.firstTarget = false, false
		n.mu.Unlock()
		n.pokeLease()
		n.mu.Lock()
	}
	due := now >= n.hb.next
	offsetDue := now >= n.offsetNext
	n.mu.Unlock()
	// The files fingerprints are worked out in the background.
	n.fingerprints(false)
	if offsetDue {
		n.measureOffset(ctx, c)
	}
	if due {
		state := StateReady
		n.mu.Lock()
		switch {
		case n.stopping:
			state = StateStopping
		case n.paused != "":
			state = StateDown
		}
		n.mu.Unlock()
		if conflict == "" {
			n.writeHeartbeat(ctx, state)
		} else {
			// Another process uses this identity: this one writes nothing,
			// but still reads the others, so its page stays true.
			n.mu.Lock()
			n.hb.next = n.clock.Mono() + n.timing.Heartbeat
			n.mu.Unlock()
		}
		n.observe(ctx, c, prefix)
	}
	// Give the lease up when this server may no longer hold it, or should
	// leave it to a server whose clock is right.
	if n.lease.Holding() {
		ok, why := n.eligible()
		// Not while OpenSearch refuses writes: nobody could take it, and
		// the disk guard must go on.
		if ok && !n.refusingWrites() {
			if leave, leaveWhy := n.leaveJobs(); leave {
				ok, why = false, leaveWhy
			}
		}
		n.mu.Lock()
		stopping, conflicted := n.stopping, n.conflict != ""
		n.mu.Unlock()
		if !ok && !stopping && !conflicted {
			n.releaseAsync(why)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now = n.clock.Mono()
	next := min(n.hb.next, n.offsetNext, n.fpNext)
	if n.probation {
		next = min(next, n.probationEnd)
	}
	return max(next-now, 10*time.Millisecond)
}

// logFailure logs a failure to reach OpenSearch the first time, then at
// most once a minute while it stays the same.
func (n *Node) logFailure(msg string, err error) {
	n.mu.Lock()
	now := n.clock.Mono()
	quiet := err.Error() == n.errLogged && now-n.errLoggedAt < time.Minute
	if !quiet {
		n.errLogged, n.errLoggedAt = err.Error(), now
	}
	n.mu.Unlock()
	if !quiet {
		if hint := store.Hint(err); hint != "" {
			n.log.Warn(msg, "err", err, "fix", hint)
		} else {
			n.log.Warn(msg, "err", err)
		}
	}
}

// identityConflictError is another live process using this server's
// identity.
type identityConflictError struct{ msg string }

func (e *identityConflictError) Error() string { return e.msg }

// firstHeartbeat checks, on an OpenSearch this process has not written
// to yet, that no other live process uses this server's identity, then
// writes the first heartbeat.
func (n *Node) firstHeartbeat(ctx context.Context, c *store.Client, prefix string) error {
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	if err := ensureRuntime(ctx, c, prefix); err != nil {
		return err
	}
	if err := ensureRuntimeTemplate(ctx, c, prefix); err != nil && ctx.Err() == nil {
		n.log.Warn("could not save the index template of the runtime index; if someone deletes that index while Signalith runs, OpenSearch makes it again with its own settings", "err", err)
	}
	index := RuntimeIndex(prefix)
	id := nodeDocID(n.ID())
	for range 3 {
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		src, ver, found, err := c.Get(rctx, index, id)
		cancel()
		if err != nil {
			return err
		}
		probation := false
		if found {
			var other Heartbeat
			_ = json.Unmarshal(src, &other)
			switch {
			case other.BootID != "" && other.BootID != n.local.BootID && other.BootID != n.local.LastBoot:
				// Written by a process that was not this folder's last: a
				// copy of the folder, alive or not. Watch it.
				live, err := n.watchIdentity(ctx, c, index, id, ver)
				if err != nil {
					return err
				}
				if live != nil {
					return n.identityConflict(live)
				}
				n.log.Warn("found a heartbeat of this server's identity from another process; it no longer changes, so it was a stale copy",
					"other_boot", other.BootID, "other_name", other.Name)
			case other.BootID != "" && other.BootID == n.local.LastBoot && other.State != StateStopped:
				// The folder's previous process did not stop cleanly: it
				// crashed, or this folder is a copy of a running server's.
				// This one starts now, and stops if that process writes
				// again.
				probation = true
			}
		}
		if err := n.local.WriteLastBoot(); err != nil {
			n.log.Warn("could not record this process in the state folder", "err", err)
		}
		doc := n.heartbeatDoc(StateStarting)
		rctx, cancel = context.WithTimeout(ctx, requestTimeout)
		sent := n.clock.Mono()
		var nv store.Version
		if found {
			nv, err = c.PutIf(rctx, index, id, doc, ver, false)
		} else {
			nv, err = c.Create(rctx, index, id, doc, false)
		}
		cancel()
		if store.IsConflict(err) {
			// It changed between the read and the write: look again.
			continue
		}
		if store.IsClusterBlock(err) {
			// OpenSearch's disk is full: nobody can write, so nobody else
			// can be using this identity's heartbeat either.
			n.mu.Lock()
			n.writesRefused, n.contacted, n.lastContact, n.lastRead = true, true, n.clock.Mono(), n.clock.Mono()
			n.hb = heartbeatState{checked: true, ver: ver, next: n.clock.Mono() + n.timing.Heartbeat}
			n.firstTarget, n.lastErr, n.lastErrRaw = false, "", nil
			n.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}
		n.mu.Lock()
		// The next heartbeat, at once, says it is ready, and the other
		// servers are read with it.
		n.hb = heartbeatState{checked: true, ver: nv, next: n.clock.Mono()}
		n.contacted, n.lastContact, n.osLatency, n.lastErr, n.lastErrRaw, n.writesRefused = true, n.clock.Mono(), n.clock.Mono()-sent, "", nil, false
		n.lastRead = n.clock.Mono()
		if probation {
			n.probation, n.probationEnd = true, n.clock.Mono()+n.timing.Heartbeat+n.timing.IdentityWatch
		} else {
			n.firstTarget = false
		}
		n.errLogged = ""
		n.mu.Unlock()
		n.log.Info("this server joined the servers that share its OpenSearch", "node_id", n.ID(), "index", index)
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	src, _, _, _ := c.Get(rctx, index, id)
	var other Heartbeat
	_ = json.Unmarshal(src, &other)
	return n.identityConflict(&other)
}

// watchIdentity watches a heartbeat of this identity for IdentityWatch
// and returns it when it changed: another live process writes it.
func (n *Node) watchIdentity(ctx context.Context, c *store.Client, index, id string, ver store.Version) (*Heartbeat, error) {
	end := n.clock.Mono() + n.timing.IdentityWatch
	for {
		left := end - n.clock.Mono()
		if left <= 0 {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.clock.After(min(n.timing.Watch, left)):
		}
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		src, now, found, err := c.Get(rctx, index, id)
		cancel()
		if err != nil {
			return nil, err
		}
		if found && !now.Same(ver) {
			var hb Heartbeat
			_ = json.Unmarshal(src, &hb)
			if hb.BootID != n.local.BootID {
				return &hb, nil
			}
		}
	}
}

// identityConflict handles another live process with this identity. On
// the first OpenSearch this process uses, it must not start at all;
// later, it stops its jobs and says why until someone fixes it.
func (n *Node) identityConflict(other *Heartbeat) error {
	where := other.Name
	if other.NodeURL != "" {
		where += ", " + other.NodeURL
	}
	msg := fmt.Sprintf("Another server (%s) is using this server's identity: its state folder was copied (a cloned computer?) or is shared. %s",
		where, n.newIdentityHowTo())
	n.mu.Lock()
	first := n.firstTarget
	n.conflict = msg
	n.mu.Unlock()
	n.log.Error(msg)
	err := &identityConflictError{msg: msg}
	if first {
		select {
		case n.fatal <- err:
		default:
		}
	}
	n.lease.Abandon("another process uses this server's identity")
	return err
}

// newIdentityHowTo says how to give this server a new identity.
func (n *Node) newIdentityHowTo() string {
	if n.opts.Deployment == "docker" {
		return "To give this server a new identity, stop it (docker compose stop signalith), delete node.id from its data volume " +
			"(docker run --rm -v <volume>:/d busybox rm /d/node.id, where docker volume ls shows the volume, such as docker_signalith-data), " +
			"then start it again (docker compose up -d)."
	}
	return fmt.Sprintf("To give this server a new identity, stop it, delete %s and start it again.", filepath.Join(n.local.Dir, nodeFile))
}

// heartbeatDoc is this server's heartbeat as it is now.
func (n *Node) heartbeatDoc(state string) Heartbeat {
	eligible, why := n.eligible()
	view := n.lease.View()
	n.mu.Lock()
	defer n.mu.Unlock()
	hb := Heartbeat{Kind: "node", NodeID: n.ID(), Name: n.Name(), BootID: n.local.BootID, PrevBoot: n.local.LastBoot, State: state,
		Version: n.opts.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Deployment: n.opts.Deployment,
		StartedAt: n.started, HeartbeatAt: n.clock.Now().UTC(), NodeURL: n.settings.NodeURL, Listen: n.settings.Listen,
		Syslog: n.settings.Syslog, LeaderEligible: eligible, NotEligible: why, Leader: view.Mine && view.Valid,
		Frozen: view.State == frozen.String(), FilesFingerprint: n.fp, MachineMoved: n.local.Moved, Problems: []string{},
		OpenSearch: OSInfo{OK: n.contacted && n.lastErr == "", Endpoint: n.endpoint, LatencyMS: n.osLatency.Milliseconds()},
		Features:   features}
	if n.lastErr != "" {
		hb.OpenSearch.Problem = store.Problem(n.lastErrRaw)
	}
	if view.Mine {
		hb.LeaseEpoch = view.Doc.Epoch
	}
	if eligible && !view.Mine {
		hb.CannotTakeOver = view.CannotTake
	}
	if n.offset != nil {
		ms := n.offset.Milliseconds()
		hb.ClockOffsetMS = &ms
	}
	sec := n.security
	hb.Security = &sec
	hb.Problems = append(hb.Problems, n.local.Warnings...)
	if n.paused != "" {
		hb.Problems = append(hb.Problems, n.paused+". Its log says why.")
	}
	return hb
}

// writeHeartbeat writes the heartbeat on the version written last.
func (n *Node) writeHeartbeat(ctx context.Context, state string) {
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	n.mu.Lock()
	c, prefix, ver, checked := n.client, n.prefix, n.hb.ver, n.hb.checked
	n.hb.next = n.clock.Mono() + n.timing.Heartbeat
	n.mu.Unlock()
	if c == nil || !checked {
		return
	}
	index, id := RuntimeIndex(prefix), nodeDocID(n.ID())
	doc := n.heartbeatDoc(state)
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	sent := n.clock.Mono()
	var nv store.Version
	var err error
	if ver.IsZero() {
		nv, err = c.Create(rctx, index, id, doc, false)
	} else {
		nv, err = c.PutIf(rctx, index, id, doc, ver, false)
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound) {
		nv, err = n.heartbeatConflict(rctx, c, prefix, id, doc)
	}
	n.mu.Lock()
	switch {
	case err == nil:
		n.hb.ver, n.contacted, n.lastContact, n.osLatency, n.lastErr, n.lastErrRaw, n.writesRefused = nv, true, n.clock.Mono(), n.clock.Mono()-sent, "", nil, false
		n.errLogged = ""
	case store.IsClusterBlock(err):
		// OpenSearch answers, but its disk is full.
		n.contacted, n.lastContact, n.writesRefused, n.lastErr, n.lastErrRaw = true, n.clock.Mono(), true, "", nil
	case errors.Is(err, errConflicted):
	default:
		n.lastErr, n.lastErrRaw = err.Error(), err
	}
	n.mu.Unlock()
	if err != nil && !store.IsClusterBlock(err) && !errors.Is(err, errConflicted) && ctx.Err() == nil {
		n.logFailure("could not write this server's heartbeat to OpenSearch", err)
	}
}

var errConflicted = errors.New("another process uses this identity")

// heartbeatConflict handles a heartbeat that changed since this server
// wrote it: rewritten by this same process (an answer that got lost), gone
// (removed, or its whole index was: it is made again), or written by
// another process with this identity.
func (n *Node) heartbeatConflict(ctx context.Context, c *store.Client, prefix, id string, doc Heartbeat) (store.Version, error) {
	index := RuntimeIndex(prefix)
	src, ver, found, err := c.Get(ctx, index, id)
	if err != nil {
		return store.Version{}, err
	}
	if !found {
		if err := ensureRuntime(ctx, c, prefix); err != nil {
			return store.Version{}, err
		}
		return c.Create(ctx, index, id, doc, false)
	}
	var other Heartbeat
	_ = json.Unmarshal(src, &other)
	switch {
	case other.BootID == n.local.BootID:
		return c.PutIf(ctx, index, id, doc, ver, false)
	case other.PrevBoot != "" && other.PrevBoot == n.local.BootID:
		// A process started from a copy of this server's state folder took
		// itself for this one's next start. This one runs on: it writes
		// its heartbeat back, and the copy stops when it sees that.
		n.mu.Lock()
		cp := other
		n.copySeen, n.copyAt = &cp, n.clock.Mono()
		n.mu.Unlock()
		where := other.Name
		if other.NodeURL != "" {
			where += ", " + other.NodeURL
		}
		n.log.Error("a copy of this server's state folder was started elsewhere while this server runs; this server goes on, and the copy stops by itself", "copy", where)
		return c.PutIf(ctx, index, id, doc, ver, false)
	}
	_ = n.identityConflict(&other)
	return store.Version{}, errConflicted
}

// measureOffset measures how far this server's clock is off OpenSearch's:
// OpenSearch's time minus this server's at the middle of the request.
func (n *Node) measureOffset(ctx context.Context, c *store.Client) {
	n.mu.Lock()
	n.offsetNext = n.clock.Mono() + n.timing.ClockCheck
	n.mu.Unlock()
	var out struct {
		Nodes map[string]struct {
			OS struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"os"`
		} `json:"nodes"`
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	t0 := n.clock.Now()
	err := c.Do(rctx, http.MethodGet, "/_nodes/_local/stats/os?filter_path=nodes.*.os.timestamp", nil, &out)
	t1 := n.clock.Now()
	if err != nil {
		n.log.Debug("could not read OpenSearch's clock", "err", err)
		return
	}
	for _, nd := range out.Nodes {
		if nd.OS.Timestamp == 0 {
			continue
		}
		mid := t0.Add(t1.Sub(t0) / 2)
		off := time.UnixMilli(nd.OS.Timestamp).Sub(mid)
		n.mu.Lock()
		n.offset = &off
		n.mu.Unlock()
		if off > 2*time.Second || off < -2*time.Second {
			n.log.Warn("this server's clock is off OpenSearch's; keep both in sync with NTP", "offset", off.Round(time.Millisecond))
		}
		return
	}
}

// fingerprints returns this server's files fingerprints. Working them out
// reads files, and the archive folder may be on a network share that does
// not answer, so it runs in the background, once at a time: when the last
// ones are older than FilesCheck, a new run starts. fresh waits for that
// run, at most FilesWait; otherwise, and when that wait runs out, the last
// ones are returned (Unknown when there are none yet).
func (n *Node) fingerprints(fresh bool) Fingerprints {
	n.mu.Lock()
	var done chan struct{}
	if fresh || !n.fpSet || n.clock.Mono() >= n.fpNext {
		done = n.fpStartLocked()
	}
	fp, set := n.fp, n.fpSet
	n.mu.Unlock()
	if done == nil || !fresh {
		if !set {
			return Fingerprints{Unknown: true}
		}
		return fp
	}
	select {
	case <-done:
	case <-n.clock.After(n.timing.FilesWait):
		n.mu.Lock()
		now := n.clock.Mono()
		quiet := n.fpSlowFirst && now-n.fpSlowAt < 10*time.Minute
		n.fpSlowAt, n.fpSlowFirst = now, true
		n.mu.Unlock()
		if !quiet {
			n.log.Warn("this server's files that the background jobs use could not be read in time; the archive folder's share may not answer", "wait", n.timing.FilesWait)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.fpSet {
		return Fingerprints{Unknown: true}
	}
	return n.fp
}

// fpStartLocked starts working out the fingerprints unless that runs
// already, and returns what is closed when it is done. The caller holds
// n.mu.
func (n *Node) fpStartLocked() chan struct{} {
	if n.fpDone != nil {
		return n.fpDone
	}
	f := n.settings.Fingerprints
	done := make(chan struct{})
	n.fpDone = done
	n.fpNext = n.clock.Mono() + n.timing.FilesCheck
	go func() {
		var fp Fingerprints
		if f != nil {
			fp = f()
		}
		n.mu.Lock()
		n.fp, n.fpSet, n.fpDone = fp, true, nil
		n.mu.Unlock()
		close(done)
	}()
	return done
}

// eligible says whether this server may hold the job lease now, and why
// not.
func (n *Node) eligible() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.eligibleLocked()
}

func (n *Node) eligibleLocked() (bool, string) {
	switch {
	case n.stopping:
		return false, "it is stopping"
	case n.conflict != "":
		return false, "another process uses its identity"
	case n.paused != "":
		return false, n.paused
	case !n.settings.Eligible:
		return false, "detections.scheduler is off on this server"
	case !n.hb.checked && n.lastErr != "":
		return false, n.osProblemLocked()
	case !n.hb.checked:
		return false, "it has not reached OpenSearch yet"
	}
	return true, ""
}

// osProblemLocked says, in a few words, why this server could not write
// its heartbeat. The caller holds n.mu.
func (n *Node) osProblemLocked() string {
	var oe *store.Error
	switch {
	case store.NoAnswer(n.lastErrRaw):
		return "OpenSearch doesn't answer it in time"
	case !errors.As(n.lastErrRaw, &oe):
		return "it cannot reach OpenSearch"
	}
	switch store.RefusalOf(oe) {
	case store.RefusedNotInitialized:
		return "OpenSearch's security settings aren't loaded"
	case store.RefusedBusy:
		return "OpenSearch is too busy to answer it in time"
	case store.RefusedSignIn:
		return "OpenSearch refuses its sign-in"
	case store.RefusedUnavailable:
		return "OpenSearch isn't ready"
	case store.RefusedBlocked:
		return "OpenSearch refuses writes"
	case store.RefusedPermission:
		return fmt.Sprintf("OpenSearch refused its heartbeat (%s)", refusal(oe, RuntimeIndex(n.prefix)))
	}
	return fmt.Sprintf("OpenSearch answered its heartbeat with an error (%s)", refusal(oe, RuntimeIndex(n.prefix)))
}

// osTroubleLocked words why this server can't use OpenSearch, for its
// red warning: a short first sentence, then what it means and what to do;
// and briefly, for the banner on every page. Only a refusal of Signalith's
// own OpenSearch user gets the advice to change that user. The caller
// holds n.mu.
func (n *Node) osTroubleLocked() (text, banner string) {
	const noJobs = "so this server runs no detections, threat intel downloads or retention"
	var oe *store.Error
	if n.lastErr != "" && store.NoAnswer(n.lastErrRaw) {
		// It reached OpenSearch, which is too slow: not out of reach.
		return "OpenSearch didn't answer this server in time, so this server can't see the other servers and runs no background jobs. " +
				"Signalith keeps trying, and goes on by itself once OpenSearch answers. " + store.BusyFix + " The error was: " + store.Sentence(n.lastErr),
			"OpenSearch doesn't answer this server in time, so it runs no background jobs."
	}
	if n.lastErr == "" || !errors.As(n.lastErrRaw, &oe) {
		text = "This server can't reach OpenSearch, so it can't see the other servers and runs no background jobs."
		if n.lastErr != "" {
			text += " The error was: " + store.Sentence(n.lastErr)
		}
		return text, "This server can't use OpenSearch, so it runs no background jobs."
	}
	index := RuntimeIndex(n.prefix)
	was := " The error was: " + store.Sentence(oe.Error())
	switch store.RefusalOf(oe) {
	case store.RefusedNotInitialized:
		return "OpenSearch is running, but its security settings aren't loaded, so it refuses every request from this server. " +
				"Until they are, this server runs no detections, threat intel downloads or retention. " + store.NotInitializedFix +
				" This server tries again by itself, so it needs no restart.",
			"OpenSearch's security settings aren't loaded, so it refuses this server, which runs no background jobs."
	case store.RefusedBusy:
		return fmt.Sprintf("OpenSearch is too busy to answer this server in time (%s), %s for now. "+
				"Signalith keeps trying, and goes on by itself once OpenSearch catches up. %s%s",
				refusal(oe, index), noJobs, store.BusyFix, was),
			"OpenSearch is too busy to answer this server, so it runs no background jobs for now."
	case store.RefusedSignIn:
		return fmt.Sprintf("OpenSearch refused this server's sign-in (%s), %s. "+
				"Check the OpenSearch user name and password, or the client certificate, on the Settings page.%s", refusal(oe, index), noJobs, was),
			"OpenSearch refuses this server's sign-in, so it runs no background jobs."
	case store.RefusedPermission:
		return fmt.Sprintf("OpenSearch refused this server's heartbeat (%s), %s. Give Signalith's OpenSearch user the right to create, read and write %s (or %s_*).%s",
				refusal(oe, index), noJobs, index, n.prefix, was),
			"OpenSearch refuses this server, so it runs no background jobs."
	case store.RefusedBlocked:
		return fmt.Sprintf("OpenSearch refuses writes (%s), %s. %s This server goes on by itself after that.%s",
				refusal(oe, index), noJobs, store.BlockedFix, was),
			"OpenSearch refuses writes, so this server runs no background jobs."
	case store.RefusedUnavailable:
		return fmt.Sprintf("OpenSearch isn't ready to answer this server (%s), %s. Signalith keeps trying. OpenSearch's log says why it isn't ready. %s%s",
				refusal(oe, index), noJobs, store.OpenSearchLog, was),
			"OpenSearch isn't ready, so this server runs no background jobs."
	}
	return fmt.Sprintf("OpenSearch answered this server's heartbeat with an error (%s), %s. Signalith keeps trying. OpenSearch's log may say why. %s%s",
			refusal(oe, index), noJobs, store.OpenSearchLog, was),
		"OpenSearch answers this server with an error, so it runs no background jobs."
}

// refusal names an OpenSearch error briefly, such as "403
// security_exception on signalith_runtime".
func refusal(oe *store.Error, index string) string {
	var body struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	out := fmt.Sprint(oe.Status)
	if json.Unmarshal([]byte(oe.Body), &body) == nil && body.Error.Type != "" {
		out += " " + body.Error.Type
	}
	return out + " on " + index
}

// mayTake is eligible, for the lease: a process on probation also waits.
func (n *Node) mayTake() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ok, why := n.eligibleLocked(); !ok {
		return ok, why
	}
	if n.probation {
		return false, "it started a moment ago and is making sure no other process uses its identity"
	}
	return true, ""
}

// leaveJobs says whether this server should leave the background jobs to
// another one: its clock is more than MaxClockOffset off OpenSearch's,
// and another server that may run them, whose clock is right, is up. A
// server alone runs them whatever its clock says.
func (n *Node) leaveJobs() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.offset == nil || n.offset.Abs() <= MaxClockOffset {
		return false, ""
	}
	for id, m := range n.members {
		// Only to one that would take them: not one whose files differ.
		if id == n.ID() || n.goneLocked(m) || !m.hb.LeaderEligible || m.hb.State != StateReady || m.hb.ClockOffsetMS == nil || m.hb.CannotTakeOver != "" {
			continue
		}
		if (time.Duration(*m.hb.ClockOffsetMS) * time.Millisecond).Abs() <= MaxClockOffset {
			return true, fmt.Sprintf("its clock is %s off OpenSearch's, so it leaves them to %s, whose clock is right",
				n.offset.Abs().Round(time.Second), m.hb.Name)
		}
	}
	return false, ""
}

// refusingWrites reports whether OpenSearch refuses this server's
// writes (a full disk).
func (n *Node) refusingWrites() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.writesRefused
}

// tookOver is told that this server took the jobs over from server from,
// because that one stopped renewing the lease: it counts as offline from
// now on unless its heartbeat changes again.
func (n *Node) tookOver(from string) {
	n.mu.Lock()
	if m := n.members[from]; m != nil {
		if gone := n.clock.Mono() - n.timing.Offline; m.since > gone {
			m.since = gone
		}
	}
	n.mu.Unlock()
	n.poke()
}

// blindLocked reports whether this server has not been able to read the
// other servers' heartbeats lately: what it knows of them is old. The
// caller holds n.mu.
func (n *Node) blindLocked() bool {
	return !n.contacted || n.clock.Mono()-n.lastRead > n.timing.Offline/2
}

// observe reads every server's heartbeat.
func (n *Node) observe(ctx context.Context, c *store.Client, prefix string) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	docs, err := c.SearchDocs(rctx, RuntimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		n.log.Debug("could not read the other servers' heartbeats", "err", err)
		return
	}
	now := n.clock.Mono()
	n.mu.Lock()
	defer n.mu.Unlock()
	// After a time this server could not read, a heartbeat that did not
	// change may simply not have been seen change: count from now.
	gap := n.blindLocked()
	n.contacted, n.lastContact, n.lastRead = true, now, now
	seen := map[string]bool{}
	for _, d := range docs {
		var hb Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" {
			continue
		}
		seen[hb.NodeID] = true
		m := n.members[hb.NodeID]
		switch {
		case m == nil:
			// First sight: how old it is can only be told from its own
			// clock, corrected by both servers' offsets when known. It is
			// kept whole, so a server started again still says when the
			// others were last seen; heartbeats older than a week are
			// removed, so more than that is a broken clock.
			age := n.clock.Now().Sub(hb.HeartbeatAt)
			if n.offset != nil && hb.ClockOffsetMS != nil {
				age += *n.offset - time.Duration(*hb.ClockOffsetMS)*time.Millisecond
			}
			age = min(max(age, 0), 8*24*time.Hour)
			n.members[hb.NodeID] = &member{hb: hb, ver: d.Version, since: now - age}
		case !m.ver.Same(d.Version):
			m.hb, m.ver, m.since = hb, d.Version, now
		case gap && hb.State != StateStopped:
			m.since = now
		}
		if n.writesRefused {
			// Nobody can write a heartbeat while OpenSearch refuses
			// writes: keep everyone as they were.
			n.members[hb.NodeID].since = now
		}
	}
	for id := range n.members {
		if !seen[id] {
			delete(n.members, id)
		}
	}
}

// housekeeping is a leader job: every 10 minutes it removes the
// heartbeats of servers gone for a week.
func (n *Node) housekeeping(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.clock.After(10 * time.Minute):
		}
		if !n.lease.Valid() {
			continue
		}
		n.mu.Lock()
		c, prefix := n.client, n.prefix
		n.mu.Unlock()
		if c == nil {
			continue
		}
		cutoff := n.clock.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		index := RuntimeIndex(prefix)
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		docs, err := c.SearchVersions(rctx, index, map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"kind": "node"}},
			map[string]any{"range": map[string]any{"heartbeat_at": map[string]any{"lt": cutoff}}},
		}}})
		for _, d := range docs {
			if d.ID == nodeDocID(n.ID()) || !n.lease.Valid() {
				continue
			}
			if err := c.DeleteIf(rctx, index, d.ID, d.Version, false); err == nil {
				n.log.Info("removed the heartbeat of a server gone for a week", "doc", d.ID)
			}
		}
		cancel()
		if err != nil {
			n.log.Debug("housekeeping could not list old heartbeats", "err", err)
		}
	}
}

// RunsJobs reports whether this server runs the background jobs now.
func (n *Node) RunsJobs() bool { return n.lease.Valid() }

// Check is the fence before a step that changes data: it confirms that
// this server still runs the background jobs.
func (n *Node) Check(ctx context.Context) error { return n.lease.Check(ctx) }

// JobHolder returns the name of another server that runs the background
// jobs, as this server last saw the lease, or "" when none does: the
// lease names nobody, this server, or a server that went offline.
func (n *Node) JobHolder() string {
	v := n.lease.View()
	if !v.Found || v.Doc.Holder == "" || v.Doc.Holder == n.ID() {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if m := n.members[v.Doc.Holder]; m != nil && n.goneLocked(m) {
		return ""
	}
	return v.Doc.HolderName
}

// holderName names the server the lease names, or the one that ran the
// jobs last.
func holderName(d LeaseDoc) string {
	if d.HolderName != "" {
		return d.HolderName
	}
	return "the server that ran them last"
}

// fixFiles says how to make server's files the same as holder's where
// they differ (parts, from Fingerprints.Differ), so that server may take
// the jobs over.
func fixFiles(parts []string, server, holder string) string {
	var what []string
	shared := false
	for _, p := range parts {
		switch p {
		case "retention policies":
			what = append(what, "retention policies (retention.yaml in the lookups folder, and retention in signalith.yaml)")
		case "threat intel feeds":
			what = append(what, "threat intel feeds (intel_feeds.yaml in the lookups folder, and intel in signalith.yaml)")
		case "archive folder":
			shared = true
		default:
			what = append(what, p)
		}
	}
	var out []string
	if len(what) > 0 {
		out = append(out, fmt.Sprintf("Make %s's %s the same as %s's, then restart %s.", server, joinWords(what), holder, server))
	}
	if shared {
		out = append(out, "Keep archives in one shared folder: set retention.archive_dir to the same shared folder on every server, then restart them.")
	}
	if len(out) == 0 {
		return fmt.Sprintf("Make the files the jobs use the same on %s as on %s, then restart %s.", server, holder, server)
	}
	return strings.Join(out, " ")
}

// goneLocked reports whether another server is offline or stopped. While
// this server cannot read the heartbeats, or nobody can write them (a full
// disk), the others stay as they were last seen. The caller holds n.mu.
func (n *Node) goneLocked(m *member) bool {
	if m.hb.State == StateStopped {
		return true
	}
	return n.clock.Mono()-m.since >= n.timing.Offline && !n.writesRefused && !n.blindLocked()
}

// Readiness reasons.
const (
	NotReadyStarting   = "starting"
	NotReadyOpenSearch = "opensearch"
	NotReadyIdentity   = "identity"
	NotReadyStopping   = "stopping"
	// NotReadyDown is a server whose parts could not start (see Pause).
	NotReadyDown = "down"
)

// Ready reports whether this server should get traffic from a load
// balancer, and if not, why: one of the NotReady reasons.
func (n *Node) Ready() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.readyLocked()
}

func (n *Node) readyLocked() (bool, string) {
	switch {
	case n.stopping:
		return false, NotReadyStopping
	case n.conflict != "":
		return false, NotReadyIdentity
	case n.paused != "":
		return false, NotReadyDown
	case !n.hb.checked && n.lastErr != "":
		return false, NotReadyOpenSearch
	case !n.hb.checked:
		return false, NotReadyStarting
	case !n.contacted || n.clock.Mono()-n.lastContact > n.timing.Offline:
		return false, NotReadyOpenSearch
	}
	return true, ""
}

// Status is the cluster as this server sees it, for GET /api/cluster.
type Status struct {
	Self    string         `json:"self"`
	Servers []ServerStatus `json:"servers"`
	Jobs    JobsStatus     `json:"lease"`
	// WritesRefused is true while OpenSearch refuses writes, as when its
	// disk is full; heartbeats then stand still.
	WritesRefused bool      `json:"writes_refused"`
	Warnings      []Warning `json:"warnings"`
}

// ServerStatus is one server.
type ServerStatus struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Self   bool   `json:"self"`
	// State is starting, ready, stopping, stopped, conflict, unreachable
	// (this server cannot reach OpenSearch, or OpenSearch doesn't answer
	// it in time), refused (OpenSearch answers this server but turns it
	// away) or offline.
	State string `json:"state"`
	// OfflineSince is when its heartbeat stopped, for an offline or
	// stopped server, on this server's clock, and SeenAgo how long ago
	// that was.
	OfflineSince *time.Time     `json:"offline_since,omitempty"`
	SeenAgo      *time.Duration `json:"-"`
	Version      string         `json:"version"`
	// Jobs is "runs" for the server that runs the background jobs,
	// "standby" for one that may take them over, "not_eligible" for one
	// that may not.
	Jobs        string    `json:"jobs"`
	StartedAt   time.Time `json:"started_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	// Uptime is how long it has run, as of now.
	Uptime time.Duration `json:"-"`
	Detail *Heartbeat    `json:"-"`
	// CannotTakeOver says why this server would not take the jobs over
	// by itself: its files differ from those of the server that ran them
	// last, or its clock is far off. differ lists those files
	// (Fingerprints.Differ).
	CannotTakeOver string `json:"-"`
	differ         []string
}

// JobsStatus is the job lease.
type JobsStatus struct {
	Holder     string     `json:"holder,omitempty"`
	HolderName string     `json:"holder_name,omitempty"`
	Epoch      int64      `json:"epoch,omitempty"`
	AcquiredAt *time.Time `json:"acquired_at,omitempty"`
	RenewedAt  *time.Time `json:"renewed_at,omitempty"`
	// Frozen is true while the holder runs only the disk guard, because
	// OpenSearch refuses writes.
	Frozen bool `json:"frozen"`
	// Mine is true when this server holds it.
	Mine bool `json:"mine"`
	// Released names the server that gave the jobs up last, while nobody
	// has taken them.
	ReleasedBy string `json:"released_by,omitempty"`
}

// Warning is something about the servers an admin should know, red for a
// problem and amber for attention. Banner, on red ones, is a short form
// for a banner on every page, which names no server address.
type Warning struct {
	Level  string `json:"level"`
	Text   string `json:"text"`
	Banner string `json:"banner,omitempty"`
}

// Status returns the cluster as this server last saw it.
func (n *Node) Status() Status {
	view := n.lease.View()
	eligible, notWhy := n.eligible()
	self := n.heartbeatDoc(StateReady)
	n.mu.Lock()
	defer n.mu.Unlock()
	ready, reason := n.readyLocked()
	now := n.clock.Mono()
	st := Status{Self: n.ID(), WritesRefused: n.writesRefused, Warnings: []Warning{}}
	// This server, as it is now rather than as last written.
	self.State = StateReady
	if !ready {
		self.State = map[string]string{NotReadyStopping: StateStopping, NotReadyIdentity: StateConflict, NotReadyOpenSearch: StateUnreachable,
			NotReadyDown: StateDown}[reason]
		if self.State == "" {
			self.State = StateStarting
		}
		if self.State == StateUnreachable && n.lastErr != "" && store.RefusalOf(n.lastErrRaw) != store.NotRefused {
			// It reached OpenSearch, which turned it away.
			self.State = StateRefused
		}
	}
	mine := ServerStatus{NodeID: self.NodeID, Name: self.Name, Self: true, State: self.State, Version: self.Version,
		StartedAt: self.StartedAt, HeartbeatAt: self.HeartbeatAt, Detail: &self, Uptime: max(n.clock.Now().Sub(n.started), 0)}
	servers := []ServerStatus{mine}
	holderID := ""
	if view.Found {
		holderID = view.Doc.Holder
	}
	for id, m := range n.members {
		if id == n.ID() {
			continue
		}
		hb := m.hb
		unchanged := now - m.since
		s := ServerStatus{NodeID: id, Name: hb.Name, State: hb.State, Version: hb.Version, StartedAt: hb.StartedAt,
			HeartbeatAt: hb.HeartbeatAt, Detail: &hb, Uptime: max(hb.HeartbeatAt.Sub(hb.StartedAt)+unchanged, 0)}
		if hb.State != StateStopped && n.goneLocked(m) {
			s.State = StateOffline
		}
		if s.State == StateOffline || s.State == StateStopped {
			// When it was last seen, told by this server's own clocks: the
			// other one's may be wrong.
			ago := max(unchanged, 0)
			at := n.clock.Now().Add(-ago).UTC()
			s.OfflineSince, s.SeenAgo = &at, &ago
		}
		servers = append(servers, s)
	}
	for i := range servers {
		s := &servers[i]
		switch {
		case s.NodeID == holderID && (s.Self && view.Valid || !s.Self && s.State != StateOffline && s.State != StateStopped):
			s.Jobs = "runs"
		case s.Self && eligible, !s.Self && s.Detail.LeaderEligible && s.State != StateOffline && s.State != StateStopped:
			s.Jobs = "standby"
		default:
			s.Jobs = "not_eligible"
		}
		if s.Self && !eligible {
			s.Detail.NotEligible = notWhy
		}
		if s.Jobs != "standby" {
			continue
		}
		// Why a server that may run the jobs would not take them over by
		// itself: its clock (from its own check), or the fingerprint
		// guard, its files differing from those of the server that ran
		// them last. Every server's page shows it: the others' are read
		// from their heartbeats.
		d := view.Doc
		guarded := view.Found && d.Fingerprint != "" && s.NodeID != d.Holder && !(d.Holder == "" && s.NodeID == d.ReleasedBy)
		switch {
		case s.Self && view.CannotTake != "":
			s.CannotTakeOver = view.CannotTake
		case !s.Self && s.Detail.CannotTakeOver != "":
			s.CannotTakeOver = s.Detail.CannotTakeOver
		case !s.Self && guarded && s.Detail.FilesFingerprint.Combined() != d.Fingerprint:
			s.CannotTakeOver = cannotTakeOver(s.Detail.FilesFingerprint.Differ(d.Fingerprints), holderName(d))
		}
		if s.CannotTakeOver != "" && guarded {
			s.differ = s.Detail.FilesFingerprint.Differ(d.Fingerprints)
		}
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Name != servers[j].Name {
			return servers[i].Name < servers[j].Name
		}
		return servers[i].NodeID < servers[j].NodeID
	})
	st.Servers = servers
	if view.Found {
		d := view.Doc
		st.Jobs = JobsStatus{Holder: d.Holder, HolderName: d.HolderName, Epoch: d.Epoch, Mine: view.Mine && view.Valid,
			Frozen: d.Holder != "" && (view.State == frozen.String() || n.writesRefused)}
		if d.Holder == "" {
			st.Jobs.ReleasedBy = d.ReleasedBy
			st.Jobs.Epoch = 0
		} else {
			acq, ren := d.AcquiredAt, d.RenewedAt
			st.Jobs.AcquiredAt, st.Jobs.RenewedAt = &acq, &ren
		}
	}
	st.Warnings = n.warningsLocked(st, view, notWhy)
	return st
}

// warningsLocked lists what an admin should know, each as a short first
// sentence, then what it means and what to do. notWhy is why this server
// may not run the jobs. The caller holds n.mu.
func (n *Node) warningsLocked(st Status, view LeaseView, notWhy string) []Warning {
	w := []Warning{}
	if n.conflict != "" {
		w = append(w, Warning{Level: "red", Text: n.conflict, Banner: "Another server is using this server's identity, so this server runs no background jobs."})
	}
	if n.copySeen != nil && n.clock.Mono()-n.copyAt < 10*time.Minute {
		where := n.copySeen.Name
		if n.copySeen.NodeURL != "" {
			where += " at " + n.copySeen.NodeURL
		}
		w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("A copy of this server's state folder was started (%s) while this server runs. "+
			"This server goes on and the copy stops by itself. Before you start the copy again, give it its own identity: delete node.id in its state folder.", where)})
	}
	if n.writesRefused {
		text, banner := fullDiskWarning(st.Jobs)
		w = append(w, Warning{Level: "red", Text: text, Banner: banner})
	}
	// This server cannot use OpenSearch: what it knows of the others is
	// old, so nothing more is said about them.
	if ready, why := n.readyLocked(); !ready && why == NotReadyOpenSearch {
		text, banner := n.osTroubleLocked()
		if n.hb.checked {
			text += " The servers below are as it last saw them."
		}
		w = append(w, Warning{Level: "red", Text: text, Banner: banner})
		return append(w, n.localWarningsLocked(st)...)
	}
	runs := false
	var standby, blocked []ServerStatus
	for _, s := range st.Servers {
		switch {
		case s.Jobs == "runs":
			runs = true
		case s.Jobs == "standby" && s.CannotTakeOver != "":
			blocked = append(blocked, s)
		case s.Jobs == "standby":
			standby = append(standby, s)
		}
	}
	holder := holderName(view.Doc)
	const none = "No server is running detections, threat intel downloads or retention."
	if !runs && n.hb.checked && view.Seen && n.conflict == "" {
		switch {
		case len(standby) > 0:
			w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("No server runs detections, threat intel downloads or retention right now. %s takes them over within a minute.", standby[0].Name)})
		case len(blocked) > 0:
			b := blocked[0]
			fix := fixFiles(b.differ, b.Name, holder)
			if len(b.differ) == 0 {
				fix = ""
			}
			w = append(w, Warning{Level: "red", Text: strings.TrimSpace(fmt.Sprintf("%s %s may run them, but does not take them over by itself, because %s. %s",
				none, b.Name, b.CannotTakeOver, fix)), Banner: none})
			blocked = blocked[1:]
		case strings.HasPrefix(notWhy, "detections.scheduler is off"):
			w = append(w, Warning{Level: "red", Text: none + " No server that may run them is up. Start one, or turn on Run detections on schedule (detections.scheduler) on the Settings page of one of them.", Banner: none})
		default:
			w = append(w, Warning{Level: "red", Text: fmt.Sprintf("%s No other server that may run them is up, and this one doesn't, because %s.", none, notWhy), Banner: none})
		}
	}
	for _, b := range blocked {
		fix := ""
		if len(b.differ) > 0 {
			fix = " " + fixFiles(b.differ, b.Name, holder)
		}
		w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("%s would not take the background jobs over if %s stopped, because %s.%s",
			b.Name, holder, b.CannotTakeOver, fix)})
	}
	return append(w, n.localWarningsLocked(st)...)
}

// localWarningsLocked are warnings about this server's folder, the
// servers' clocks and names. The caller holds n.mu.
func (n *Node) localWarningsLocked(st Status) []Warning {
	var w []Warning
	for _, msg := range n.local.Warnings {
		w = append(w, Warning{Level: "amber", Text: msg})
	}
	names := map[string]int{}
	for _, s := range st.Servers {
		if s.State == StateOffline || s.State == StateStopped {
			continue
		}
		names[s.Name]++
		if s.Detail != nil && s.Detail.ClockOffsetMS != nil {
			off := time.Duration(*s.Detail.ClockOffsetMS) * time.Millisecond
			if off.Abs() > 2*time.Second {
				w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("%s's clock is %s off OpenSearch's. Detections are scheduled by the clock: keep every server's clock in sync with NTP (Windows Time on Windows).", s.Name, off.Abs().Round(100*time.Millisecond))})
			}
		}
	}
	dups := []string{}
	for name, k := range names {
		if k > 1 {
			dups = append(dups, name)
		}
	}
	sort.Strings(dups)
	for _, name := range dups {
		w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("More than one running server is named %s. Give each its own name: set cluster.node_name in signalith.yaml (SIGNALITH_NODE_NAME in Docker) on all but one, then restart them.", name)})
	}
	return w
}

// fullDiskWarning says that OpenSearch refuses writes, what Signalith does
// about it, and what an admin can do; and briefly, for every page. Only
// the holder knows whether its disk guard is on, or has days left it may
// delete, so the short form claims nothing about freeing space.
func fullDiskWarning(jobs JobsStatus) (text, banner string) {
	head := "OpenSearch's disk is full, so it refuses new events. "
	if jobs.Holder == "" {
		return head + "No server runs the disk guard right now, so nothing frees space by itself. Give OpenSearch more disk, or start a server that runs the background jobs.",
			head + "No server is deleting old days to free space."
	}
	return head + fmt.Sprintf("%s keeps only the retention disk guard running: unless it was turned off on the Data retention page, it deletes the oldest days until there is room. "+
			"New events are stored again by themselves after that; agents keep theirs until then. To make room sooner, give OpenSearch more disk.", jobs.HolderName),
		strings.TrimSpace(head)
}

// Banners returns the red problems for a banner on every page, briefly.
func (n *Node) Banners() []string {
	var out []string
	for _, w := range n.Status().Warnings {
		if w.Level == "red" && w.Banner != "" && !slicesContains(out, w.Banner) {
			out = append(out, w.Banner)
		}
	}
	return out
}

func slicesContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
