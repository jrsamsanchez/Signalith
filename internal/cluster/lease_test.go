package cluster

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const testIndex = "s_runtime"

// skewed is a clock whose wall time is off by a fixed amount, as on a
// computer whose clock is wrong; its monotonic time is the real one.
type skewed struct {
	*ostest.Clock
	off time.Duration
}

func (s skewed) Now() time.Time { return s.Clock.Now().Add(s.off) }

// sim runs leases on one fake clock as their servers' loops would: each
// one steps when its next round is due.
type sim struct {
	t     *testing.T
	clock *ostest.Clock
	os    *ostest.Server
	c     *store.Client
	nodes []*simNode
}

type simNode struct {
	l    *Lease
	next time.Duration
	// lastStep is when it last stepped.
	lastStep time.Duration
	// paused nodes do not step, as a crashed or stopped server.
	paused bool
	fp     Fingerprints
	mu     sync.Mutex
}

func newSim(t *testing.T) *sim {
	t.Helper()
	os := ostest.New(t)
	clock := ostest.NewClock(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	return &sim{t: t, clock: clock, os: os, c: store.New(store.Config{URL: os.URL})}
}

// add adds a server; clock may be nil for the shared one.
func (s *sim) add(id string, clock Clock) *simNode {
	if clock == nil {
		clock = s.clock
	}
	n := &simNode{}
	n.l = &Lease{
		Self:   Self{NodeID: id, Name: "siem-" + strings.TrimPrefix(id, "n_"), Version: "1.0.0", BootID: "b_" + id},
		Clock:  clock,
		Timing: DefaultTiming,
		Target: func() (*store.Client, string) { return s.c, testIndex },
		Eligible: func() (bool, string) {
			return true, ""
		},
		Fingerprints: func(bool) Fingerprints {
			n.mu.Lock()
			defer n.mu.Unlock()
			return n.fp
		},
	}
	n.next = s.clock.Mono()
	s.nodes = append(s.nodes, n)
	return n
}

func (n *simNode) setFP(fp Fingerprints) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.fp = fp
}

// run lets d pass, stepping each server whenever it is due.
func (s *sim) run(d time.Duration) {
	end := s.clock.Mono() + d
	for {
		var due *simNode
		for _, n := range s.nodes {
			if !n.paused && (due == nil || n.next < due.next) {
				due = n
			}
		}
		now := s.clock.Mono()
		if due == nil || due.next > end {
			if end > now {
				s.clock.Advance(end - now)
			}
			return
		}
		if due.next > now {
			s.clock.Advance(due.next - now)
		}
		due.lastStep = s.clock.Mono()
		due.next = s.clock.Mono() + due.l.Step(context.Background())
	}
}

// lease returns lease:jobs as stored.
func (s *sim) lease() LeaseDoc {
	s.t.Helper()
	src := s.os.Source(testIndex, leaseID)
	if src == nil {
		return LeaseDoc{}
	}
	b, _ := json.Marshal(src)
	var d LeaseDoc
	if err := json.Unmarshal(b, &d); err != nil {
		s.t.Fatal(err)
	}
	return d
}

// probe is a job that records when it runs.
type probe struct {
	mu      sync.Mutex
	starts  int
	running int
	// hold, when set, keeps the job from returning after it is cancelled
	// until it is closed.
	hold chan struct{}
}

func (p *probe) job(name string, emergency bool) Job {
	return Job{Name: name, Emergency: emergency, Run: func(ctx context.Context) {
		p.mu.Lock()
		p.starts++
		p.running++
		hold := p.hold
		p.mu.Unlock()
		<-ctx.Done()
		if hold != nil {
			<-hold
		}
		p.mu.Lock()
		p.running--
		p.mu.Unlock()
	}}
}

func (p *probe) state() (starts, running int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.starts, p.running
}

// eventually waits for cond in real time: jobs start and stop in their
// own goroutines.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTakeoverOnlyAfter30SecondsWithoutChange(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	pa := &probe{}
	a.l.SetJobs([]Job{pa.job("detections", false)})
	s.run(time.Second)
	if !a.l.Holding() || b.l.Holding() || s.lease().Holder != "n_a" || s.lease().Epoch != 1 {
		t.Fatalf("a should hold the lease: %+v", s.lease())
	}
	eventually(t, "a's job", func() bool { _, r := pa.state(); return r == 1 })
	// While a renews, b never takes over.
	s.run(5 * time.Minute)
	if b.l.Holding() || s.lease().Holder != "n_a" || s.lease().Epoch != 1 {
		t.Fatalf("b took over a live holder: %+v", s.lease())
	}
	// a stops renewing, as a crashed server would. Its last renewal is
	// the last change b sees.
	a.paused = true
	lastChange := a.lastStep
	s.run(lastChange + 29*time.Second - s.clock.Mono())
	if b.l.Holding() {
		t.Fatalf("b took over %v after the last change", s.clock.Mono()-lastChange)
	}
	s.run(3 * time.Second)
	if !b.l.Holding() || s.lease().Holder != "n_b" || s.lease().Epoch != 2 {
		t.Fatalf("b did not take over: %+v", s.lease())
	}
	// When a comes back, its next renewal fails and its jobs stop at once.
	a.paused = false
	a.next = s.clock.Mono()
	s.run(time.Second)
	if a.l.Holding() || a.l.Valid() {
		t.Error("a still thinks it holds the lease")
	}
	eventually(t, "a's job to stop", func() bool { _, r := pa.state(); return r == 0 })
}

func TestSelfFenceAt20Seconds(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	p := &probe{}
	a.l.SetJobs([]Job{p.job("detections", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := p.state(); return r == 1 })
	// The last good renewal is sent at 10 s; OpenSearch then stops
	// answering.
	s.run(9 * time.Second)
	lastGood := s.clock.Mono()
	s.run(500 * time.Millisecond)
	s.os.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "unavailable"} })
	s.run(19*time.Second - (s.clock.Mono() - lastGood))
	if !a.l.Valid() {
		t.Fatalf("fenced after only %v", s.clock.Mono()-lastGood)
	}
	if _, r := p.state(); r != 1 {
		t.Fatal("the job stopped too early")
	}
	s.run(time.Second + 100*time.Millisecond)
	if a.l.Valid() || a.l.Holding() {
		t.Fatalf("still holding %v after the last good renewal", s.clock.Mono()-lastGood)
	}
	eventually(t, "the job to stop", func() bool { _, r := p.state(); return r == 0 })
}

func TestConflictOnRenewStopsJobsAtOnce(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	p := &probe{}
	a.l.SetJobs([]Job{p.job("detections", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := p.state(); return r == 1 })
	// Someone else writes the lease.
	s.os.Put(testIndex, leaseID, map[string]any{"kind": "lease", "holder": "n_x", "epoch": 9})
	s.run(10 * time.Second)
	if a.l.Holding() {
		t.Fatal("a keeps a lease someone else wrote")
	}
	eventually(t, "the job to stop", func() bool { _, r := p.state(); return r == 0 })
}

func TestTwo429sOnRenewalDoNotLoseTheLease(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	p := &probe{}
	a.l.SetJobs([]Job{p.job("detections", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := p.state(); return r == 1 })
	s.os.FailN(2, "PUT", leaseID, 429, "es_rejected_execution_exception")
	s.run(30 * time.Second)
	if !a.l.Holding() || !a.l.Valid() || s.lease().Epoch != 1 || s.lease().Holder != "n_a" {
		t.Fatalf("lost the lease: %+v", s.lease())
	}
	if starts, r := p.state(); starts != 1 || r != 1 {
		t.Errorf("the job was restarted or stopped: %d starts, %d running", starts, r)
	}
}

func TestGracefulReleaseWaitsForInFlightWork(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	p := &probe{hold: make(chan struct{})}
	a.l.SetJobs([]Job{p.job("retention", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := p.state(); return r == 1 })
	released := make(chan struct{})
	go func() {
		a.l.Release("the server is stopping")
		close(released)
	}()
	// The job is cancelled but still finishing its step: a keeps the
	// lease, renewing it, and b does not take over.
	eventually(t, "the release to start", func() bool { return a.l.View().State == "releasing" })
	s.run(45 * time.Second)
	select {
	case <-released:
		t.Fatal("released before the work in progress finished")
	default:
	}
	if s.lease().Holder != "n_a" || b.l.Holding() || !a.l.Valid() {
		t.Fatalf("lease %+v while a's job finishes", s.lease())
	}
	close(p.hold)
	<-released
	if d := s.lease(); d.Holder != "" || d.ReleasedBy != "n_a" || d.ReleaseReason != "the server is stopping" {
		t.Fatalf("not released: %+v", d)
	}
	// b takes it within a couple of seconds.
	a.paused = true
	s.run(3 * time.Second)
	if !b.l.Holding() || s.lease().Holder != "n_b" || s.lease().Epoch != 2 {
		t.Fatalf("b did not take over after the release: %+v", s.lease())
	}
}

func TestReleaseGivesUpAfterTheWait(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	p := &probe{hold: make(chan struct{})}
	defer close(p.hold)
	a.l.SetJobs([]Job{p.job("stuck", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := p.state(); return r == 1 })
	released := make(chan struct{})
	go func() {
		a.l.Release("the server is stopping")
		close(released)
	}()
	eventually(t, "the release to start", func() bool { return a.l.View().State == "releasing" })
	s.run(61 * time.Second)
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the release waited longer than a minute")
	}
	if s.lease().Holder != "" {
		t.Errorf("not released: %+v", s.lease())
	}
}

func TestSkewedWallClocksChangeNothing(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", skewed{s.clock, 2 * time.Hour})
	b := s.add("n_b", skewed{s.clock, -3 * time.Hour})
	s.run(2 * time.Minute)
	if !a.l.Holding() || b.l.Holding() || s.lease().Epoch != 1 {
		t.Fatalf("lease %+v", s.lease())
	}
	// The holder's clock is set back an hour: nothing changes either.
	s.clock.SetWall(s.clock.Now().Add(-time.Hour))
	s.run(2 * time.Minute)
	if !a.l.Holding() || !a.l.Valid() || b.l.Holding() || s.lease().Epoch != 1 {
		t.Fatalf("after a clock change: %+v", s.lease())
	}
	// The wall-clock times in the lease are only for people to read.
	if d := s.lease(); d.RenewedAt.Before(s.clock.Now().Add(time.Hour)) {
		t.Errorf("renewed_at %v is not the holder's own clock", d.RenewedAt)
	}
}

func TestSuspendedHolderStopsItsJobs(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	s.run(time.Second)
	// The computer sleeps for an hour: its monotonic clock stood still,
	// its wall clock did not.
	s.clock.SetWall(s.clock.Now().Add(time.Hour))
	if a.l.Valid() {
		t.Fatal("a suspended holder still counts itself valid")
	}
	// At its next round it stops its jobs; nobody else took over, so it
	// takes its own lease back, with a new epoch.
	s.run(12 * time.Second)
	if !a.l.Holding() || s.lease().Epoch != 2 {
		t.Fatalf("lease %+v", s.lease())
	}
}

func TestRecreatedLeaseTakesAnEpochAboveTheStoredOnes(t *testing.T) {
	s := newSim(t)
	s.os.Put(testIndex, "node:n_old", map[string]any{"kind": "node", "lease_epoch": 17})
	s.os.Put(testIndex, "op:x", map[string]any{"kind": "op", "epoch": 21})
	a := s.add("n_a", nil)
	s.run(time.Second)
	if d := s.lease(); d.Holder != "n_a" || d.Epoch != 22 {
		t.Fatalf("lease %+v", d)
	}
	// Someone deletes it: the holder loses it at its next renewal. Nobody
	// makes a new one before the takeover time, as for a lease that stopped
	// changing: another holder, cut off from OpenSearch, may not have
	// stopped its jobs yet. The next one is above every epoch still
	// stored, including the holder's own heartbeat.
	s.os.Put(testIndex, "node:n_a", map[string]any{"kind": "node", "lease_epoch": 22})
	s.os.Delete(testIndex, leaseID)
	s.run(15 * time.Second)
	if d := s.lease(); d.Holder != "" || a.l.Holding() {
		t.Fatalf("lease made again too soon: %+v", d)
	}
	s.run(30 * time.Second)
	if d := s.lease(); d.Holder != "n_a" || d.Epoch != 23 {
		t.Fatalf("lease %+v", d)
	}
}

// A lease deleted while another server holds it, cut off from OpenSearch:
// the others wait the takeover time, by which that holder has stopped its
// jobs at the fence time.
func TestDeletedLeaseWaitsForTheCutOffHolder(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	pa := &probe{}
	a.l.SetJobs([]Job{pa.job("detections", false)})
	s.run(time.Second)
	if !a.l.Holding() {
		t.Fatal("a does not hold the lease")
	}
	eventually(t, "a's job", func() bool { _, r := pa.state(); return r == 1 })
	// a is cut off (it no longer steps), and the lease is deleted.
	a.paused = true
	s.os.Delete(testIndex, leaseID)
	s.run(a.l.Timing.Fence + time.Second)
	if b.l.Holding() {
		t.Fatal("b made a new lease while a may still run its jobs")
	}
	eventually(t, "a to stop its jobs at the fence time", func() bool { _, r := pa.state(); return r == 0 })
	s.run(a.l.Timing.Takeover)
	if !b.l.Holding() || s.lease().Holder != "n_b" {
		t.Fatalf("lease %+v", s.lease())
	}
}

func TestCrashedServersLeaseIsTakenBackSooner(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	s.run(time.Second)
	a.paused = true
	// The same server restarts a second later, after a crash: a new
	// process of the same identity, whose state folder says the old one
	// was its last boot. It takes the lease back once it has seen it
	// unchanged for the fence time, not the whole takeover time.
	a2 := s.add("n_a", nil)
	a2.l.Self.BootID, a2.l.Self.LastBoot = "b_new", "b_n_a"
	s.run(15 * time.Second)
	if a2.l.Holding() {
		t.Fatal("took the lease back before the old process had stopped its jobs")
	}
	s.run(8 * time.Second)
	if !a2.l.Holding() || s.lease().Epoch != 2 || s.lease().HolderBoot != "b_new" {
		t.Fatalf("lease %+v", s.lease())
	}
	// A process with this identity that is not the folder's next boot
	// (a copied folder) must wait like anyone else.
	a2.paused = true
	c := s.add("n_a", nil)
	c.l.Self.BootID, c.l.Self.LastBoot = "b_copy", "b_other"
	s.run(25 * time.Second)
	if c.l.Holding() {
		t.Fatal("a copy of the identity took the lease early")
	}
}

// A copy of a running server's state folder, made with its last_boot,
// never takes the lease from the running server.
func TestLiveCopyNeverTakesTheLease(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	s.run(time.Second)
	cp := s.add("n_a", nil)
	cp.l.Self.BootID, cp.l.Self.LastBoot = "b_copy", "b_n_a"
	s.run(2 * time.Minute)
	if cp.l.Holding() || !a.l.Holding() || s.lease().HolderBoot != "b_n_a" || s.lease().Epoch != 1 {
		t.Fatalf("lease %+v", s.lease())
	}
}

func TestFingerprintGuard(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	a.setFP(Fingerprints{Retention: "sha256:r1", Feeds: "sha256:f1"})
	b.setFP(Fingerprints{Retention: "sha256:r2", Feeds: "sha256:f1"})
	s.run(5 * time.Second)
	// While a runs the jobs, b already says why it could not take over.
	if why := b.l.View().CannotTake; !strings.Contains(why, "retention policies differ from siem-a's") {
		t.Errorf("why, before: %q", why)
	}
	a.paused = true
	s.run(time.Minute)
	if b.l.Holding() {
		t.Fatal("b took over with different retention policies")
	}
	if why := b.l.View().CannotTake; !strings.Contains(why, "retention policies differ from siem-a's") {
		t.Errorf("why: %q", why)
	}
	b.setFP(Fingerprints{Retention: "sha256:r1", Feeds: "sha256:f1"})
	s.run(3 * time.Second)
	if !b.l.Holding() {
		t.Fatal("b did not take over once its files matched")
	}
}

func TestNotEligibleNeverTakes(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	a.l.Eligible = func() (bool, string) { return false, "detections.scheduler is off on this server" }
	s.run(time.Minute)
	if a.l.Holding() || s.os.Source(testIndex, leaseID) != nil {
		t.Fatal("a server that may not run the jobs took the lease")
	}
	if a.l.View().CannotTake != "detections.scheduler is off on this server" {
		t.Errorf("why: %q", a.l.View().CannotTake)
	}
}

func TestBlockedRenewalKeepsTheRole(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	normal, guard := &probe{}, &probe{}
	a.l.SetJobs([]Job{normal.job("detections", false), guard.job("retention", true)})
	s.run(time.Second)
	eventually(t, "the jobs", func() bool {
		_, n := normal.state()
		_, g := guard.state()
		return n == 1 && g == 1
	})
	// OpenSearch's disk fills up: every write is refused.
	s.os.Block(true)
	s.run(15 * time.Second)
	if !a.l.Frozen() || !a.l.Valid() {
		t.Fatalf("not frozen: %+v", a.l.View())
	}
	eventually(t, "detections to pause", func() bool { _, n := normal.state(); return n == 0 })
	if _, g := guard.state(); g != 1 {
		t.Fatal("the disk guard stopped")
	}
	// Long after: a keeps the role, b cannot take it, and a fence check
	// before a delete still passes.
	s.run(3 * time.Minute)
	if !a.l.Frozen() || !a.l.Valid() || b.l.Holding() || s.lease().Holder != "n_a" {
		t.Fatalf("lease %+v, a %+v", s.lease(), a.l.View())
	}
	if err := a.l.Check(context.Background()); err != nil {
		t.Fatalf("fence check while frozen: %v", err)
	}
	if err := b.l.Check(context.Background()); err == nil {
		t.Fatal("b passes the fence check")
	}
	// The disk guard, fenced by the lease, still deletes the oldest day on
	// a, and nothing on b.
	for _, tc := range []struct {
		n       *simNode
		deletes bool
	}{{b, false}, {a, true}} {
		mem, m, oldest, newest := guardFixture(t, tc.n.l.Check)
		run, err := m.Run(context.Background(), retention.TriggerGuard, "")
		if err != nil {
			t.Fatal(err)
		}
		_, _, oldKept := mem.Index(oldest)
		_, _, newKept := mem.Index(newest)
		if oldKept == tc.deletes || !newKept || (run.Deleted > 0) != tc.deletes {
			t.Errorf("%s: deleted %d, oldest kept %v, calls %v", tc.n.l.Self.NodeID, run.Deleted, oldKept, mem.Calls)
		}
	}
	// Writes work again: a renews and detections run again; the guard
	// never stopped.
	s.os.Block(false)
	s.run(5 * time.Second)
	if a.l.Frozen() || !a.l.Holding() || s.lease().Epoch != 1 {
		t.Fatalf("after the block: %+v", a.l.View())
	}
	eventually(t, "detections to run again", func() bool { st, n := normal.state(); return st == 2 && n == 1 })
	if st, g := guard.state(); st != 1 || g != 1 {
		t.Errorf("guard restarted: %d starts", st)
	}
}

func TestSetJobsKeepsTheEpoch(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	p1, p2 := &probe{}, &probe{}
	a.l.SetJobs([]Job{p1.job("one", false)})
	s.run(time.Second)
	eventually(t, "job one", func() bool { _, r := p1.state(); return r == 1 })
	a.l.SetJobs(nil)
	if _, r := p1.state(); r != 0 {
		t.Fatal("SetJobs returned before the old jobs ended")
	}
	a.l.SetJobs([]Job{p2.job("two", false)})
	eventually(t, "job two", func() bool { _, r := p2.state(); return r == 1 })
	s.run(time.Minute)
	if a.l.Epoch() != 1 || s.lease().Epoch != 1 {
		t.Errorf("epoch %d", a.l.Epoch())
	}
}

// guardFixture is a full disk with three days of events, 40, 30 and 20
// days old, and a retention manager whose steps are fenced by fence.
func guardFixture(t *testing.T, fence func(context.Context) error) (mem *retention.Memory, m *retention.Manager, oldest, newest string) {
	t.Helper()
	now := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
	mem = retention.NewMemory()
	for _, ago := range []int{40, 30, 20} {
		mem.AddIndex(retention.IndexName("s", "endpoint", now.AddDate(0, 0, -ago)), 10<<30)
	}
	mem.DiskTotal, mem.DiskBase = 100<<30, 66<<30 // 96% used
	dir := t.TempDir()
	m = &retention.Manager{Cluster: mem, Prefix: "s",
		Store:   retention.NewStore(filepath.Join(dir, "retention.yaml")),
		Archive: &retention.Archive{Dir: filepath.Join(dir, "archive")}, HistoryFile: filepath.Join(dir, "history.json"),
		Now: func() time.Time { return now }, Fence: fence}
	return mem, m, retention.IndexName("s", "endpoint", now.AddDate(0, 0, -40)), retention.IndexName("s", "endpoint", now.AddDate(0, 0, -20))
}

// A second Release while the first still waits for the jobs waits too: the
// lease is given up only once they have ended.
func TestSecondReleaseWaitsForTheFirst(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	p := &probe{hold: make(chan struct{})}
	a.l.SetJobs([]Job{p.job("detections", false)})
	s.run(time.Second)
	eventually(t, "a's job", func() bool { _, r := p.state(); return r == 1 })
	done := make(chan struct{}, 2)
	go func() { a.l.Release("first"); done <- struct{}{} }()
	eventually(t, "the first release", func() bool { return a.l.View().State == releasing.String() })
	go func() { a.l.Release("second"); done <- struct{}{} }()
	s.run(5 * time.Second)
	select {
	case <-done:
		t.Fatal("a release returned while the job still runs")
	default:
	}
	if d := s.lease(); d.Holder != "n_a" || b.l.Holding() {
		t.Fatalf("given up while the job still runs: %+v", d)
	}
	close(p.hold)
	for range 2 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a release did not return once the job ended")
		}
	}
	if d := s.lease(); d.Holder != "" || d.ReleasedBy != "n_a" {
		t.Fatalf("lease %+v", d)
	}
}

// After a full disk, the jobs the freeze stopped are still waited for:
// new ones start only once they have ended, and a release or a restart's
// SetJobs waits for them.
func TestThawWaitsForTheFrozenJobs(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	normal := &probe{hold: make(chan struct{})}
	a.l.SetJobs([]Job{normal.job("detections", false)})
	s.run(time.Second)
	eventually(t, "the job", func() bool { _, r := normal.state(); return r == 1 })
	s.os.Block(true)
	s.run(15 * time.Second)
	if !a.l.Frozen() {
		t.Fatalf("not frozen: %+v", a.l.View())
	}
	s.os.Block(false)
	s.run(5 * time.Second)
	if a.l.Frozen() {
		t.Fatalf("still frozen: %+v", a.l.View())
	}
	// The stopped job has not returned: no second one runs beside it.
	if st, r := normal.state(); st != 1 || r != 1 {
		t.Fatalf("starts %d running %d", st, r)
	}
	done := make(chan struct{})
	go func() { a.l.SetJobs(nil); close(done) }()
	select {
	case <-done:
		t.Fatal("SetJobs returned while the stopped job still runs")
	case <-time.After(200 * time.Millisecond):
	}
	close(normal.hold)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SetJobs did not return once the job ended")
	}
	if _, r := normal.state(); r != 0 {
		t.Fatalf("%d still running", r)
	}
}

// A frozen lease does not move when OpenSearch takes writes again: a
// standby counts the takeover time from when writes work again, by which
// the holder has renewed.
func TestFrozenLeaseDoesNotMoveWhenWritesReturn(t *testing.T) {
	for off := time.Duration(0); off < 30*time.Second; off += 2500 * time.Millisecond {
		s := newSim(t)
		a, b := s.add("n_a", nil), s.add("n_b", nil)
		var mu sync.Mutex
		refused := false
		b.l.WritesRefused = func() bool {
			mu.Lock()
			defer mu.Unlock()
			return refused
		}
		s.run(time.Second)
		s.os.Block(true)
		s.run(5 * time.Second)
		// b's own heartbeat is refused too.
		mu.Lock()
		refused = true
		mu.Unlock()
		s.run(2*time.Minute + off)
		s.os.Block(false)
		s.run(3 * time.Second)
		mu.Lock()
		refused = false
		mu.Unlock()
		s.run(time.Minute)
		if d := s.lease(); d.Holder != "n_a" || d.Epoch != 1 || b.l.Holding() || !a.l.Holding() {
			t.Fatalf("after %v: lease %+v", off, d)
		}
	}
}

// Moving the jobs to a named server: the lease is released naming it, and
// it takes the lease while the others wait PreferWait for it.
func TestReleaseToHandsTheLeaseToTheNamedServer(t *testing.T) {
	s := newSim(t)
	a, b, c := s.add("n_a", nil), s.add("n_b", nil), s.add("n_c", nil)
	s.run(time.Second)
	if !a.l.Holding() {
		t.Fatalf("a does not hold the lease: %+v", s.lease())
	}
	a.l.ReleaseTo("an admin moved the background jobs", "n_c")
	if d := s.lease(); d.Holder != "" || d.Prefer != "n_c" || d.ReleasedBy != "n_a" {
		t.Fatalf("released lease = %+v", d)
	}
	s.run(3 * time.Second)
	if !c.l.Holding() || b.l.Holding() || a.l.Holding() {
		t.Fatalf("lease %+v: the named server did not take it", s.lease())
	}
}

// The named server never takes it: the others do once PreferWait passed.
func TestReleaseToAnAbsentServerFallsBack(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	s.run(time.Second)
	a.l.ReleaseTo("an admin moved the background jobs", "n_gone")
	a.paused = true
	s.run(DefaultTiming.PreferWait / 2)
	if b.l.Holding() {
		t.Fatal("b took the lease before the named server had its turn")
	}
	s.run(DefaultTiming.PreferWait + 3*time.Second)
	if !b.l.Holding() {
		t.Fatalf("nobody took the lease: %+v", s.lease())
	}
}
