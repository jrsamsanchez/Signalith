package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fast is a timing for tests on the real clock.
var fast = Timing{
	Heartbeat: 200 * time.Millisecond, Offline: 600 * time.Millisecond, IdentityWatch: 800 * time.Millisecond,
	Renew: 200 * time.Millisecond, Retry: 50 * time.Millisecond, Fence: time.Second, Takeover: 1500 * time.Millisecond,
	Watch: 50 * time.Millisecond, ReleaseWait: 3 * time.Second, PreferWait: 200 * time.Millisecond,
	ClockCheck: time.Second, FilesCheck: time.Second, FilesWait: 300 * time.Millisecond,
}

func testOptions(name string) LocalOptions {
	return LocalOptions{
		Hostname:  func() (string, error) { return name, nil },
		MachineID: func() string { return "machine-1" },
	}
}

func TestOpenLocal(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(l.Identity.NodeID, "n_") || l.Identity.Name != "siem-a" || l.LastBoot != "" || !strings.HasPrefix(l.BootID, "b_") {
		t.Fatalf("identity %+v boot %q last %q", l.Identity, l.BootID, l.LastBoot)
	}
	// A second process (or a second open in this one) is refused.
	if _, err := OpenLocal(dir, testOptions("siem-a")); err == nil || !strings.Contains(err.Error(), "another Signalith process uses the state folder") {
		t.Fatalf("second open: %v", err)
	}
	if err := l.WriteLastBoot(); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// The next start keeps the identity and knows the last boot; a name
	// set in signalith.yaml wins and is kept.
	o := testOptions("other-host")
	o.Name = "siem-1"
	l2, err := OpenLocal(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Identity.NodeID != l.Identity.NodeID || l2.Identity.Name != "siem-1" || l2.LastBoot != l.BootID || l2.BootID == l.BootID {
		t.Fatalf("reopened %+v last %q", l2.Identity, l2.LastBoot)
	}
	l2.Close()
	l3, err := OpenLocal(dir, testOptions("other-host"))
	if err != nil {
		t.Fatal(err)
	}
	if l3.Identity.Name != "siem-1" || l3.Moved {
		t.Errorf("name %q moved %v", l3.Identity.Name, l3.Moved)
	}
	l3.Close()
	// The folder restored on another computer: a warning, same identity.
	moved := testOptions("x")
	moved.MachineID = func() string { return "machine-2" }
	l4, err := OpenLocal(dir, moved)
	if err != nil {
		t.Fatal(err)
	}
	if !l4.Moved || len(l4.Warnings) == 0 || l4.Identity.NodeID != l.Identity.NodeID {
		t.Errorf("moved %v warnings %v", l4.Moved, l4.Warnings)
	}
	l4.Close()
	// A damaged identity is never replaced silently.
	if err := os.WriteFile(filepath.Join(dir, nodeFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(dir, testOptions("x")); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("damaged: %v", err)
	}
}

func TestNamesInContainers(t *testing.T) {
	for host, want := range map[string]string{
		"4f2a91c07b3e": "signalith-1", // a random container id
		"siem-b":       "siem-b",      // a fixed hostname: in the compose file
		"":             "signalith-1",
	} {
		o := LocalOptions{InContainer: true, Hostname: func() (string, error) { return host, nil }}
		if got := hostName(o); got != want {
			t.Errorf("%q: %q, want %q", host, got, want)
		}
	}
	if got := hostName(LocalOptions{Hostname: func() (string, error) { return "WIN SERVER/1", nil }}); got != "WIN-SERVER-1" {
		t.Errorf("odd name: %q", got)
	}
	dir := t.TempDir()
	l, err := OpenLocal(dir, LocalOptions{InContainer: true, Hostname: func() (string, error) { return "4f2a91c07b3e", nil },
		MachineID: func() string { return "m" }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Identity.MachineID != "" || l.Identity.Name != "signalith-1" {
		t.Errorf("container identity %+v", l.Identity)
	}
}

func TestLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(path); !errors.Is(err, errLocked) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock2, err := lockFile(path)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

// testNode starts a node on a state folder with a fake OpenSearch.
func testNode(t *testing.T, dir string, c *store.Client, eligible bool) *Node {
	t.Helper()
	l, err := OpenLocal(dir, testOptions("host-"+filepath.Base(dir)))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
	ctx, cancel := context.WithCancel(context.Background())
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: eligible, Listen: "0.0.0.0:8080"})
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	return n
}

// crash stops a node the way a killed process stops: no release, no last
// heartbeat, and its lock released.
func crash(n *Node) {
	n.mu.Lock()
	cancel, done := n.cancel, n.loopDone
	n.mu.Unlock()
	cancel()
	<-done
	n.lease.Abandon("crashed")
	n.Close()
}

func waitReady(t *testing.T, n *Node, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if ok, _ := n.Ready(); ok {
			return
		}
		if time.Now().After(deadline) {
			_, why := n.Ready()
			t.Fatalf("%s not ready after %v: %s", n.Name(), within, why)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func heartbeatOf(t *testing.T, os *ostest.Server, id string) Heartbeat {
	t.Helper()
	b, _ := json.Marshal(os.Source("s_runtime", nodeDocID(id)))
	var hb Heartbeat
	_ = json.Unmarshal(b, &hb)
	return hb
}

func TestCrashRestartWithinASecondPassesTheIdentityCheck(t *testing.T) {
	os := ostest.New(t)
	c := store.New(store.Config{URL: os.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	crash(a)
	// The same folder starts again at once. The heartbeat it finds was
	// written by this folder's last process, so it does not wait.
	l, err := OpenLocal(dir, testOptions("host"))
	if err != nil {
		t.Fatal(err)
	}
	if l.LastBoot != a.local.BootID {
		t.Fatalf("last boot %q, want %q", l.LastBoot, a.local.BootID)
	}
	timing := fast
	timing.IdentityWatch = 12 * time.Second
	b := New(Options{Local: l, Version: "1.0.0", Timing: timing})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer l.Close()
	start := time.Now()
	b.Start(ctx)
	b.Use(c, "s", Settings{Eligible: true})
	waitReady(t, b, time.Second)
	if took := time.Since(start); took > time.Second {
		t.Errorf("the identity check took %v", took)
	}
	if hb := heartbeatOf(t, os, b.ID()); hb.BootID != l.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
	select {
	case err := <-b.Fatal():
		t.Fatalf("refused: %v", err)
	default:
	}
}

// copyIdentity copies node.id into a new state folder, as a cloned
// computer or a copied folder would.
func copyIdentity(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	b, err := os.ReadFile(filepath.Join(from, nodeFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, nodeFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return to
}

func TestForeignAdvancingHeartbeatRefusesStart(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	b := testNode(t, copyIdentity(t, dir), c, true)
	if b.ID() != a.ID() {
		t.Fatal("not a copy")
	}
	select {
	case err := <-b.Fatal():
		if !strings.Contains(err.Error(), "is using this server's identity") || !strings.Contains(err.Error(), "signalith cluster new-identity") {
			t.Errorf("message: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a copy of a live server's identity started")
	}
	if ok, why := b.Ready(); ok || why != NotReadyIdentity {
		t.Errorf("ready %v %s", ok, why)
	}
	// It never wrote over the live server's heartbeat, and never ran the
	// jobs.
	if hb := heartbeatOf(t, fos, a.ID()); hb.BootID != a.local.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
	if b.lease.Holding() {
		t.Error("the copy holds the lease")
	}
}

func TestStaleCopyOfAnIdentityStarts(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	dir := t.TempDir()
	// a has an address of its own, pulled out when it crashes: a heartbeat
	// it sent just before would otherwise land while b watches, and b
	// would rightly take a for alive.
	plug := fos.Plug(t)
	a := testNode(t, dir, store.New(store.Config{URL: plug.URL}), true)
	waitReady(t, a, 5*time.Second)
	crash(a)
	plug.Pull()
	// The folder restored from a backup elsewhere, with its old server
	// gone: the heartbeat does not change, so it is a stale copy.
	b := testNode(t, copyIdentity(t, dir), c, true)
	waitReady(t, b, 5*time.Second)
	if hb := heartbeatOf(t, fos, b.ID()); hb.BootID != b.local.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
}

func TestTwoServersOneRunsTheJobs(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, false)
	waitReady(t, a, 5*time.Second)
	waitReady(t, b, 5*time.Second)
	var st Status
	deadline := time.Now().Add(5 * time.Second)
	for {
		st = b.Status()
		if len(st.Servers) == 2 && st.Jobs.HolderName == a.Name() && st.Servers[0].State == StateReady && st.Servers[1].State == StateReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, s := range st.Servers {
		want := map[string]string{a.ID(): "runs", b.ID(): "not_eligible"}[s.NodeID]
		if s.Jobs != want || s.State != StateReady {
			t.Errorf("%s: jobs %q state %q", s.Name, s.Jobs, s.State)
		}
	}
	if !a.RunsJobs() || b.RunsJobs() || b.JobHolder() != a.Name() {
		t.Error("jobs on the wrong server")
	}
	// a stops: b sees it stopped at once, and the warning that nobody runs
	// the jobs.
	a.Stop()
	if d := heartbeatOf(t, fos, a.ID()); d.State != StateStopped {
		t.Errorf("last heartbeat %q", d.State)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		st = b.Status()
		stopped := false
		for _, s := range st.Servers {
			stopped = stopped || s.NodeID == a.ID() && s.State == StateStopped && s.OfflineSince != nil
		}
		if stopped && len(st.Warnings) > 0 && strings.Contains(st.Warnings[0].Text, "No server is running") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCrashedServerShowsOffline(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	waitReady(t, b, 5*time.Second)
	// Whoever holds the jobs crashes; the other takes over and shows it
	// offline.
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() && !b.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("nobody took the jobs")
		}
		time.Sleep(10 * time.Millisecond)
	}
	holder, other := a, b
	if b.RunsJobs() {
		holder, other = b, a
	}
	crash(holder)
	deadline = time.Now().Add(10 * time.Second)
	for {
		st := other.Status()
		offline := false
		for _, s := range st.Servers {
			offline = offline || s.NodeID == holder.ID() && s.State == StateOffline
		}
		if offline && other.RunsJobs() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v runs %v", st, other.RunsJobs())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A server that starts finds the others as they were last written, and
// says how long ago that was, not merely that it was a while.
func TestStartedServerSaysWhenOthersWereLastSeen(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	ago := func(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }
	fos.Put("s_runtime", nodeDocID("n_stopped"), map[string]any{"kind": "node", "node_id": "n_stopped", "name": "old",
		"boot_id": "b1", "state": StateStopped, "started_at": ago(50 * time.Hour), "heartbeat_at": ago(2 * time.Hour)})
	fos.Put("s_runtime", nodeDocID("n_killed"), map[string]any{"kind": "node", "node_id": "n_killed", "name": "killed",
		"boot_id": "b2", "state": StateReady, "started_at": ago(time.Hour), "heartbeat_at": ago(10 * time.Minute)})
	a := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	want := map[string]struct {
		state string
		ago   time.Duration
	}{"old": {StateStopped, 2 * time.Hour}, "killed": {StateOffline, 10 * time.Minute}}
	var servers []ServerStatus
	until(t, 5*time.Second, "both listed", func() bool {
		servers = a.Status().Servers
		return len(servers) == 3
	})
	for _, s := range servers {
		w, ok := want[s.Name]
		if !ok {
			continue
		}
		delete(want, s.Name)
		if s.State != w.state || s.SeenAgo == nil || *s.SeenAgo < w.ago-time.Minute || *s.SeenAgo > w.ago+time.Minute {
			t.Errorf("%s: state %s, last seen %v ago; want %s, %v ago", s.Name, s.State, s.SeenAgo, w.state, w.ago)
		}
	}
	if len(want) > 0 {
		t.Errorf("not listed: %v", want)
	}
}

// offClock is the real clock with its wall time off by a fixed amount,
// as on a computer whose clock is wrong.
type offClock struct {
	Clock
	off time.Duration
}

func (c offClock) Now() time.Time { return c.Clock.Now().Add(c.off) }

// startNode starts a node with its own clock and fingerprints.
func startNode(t *testing.T, dir string, c *store.Client, clock Clock, fp func() Fingerprints) *Node {
	t.Helper()
	l, err := OpenLocal(dir, testOptions("host-"+filepath.Base(dir)))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast, Clock: clock})
	ctx, cancel := context.WithCancel(context.Background())
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: true, Listen: "0.0.0.0:8080", Fingerprints: fp})
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	return n
}

func until(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A server alone runs the jobs whatever its clock says, and says the
// clock is wrong.
func TestClockFarOffAloneStillRunsTheJobs(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := startNode(t, t.TempDir(), c, offClock{NewRealClock(), 45 * time.Second}, nil)
	until(t, 5*time.Second, "the offset in the heartbeat", func() bool {
		hb := heartbeatOf(t, fos, a.ID())
		return hb.ClockOffsetMS != nil && *hb.ClockOffsetMS < -44000 && *hb.ClockOffsetMS > -46000
	})
	until(t, 5*time.Second, "the jobs", a.RunsJobs)
	found := false
	for _, w := range a.Status().Warnings {
		found = found || w.Level == "amber" && strings.Contains(w.Text, "clock is 45s off OpenSearch's")
	}
	if !found {
		t.Errorf("warnings %+v", a.Status().Warnings)
	}
}

// A server whose clock is far off leaves the jobs to one whose clock is
// right while that one is up, and takes them back when it is gone.
func TestClockFarOffLeavesTheJobsToAServerWithTheRightClock(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := startNode(t, t.TempDir(), c, offClock{NewRealClock(), 45 * time.Second}, nil)
	until(t, 5*time.Second, "a to run the jobs", a.RunsJobs)
	b := startNode(t, t.TempDir(), c, nil, nil)
	until(t, 10*time.Second, "b to run the jobs", func() bool { return b.RunsJobs() && !a.RunsJobs() })
	// It stays so.
	time.Sleep(3 * fast.Takeover)
	if !b.RunsJobs() || a.RunsJobs() {
		t.Fatal("the jobs moved back to the server whose clock is wrong")
	}
	crash(b)
	until(t, 10*time.Second, "a to take the jobs back", a.RunsJobs)
}

// A copy of a running server's state folder, with its last_boot, takes
// itself for that server's next start. The running server goes on; the
// copy stops.
func TestLiveCopyWithLastBootStops(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	until(t, 5*time.Second, "a to run the jobs", a.RunsJobs)
	to := copyIdentity(t, dir)
	b, err := os.ReadFile(filepath.Join(dir, "cluster", lastBootName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(to, "cluster"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, "cluster", lastBootName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	cp := testNode(t, to, c, true)
	if cp.local.LastBoot != a.local.BootID {
		t.Fatalf("the copy's last boot %q, want %q", cp.local.LastBoot, a.local.BootID)
	}
	select {
	case err := <-cp.Fatal():
		if !strings.Contains(err.Error(), "is using this server's identity") {
			t.Errorf("message: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a copy of a running server's folder kept running")
	}
	if cp.lease.Holding() {
		t.Error("the copy holds the lease")
	}
	// The running server never stopped, and keeps its heartbeat.
	if ok, why := a.Ready(); !ok || !a.RunsJobs() {
		t.Errorf("a: ready %v (%s), runs jobs %v", ok, why, a.RunsJobs())
	}
	until(t, 5*time.Second, "a's heartbeat back", func() bool { return heartbeatOf(t, fos, a.ID()).BootID == a.local.BootID })
	// a can only tell that a copy was started when the copy wrote its
	// heartbeat. The copy may see a's heartbeat first and stop before it
	// writes one; then there is nothing to warn about.
	cp.mu.Lock()
	wrote := !cp.hb.ver.IsZero()
	cp.mu.Unlock()
	if !wrote {
		return
	}
	found := false
	for _, w := range a.Status().Warnings {
		found = found || strings.Contains(w.Text, "A copy of this server's state folder was started")
	}
	if !found {
		t.Errorf("a's warnings %+v", a.Status().Warnings)
	}
}

// A heartbeat write that hangs does not hold up the lease: the lease runs
// in its own loop.
func TestHangingHeartbeatDoesNotHoldUpTheLease(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	until(t, 5*time.Second, "the jobs", a.RunsJobs)
	release := make(chan struct{})
	defer close(release)
	fos.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "node:") || strings.Contains(p, "node%3A") || strings.Contains(p, "_search") || strings.Contains(p, "_nodes") {
			<-release
		}
		return nil
	})
	time.Sleep(3 * fast.Fence)
	if !a.RunsJobs() {
		t.Fatal("a lost the lease while its heartbeat hung")
	}
}

// Fingerprints that cannot be worked out in time (an archive share that
// does not answer) neither hold up the heartbeat nor let a server take the
// jobs over blindly.
func TestSlowFingerprintsHoldNothingUp(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	hang := make(chan struct{})
	defer close(hang)
	a := startNode(t, t.TempDir(), c, nil, func() Fingerprints { return Fingerprints{Retention: "r"} })
	until(t, 5*time.Second, "a to run the jobs", a.RunsJobs)
	b := startNode(t, t.TempDir(), c, nil, func() Fingerprints { <-hang; return Fingerprints{Retention: "r"} })
	waitReady(t, b, 5*time.Second)
	until(t, 5*time.Second, "b's heartbeats", func() bool { return heartbeatOf(t, fos, b.ID()).State == StateReady })
	crash(a)
	// Wait for b to give its reason rather than a fixed time: under the
	// race detector the takeover check can run late.
	deadline := time.Now().Add(2*fast.Takeover + 2*fast.FilesWait + 10*time.Second)
	for {
		if b.RunsJobs() {
			t.Fatal("b took the jobs over without knowing its files")
		}
		why := b.lease.View().CannotTake
		if strings.Contains(why, "could not be read in time") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("why: %q", why)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(2 * fast.Takeover)
	if b.RunsJobs() {
		t.Fatal("b took the jobs over without knowing its files")
	}
}

func TestUseAnotherOpenSearchMovesTheLease(t *testing.T) {
	os1, os2 := ostest.New(t), ostest.New(t)
	c1, c2 := store.New(store.Config{URL: os1.URL}), store.New(store.Config{URL: os2.URL})
	a := testNode(t, t.TempDir(), c1, true)
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("no lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.Use(c2, "s", Settings{Eligible: true})
	if d := os1.Source("s_runtime", leaseID); d["holder"] != "" || d["released_by"] != a.ID() {
		t.Errorf("old lease %v", d)
	}
	deadline = time.Now().Add(5 * time.Second)
	for os2.Source("s_runtime", leaseID)["holder"] != a.ID() {
		if time.Now().After(deadline) {
			t.Fatal("no lease on the new OpenSearch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Turning detections.scheduler off gives the lease up.
	a.Use(c2, "s", Settings{Eligible: false})
	deadline = time.Now().Add(5 * time.Second)
	for os2.Source("s_runtime", leaseID)["holder"] != "" {
		if time.Now().After(deadline) {
			t.Fatal("still holding with the scheduler off")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadyNeedsOpenSearch(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	fos.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "unavailable"} })
	a := testNode(t, t.TempDir(), c, true)
	time.Sleep(200 * time.Millisecond)
	if ok, why := a.Ready(); ok || why != NotReadyOpenSearch {
		t.Errorf("ready %v %q", ok, why)
	}
	fos.SetFault(nil)
	waitReady(t, a, 5*time.Second)
	// A full disk still answers: the server stays ready.
	fos.Block(true)
	time.Sleep(3 * fast.Heartbeat)
	if ok, why := a.Ready(); !ok {
		t.Errorf("not ready with a full disk: %s", why)
	}
	if st := a.Status(); !st.WritesRefused {
		t.Errorf("status %+v", st)
	}
}

// Every server's list shows a server whose files differ from the job
// holder's, and says how to fix it: the holder's own list too, not only
// the list of the server that would not take over.
func TestEveryServerShowsWhoCannotTakeOver(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	start := func(retention string) *Node {
		l, err := OpenLocal(t.TempDir(), testOptions("host-"+retention))
		if err != nil {
			t.Fatal(err)
		}
		n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
		ctx, cancel := context.WithCancel(context.Background())
		n.Start(ctx)
		n.Use(c, "s", Settings{Eligible: true, Fingerprints: func() Fingerprints {
			return Fingerprints{Retention: retention, Feeds: "f", Detections: "d"}
		}})
		t.Cleanup(func() {
			cancel()
			n.Close()
		})
		return n
	}
	a := start("r1")
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("no lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	b := start("r2")
	waitReady(t, b, 5*time.Second)
	check := func(n *Node) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			st := n.Status()
			var row ServerStatus
			for _, s := range st.Servers {
				if s.NodeID == b.ID() {
					row = s
				}
			}
			text := ""
			for _, w := range st.Warnings {
				text += w.Level + ": " + w.Text + "\n"
			}
			if row.Jobs == "standby" && row.CannotTakeOver == "its retention policies differ from "+a.Name()+"'s" &&
				strings.Contains(text, "amber: "+b.Name()+" would not take the background jobs over if "+a.Name()+" stopped, because its retention policies differ from "+a.Name()+"'s.") &&
				strings.Contains(text, "Make "+b.Name()+"'s retention policies (retention.yaml in the lookups folder, and retention in signalith.yaml) the same as "+a.Name()+"'s, then restart "+b.Name()+".") {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: row %+v warnings:\n%s", n.Name(), row, text)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	check(a)
	check(b)
	// The holder crashes: b does not take over, and says why in red.
	crash(a)
	deadline = time.Now().Add(10 * time.Second)
	for {
		st := b.Status()
		if len(st.Warnings) > 0 && st.Warnings[0].Level == "red" && strings.HasPrefix(st.Warnings[0].Text, "No server is running detections") &&
			strings.Contains(st.Warnings[0].Text, "because its retention policies differ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("warnings %+v", st.Warnings)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b.RunsJobs() {
		t.Error("b took the jobs over with different retention policies")
	}
}

func TestFixFiles(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		want  string
	}{
		{[]string{"detections folder"}, "Make siem-b's detections folder the same as siem-a's, then restart siem-b."},
		{[]string{"threat intel feeds", "detections folder"}, "Make siem-b's threat intel feeds (intel_feeds.yaml in the lookups folder, and intel in signalith.yaml) and detections folder the same as siem-a's, then restart siem-b."},
		{[]string{"archive folder"}, "Keep archives in one shared folder: set retention.archive_dir to the same shared folder on every server, then restart them."},
		{nil, "Make the files the jobs use the same on siem-b as on siem-a, then restart siem-b."},
	} {
		if got := fixFiles(tc.parts, "siem-b", "siem-a"); got != tc.want {
			t.Errorf("%v:\n got %s\nwant %s", tc.parts, got, tc.want)
		}
	}
}

// The runtime index has an index template, so when someone deletes it
// while servers run, OpenSearch makes it again with its own settings.
func TestRuntimeIndexTemplate(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	ctx := context.Background()
	hasSettings := func(index string) bool {
		body := string(fos.IndexBody(index))
		return strings.Contains(body, `"dynamic":"false"`) && strings.Contains(body, `"auto_expand_replicas":"0-1"`)
	}
	// A write to a missing index creates it from the template.
	if err := ensureRuntimeTemplate(ctx, c, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Create(ctx, "x_runtime", "node:n_1", map[string]any{"kind": "node"}, false); err != nil {
		t.Fatal(err)
	}
	if !hasSettings("x_runtime") {
		t.Errorf("auto-created with %s", fos.IndexBody("x_runtime"))
	}
	a := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	if !strings.Contains(strings.Join(fos.Templates(), ","), "s_runtime") {
		t.Fatalf("templates %v", fos.Templates())
	}
	if err := c.Do(ctx, http.MethodDelete, "/s_runtime", nil, nil); err != nil {
		t.Fatal(err)
	}
	until(t, 5*time.Second, "the runtime index again", func() bool {
		return strings.Contains(strings.Join(fos.Indices(), ","), "s_runtime") && heartbeatOf(t, fos, a.ID()).NodeID == a.ID()
	})
	if !hasSettings("s_runtime") {
		t.Errorf("made again with %s", fos.IndexBody("s_runtime"))
	}
}

// The banner every signed-in user sees while OpenSearch's disk is full
// never says space is being freed: whether the holder's disk guard is on,
// and has days it may delete, is known only there. The admins' text says
// what the guard does unless it was turned off.
func TestFullDiskBannerClaimsNothing(t *testing.T) {
	text, banner := fullDiskWarning(JobsStatus{Holder: "n_a", HolderName: "siem-a"})
	if strings.Contains(banner, "deleting") || strings.Contains(banner, "free") || !strings.Contains(banner, "refuses new events") {
		t.Errorf("banner %q", banner)
	}
	if !strings.Contains(text, "siem-a keeps only the retention disk guard running: unless it was turned off") {
		t.Errorf("text %q", text)
	}
	if _, banner := fullDiskWarning(JobsStatus{}); !strings.Contains(banner, "No server is deleting old days") {
		t.Errorf("no holder: %q", banner)
	}
}

func TestHeartbeatCarriesTheSecuritySummary(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, false)
	waitReady(t, a, 5*time.Second)
	at := time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC)
	a.SetSecurity(SecuritySummary{CheckedAt: &at, Risk: 1, Attention: 2, CAScope: "strict"})
	until(t, 5*time.Second, "b sees a's security check", func() bool {
		for _, s := range b.Status().Servers {
			if s.NodeID == a.ID() && s.Detail != nil && s.Detail.Security != nil && s.Detail.Security.Risk == 1 {
				sec := s.Detail.Security
				return sec.Attention == 2 && sec.CAScope == "strict" && sec.CheckedAt != nil && sec.CheckedAt.Equal(at)
			}
		}
		return false
	})
	// Before its first check a server says so, with no time.
	if d := heartbeatOf(t, fos, b.ID()); d.Security == nil || d.Security.CheckedAt != nil {
		t.Errorf("unchecked server: %+v", d.Security)
	}
}

// selfOf is this server's own row in its status.
func selfOf(st Status) ServerStatus {
	for _, s := range st.Servers {
		if s.Self {
			return s
		}
	}
	return ServerStatus{}
}

// redWarning waits for this server's red warning about OpenSearch.
func redWarning(t *testing.T, n *Node) (Status, Warning) {
	t.Helper()
	var st Status
	until(t, 5*time.Second, "a red warning about OpenSearch", func() bool {
		st = n.Status()
		return len(st.Warnings) > 0 && st.Warnings[0].Level == "red" && strings.Contains(st.Warnings[0].Text, "OpenSearch")
	})
	return st, st.Warnings[0]
}

// settledWarning waits for the red warning about OpenSearch and for this
// server's own entry to agree with it: the warning can show before the
// failed heartbeat has recorded how OpenSearch failed, or why this server
// doesn't run the jobs.
func settledWarning(t *testing.T, n *Node, agrees func(self ServerStatus) bool) (Status, Warning) {
	t.Helper()
	var st Status
	var w Warning
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, w = redWarning(t, n)
		if self := selfOf(st); self.Detail != nil && agrees(self) || time.Now().After(deadline) {
			return st, w
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Each way OpenSearch turns a server away is told as what it is: only a
// refusal of Signalith's own user gets the advice to give that user more
// rights, a server that reached OpenSearch is never said not to reach it,
// and an error that ends in a period gets no second one.
func TestRefusalsAreWordedByKind(t *testing.T) {
	notInit := func(m, p string) *ostest.Fault { f := ostest.NotInitialized; return &f }
	for _, c := range []struct {
		name    string
		fault   func(m, p string) *ostest.Fault
		state   string
		problem string
		why     string
		text    []string
		not     []string
		banner  string
	}{
		{name: "security settings not loaded", fault: notInit, state: StateRefused, problem: "not_initialized",
			why: "OpenSearch's security settings aren't loaded",
			text: []string{
				"OpenSearch is running, but its security settings aren't loaded, so it refuses every request from this server. ",
				"Until they are, this server runs no detections, threat intel downloads or retention. ",
				"If OpenSearch started only a few minutes ago, wait: it loads them as it starts. ",
				"Otherwise, with the Docker quick start, run docker compose -f deploy/docker/docker-compose.yml up -d again from the Signalith folder: " +
					"it re-runs the step that loads OpenSearch's security settings. ",
				"If that doesn't load them, docs/opensearch-security.md#if-opensearchs-security-settings-arent-loaded says what to do. ",
				"Without Docker, load them with securityadmin.sh, as docs/opensearch-security.md#3-load-the-security-settings shows. ",
				"This server tries again by itself, so it needs no restart.",
			},
			not:    []string{"right to", "can't reach", "Can't reach", "setup step"},
			banner: "OpenSearch's security settings aren't loaded, so it refuses this server, which runs no background jobs."},
		{name: "busy", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 503, Type: "process_cluster_event_timeout_exception"}
		}, state: StateRefused, problem: "busy", why: "OpenSearch is too busy to answer it in time",
			text: []string{
				"OpenSearch is too busy to answer this server in time (503 process_cluster_event_timeout_exception on s_runtime), " +
					"so this server runs no detections, threat intel downloads or retention for now. ",
				"Signalith keeps trying, and goes on by itself once OpenSearch catches up.",
				"If this lasts more than a few minutes, check that OpenSearch's computer has enough memory and CPU, and what OpenSearch's log says. " +
					"With the Docker quick start, show it with docker compose -f deploy/docker/docker-compose.yml logs opensearch from the Signalith folder; " +
					"otherwise it is in /var/log/opensearch, or in the logs folder where you unpacked OpenSearch.",
				"The error was: opensearch returned 503: process_cluster_event_timeout_exception: injected by the test.",
			},
			not:    []string{"right to", "can't reach"},
			banner: "OpenSearch is too busy to answer this server, so it runs no background jobs for now."},
		{name: "queue full", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 429, Type: "rejected_execution_exception"}
		}, state: StateRefused, problem: "busy", text: []string{"OpenSearch is too busy to answer this server in time (429 rejected_execution_exception on s_runtime)"},
			not: []string{"right to"}},
		{name: "no rights", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 403, Type: "security_exception"}
		}, state: StateRefused, problem: "forbidden", why: "OpenSearch refused its heartbeat (403 security_exception on s_runtime)",
			text: []string{"OpenSearch refused this server's heartbeat (403 security_exception on s_runtime), so this server runs no detections, threat intel downloads or retention. " +
				"Give Signalith's OpenSearch user the right to create, read and write s_runtime (or s_*). The error was: opensearch returned 403: security_exception: injected by the test."},
			banner: "OpenSearch refuses this server, so it runs no background jobs."},
		{name: "sign-in", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 401, Type: "security_exception"}
		}, state: StateRefused, problem: "auth", why: "OpenSearch refuses its sign-in",
			text: []string{"OpenSearch refused this server's sign-in (401 security_exception on s_runtime)", "on the Settings page."},
			not:  []string{"right to"}},
		{name: "not ready", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 503, Type: "cluster_manager_not_discovered_exception"}
		}, state: StateRefused, problem: "unavailable", why: "OpenSearch isn't ready",
			text: []string{"OpenSearch isn't ready to answer this server (503 cluster_manager_not_discovered_exception on s_runtime)",
				"OpenSearch's log says why it isn't ready. With the Docker quick start, show it with docker compose -f deploy/docker/docker-compose.yml logs opensearch"},
			not: []string{"right to"}},
		// A block, by itself on a full disk or set by an admin: not a
		// matter of rights. OpenSearch answers so even for an index that
		// exists while it blocks making indices.
		{name: "index creation blocked", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 403, Type: "index_create_block_exception"}
		}, state: StateRefused, problem: "blocked", why: "OpenSearch refuses writes",
			text: []string{"OpenSearch refuses writes (403 index_create_block_exception on s_runtime), so this server runs no detections, threat intel downloads or retention. " +
				"OpenSearch does this when its disk is full, or when someone set a block such as cluster.blocks.read_only: give OpenSearch more disk, or remove the block. " +
				"This server goes on by itself after that."},
			not:    []string{"right to"},
			banner: "OpenSearch refuses writes, so this server runs no background jobs."},
		// Any other error answer is not about rights either, and is not
		// labelled as a refusal of Signalith.
		{name: "other error", fault: func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: 400, Type: "index_closed_exception"}
		}, state: StateRefused, problem: "other", why: "OpenSearch answered its heartbeat with an error (400 index_closed_exception on s_runtime)",
			text: []string{"OpenSearch answered this server's heartbeat with an error (400 index_closed_exception on s_runtime), " +
				"so this server runs no detections, threat intel downloads or retention. Signalith keeps trying. OpenSearch's log may say why. " +
				"With the Docker quick start, show it with docker compose -f deploy/docker/docker-compose.yml logs opensearch"},
			not:    []string{"right to", "refuse"},
			banner: "OpenSearch answers this server with an error, so it runs no background jobs."},
	} {
		t.Run(c.name, func(t *testing.T) {
			fos := ostest.New(t)
			fos.SetFault(c.fault)
			n := testNode(t, t.TempDir(), store.New(store.Config{URL: fos.URL}), true)
			st, w := settledWarning(t, n, func(self ServerStatus) bool {
				return self.Detail.OpenSearch.Problem == c.problem && (c.why == "" || self.Detail.NotEligible == c.why)
			})
			for _, want := range c.text {
				if !strings.Contains(w.Text, want) {
					t.Errorf("the warning lacks %q:\n%s", want, w.Text)
				}
			}
			for _, bad := range c.not {
				if strings.Contains(w.Text, bad) {
					t.Errorf("the warning says %q:\n%s", bad, w.Text)
				}
			}
			if strings.Contains(w.Text, "..") || strings.Contains(w.Banner, "..") {
				t.Errorf("a doubled period:\n%s\n%s", w.Text, w.Banner)
			}
			if c.banner != "" && w.Banner != c.banner {
				t.Errorf("banner %q", w.Banner)
			}
			self := selfOf(st)
			if self.State != c.state || self.Detail == nil || self.Detail.OpenSearch.Problem != c.problem || self.Detail.OpenSearch.OK {
				t.Errorf("state %q, opensearch %+v", self.State, self.Detail.OpenSearch)
			}
			if c.why != "" && self.Detail.NotEligible != c.why {
				t.Errorf("why it doesn't run the jobs: %q", self.Detail.NotEligible)
			}
			if ok, why := n.Ready(); ok || why != NotReadyOpenSearch {
				t.Errorf("ready %v %q", ok, why)
			}
			if b := n.Banners(); len(b) != 1 || b[0] != w.Banner {
				t.Errorf("banners %q", b)
			}
		})
	}
}

// A server that cannot reach OpenSearch at all says so, with the error
// ending in one period.
func TestUnreachableIsWordedAsSuch(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	n := testNode(t, t.TempDir(), store.New(store.Config{URL: "http://" + closed, Timeout: time.Second}), true)
	st, w := settledWarning(t, n, func(self ServerStatus) bool { return self.Detail.NotEligible == "it cannot reach OpenSearch" })
	if !strings.HasPrefix(w.Text, "This server can't reach OpenSearch, so it can't see the other servers and runs no background jobs. The error was: opensearch unreachable at") ||
		strings.Contains(w.Text, "..") || !strings.HasSuffix(w.Text, ".") || strings.Contains(w.Text, "right to") {
		t.Errorf("%q", w.Text)
	}
	if w.Banner != "This server can't use OpenSearch, so it runs no background jobs." {
		t.Errorf("banner %q", w.Banner)
	}
	if s := selfOf(st); s.State != StateUnreachable || s.Detail.OpenSearch.Problem != "" || s.Detail.NotEligible != "it cannot reach OpenSearch" {
		t.Errorf("%q %+v %q", s.State, s.Detail.OpenSearch, s.Detail.NotEligible)
	}
}

// An OpenSearch that takes the requests but doesn't answer in time is
// too slow, not out of reach, and is said to be so.
func TestNoAnswerIsWordedAsSuch(t *testing.T) {
	fos := ostest.New(t)
	fos.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Stall: true} })
	n := testNode(t, t.TempDir(), store.New(store.Config{URL: fos.URL, Timeout: 200 * time.Millisecond}), true)
	st, w := settledWarning(t, n, func(self ServerStatus) bool {
		return self.Detail.OpenSearch.Problem == "timeout" && self.Detail.NotEligible == "OpenSearch doesn't answer it in time"
	})
	if !strings.HasPrefix(w.Text, "OpenSearch didn't answer this server in time, so this server can't see the other servers and runs no background jobs. "+
		"Signalith keeps trying, and goes on by itself once OpenSearch answers. If this lasts more than a few minutes,") ||
		!strings.Contains(w.Text, "The error was: opensearch at "+fos.URL+" did not answer in time: ") ||
		strings.Contains(w.Text, "..") || !strings.HasSuffix(w.Text, ".") || strings.Contains(w.Text, "can't reach") || strings.Contains(w.Text, "right to") {
		t.Errorf("%q", w.Text)
	}
	if w.Banner != "OpenSearch doesn't answer this server in time, so it runs no background jobs." {
		t.Errorf("banner %q", w.Banner)
	}
	if s := selfOf(st); s.State != StateUnreachable || s.Detail.OpenSearch.Problem != "timeout" || s.Detail.NotEligible != "OpenSearch doesn't answer it in time" {
		t.Errorf("%q %+v %q", s.State, s.Detail.OpenSearch, s.Detail.NotEligible)
	}
	if ok, why := n.Ready(); ok || why != NotReadyOpenSearch {
		t.Errorf("ready %v %q", ok, why)
	}
	// It goes on by itself once OpenSearch answers again.
	fos.SetFault(nil)
	waitReady(t, n, 5*time.Second)
	until(t, 5*time.Second, "the problem cleared", func() bool {
		s := selfOf(n.Status())
		return s.State == StateReady && s.Detail.OpenSearch.Problem == ""
	})
}

// A server that ran, and then finds OpenSearch's security settings not
// loaded (OpenSearch started again without them), says so too, and that
// the other servers are shown as it last saw them; it goes on by itself
// once they are loaded.
func TestRefusedAfterRunning(t *testing.T) {
	fos := ostest.New(t)
	n := testNode(t, t.TempDir(), store.New(store.Config{URL: fos.URL}), true)
	waitReady(t, n, 5*time.Second)
	fos.SetFault(func(m, p string) *ostest.Fault { f := ostest.NotInitialized; return &f })
	st, w := settledWarning(t, n, func(self ServerStatus) bool {
		return self.State == StateRefused && self.Detail.OpenSearch.Problem == "not_initialized"
	})
	if !strings.HasPrefix(w.Text, "OpenSearch is running, but its security settings aren't loaded") ||
		!strings.HasSuffix(w.Text, "This server tries again by itself, so it needs no restart. The servers below are as it last saw them.") {
		t.Errorf("%q", w.Text)
	}
	if s := selfOf(st); s.State != StateRefused || s.Detail.OpenSearch.Problem != "not_initialized" {
		t.Errorf("%q %+v", s.State, s.Detail.OpenSearch)
	}
	fos.SetFault(nil)
	waitReady(t, n, 5*time.Second)
	// A read can make it ready before its next heartbeat clears the
	// problem.
	until(t, 5*time.Second, "the problem cleared", func() bool {
		s := selfOf(n.Status())
		return s.State == StateReady && s.Detail.OpenSearch.Problem == ""
	})
}

func TestIndexingServers(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	var nilNode *Node
	if nilNode.IndexingServers(10*time.Minute) != 1 {
		t.Error("without a node")
	}
	at := func(v *atomic.Int64) func() time.Time {
		return func() time.Time {
			if n := v.Load(); n != 0 {
				return time.Unix(n, 0)
			}
			return time.Time{}
		}
	}
	var aAt, bAt atomic.Int64
	a := testNode(t, t.TempDir(), c, true)
	a.Use(c, "s", Settings{Eligible: true, Indexed: at(&aAt)})
	// Alone and not indexing yet: itself.
	if got := a.IndexingServers(10 * time.Minute); got != 1 {
		t.Errorf("alone: %d", got)
	}
	b := testNode(t, t.TempDir(), c, false)
	b.Use(c, "s", Settings{Indexed: at(&bAt)})
	until(t, 5*time.Second, "a sees b", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.members) >= 2
	})
	// Neither has indexed: never less than 1.
	if got := a.IndexingServers(10 * time.Minute); got != 1 {
		t.Errorf("nobody indexing: %d", got)
	}
	// A server of a version before indexed_at counts while it is up.
	stopOld := make(chan struct{})
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		for {
			fos.Put("s_runtime", nodeDocID("n_old"), map[string]any{"kind": "node", "node_id": "n_old", "name": "old",
				"state": StateReady, "version": "0.9.0", "heartbeat_at": time.Now().UTC().Format(time.RFC3339Nano)})
			select {
			case <-stopOld:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	aAt.Store(time.Now().Unix())
	until(t, 5*time.Second, "a counts itself and the old one", func() bool { return a.IndexingServers(10*time.Minute) == 2 })
	bAt.Store(time.Now().Add(-2 * time.Minute).Unix())
	until(t, 5*time.Second, "a sees b's indexed_at", func() bool { return a.IndexingServers(10*time.Minute) == 3 })
	if hb := heartbeatOf(t, fos, b.ID()); hb.IndexedAt == nil || hb.IndexedAt.Unix() != bAt.Load() {
		t.Errorf("heartbeat indexed_at: %v", hb.IndexedAt)
	}
	// b last indexed 15 minutes ago: it no longer counts.
	bAt.Store(time.Now().Add(-15 * time.Minute).Unix())
	until(t, 5*time.Second, "b stops counting", func() bool { return a.IndexingServers(10*time.Minute) == 2 })
	// The old one goes offline: it no longer counts either.
	close(stopOld)
	<-oldDone
	until(t, 5*time.Second, "the old one goes offline", func() bool { return a.IndexingServers(10*time.Minute) == 1 })
}

// stepClock is a real clock whose wall time a test can step, as a clock
// correction does, without moving its monotonic time.
type stepClock struct {
	Clock
	mu  sync.Mutex
	off time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Clock.Now().Add(c.off)
}

func (c *stepClock) step(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// ClusterNow follows OpenSearch's clock, not this server's wall clock:
// a server 5 s behind works out OpenSearch's time, and a step of its
// wall clock does not move it.
func TestClusterNowFollowsOpenSearch(t *testing.T) {
	fos := ostest.New(t)
	fos.Offset = 5 * time.Second
	c := store.New(store.Config{URL: fos.URL})
	clock := &stepClock{Clock: NewRealClock()}
	n := startNode(t, t.TempDir(), c, clock, nil)
	near := func() bool {
		d := n.ClusterNow().Sub(time.Now().Add(5 * time.Second))
		return d < 50*time.Millisecond && d > -50*time.Millisecond
	}
	until(t, 5*time.Second, "OpenSearch's time", near)
	clock.step(time.Hour)
	if !near() {
		t.Errorf("a step of the wall clock moved the cluster time: %v", n.ClusterNow().Sub(time.Now()))
	}
}

// The shared configuration's state goes into the heartbeat, and a server
// it keeps out (not part of the cluster yet) does not run the jobs.
func TestSharedStatusInHeartbeatAndEligibility(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	l, err := OpenLocal(t.TempDir(), testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	var why atomic.Value
	why.Store("it is not part of the cluster yet")
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: true, Shared: func() SharedStatus {
		return SharedStatus{Mode: "legacy_b", LevelMin: 1, LevelMax: 1, ConfigSeq: 7, MaxRev: 3, Tamper: []string{"feeds"}, NotEligible: why.Load().(string)}
	}})
	waitReady(t, n, 5*time.Second)
	until(t, 5*time.Second, "the heartbeat carries the shared status", func() bool {
		hb := heartbeatOf(t, fos, n.ID())
		return hb.Mode == "legacy_b" && hb.LevelMax == 1 && hb.ConfigSeq == 7 && hb.MaxRev == 3 && len(hb.Tamper) == 1 &&
			!hb.LeaderEligible && hb.NotEligible == "it is not part of the cluster yet"
	})
	time.Sleep(3 * fast.Renew)
	if n.RunsJobs() {
		t.Fatal("a server kept out by the shared configuration took the jobs")
	}
	why.Store("")
	until(t, 5*time.Second, "it takes the jobs once it may", n.RunsJobs)
}

// The settings waiting for a restart, the shared ones refused, how far
// the settings were applied and the restart run by request go into the
// heartbeat; a server with none of them writes none of the fields.
func TestSettingsStateInHeartbeat(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	l, err := OpenLocal(t.TempDir(), testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	var busy atomic.Bool
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: true})
	waitReady(t, n, 5*time.Second)
	if src := fos.Source(RuntimeIndex("s"), nodeDocID(n.ID())); src["restart_needed"] != nil || src["restart"] != nil || src["settings_rev"] != nil {
		t.Fatalf("fields written without settings: %v", src)
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	n.Use(c, "s", Settings{Eligible: true,
		Shared: func() SharedStatus {
			return SharedStatus{Mode: "member", SettingsRev: &SettingsRev{Settings: 7, NodeCfg: 12}}
		},
		Pending: func() ([]string, []string) { return []string{"server.listen"}, []string{"server.tls.names"} },
		Restart: func() RestartStatus {
			return RestartStatus{Busy: busy.Load(), Last: &RestartResult{At: at, Error: "port 8443 is in use", RolledBack: true, Keys: []string{"server.listen"}}}
		}})
	busy.Store(true)
	until(t, 5*time.Second, "the heartbeat carries the settings' state", func() bool {
		hb := heartbeatOf(t, fos, n.ID())
		return slices.Equal(hb.RestartNeeded, []string{"server.listen"}) && slices.Equal(hb.SettingsRefused, []string{"server.tls.names"}) &&
			hb.SettingsRev != nil && *hb.SettingsRev == SettingsRev{Settings: 7, NodeCfg: 12} &&
			hb.Restart != nil && hb.Restart.Busy && hb.Restart.Last != nil && hb.Restart.Last.RolledBack && hb.Restart.Last.At.Equal(at)
	})
}

// A drained server is not ready, gives up the background jobs and does
// not take them back; resumed, it is ready again.
func TestDrainAndResume(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	b := testNode(t, t.TempDir(), c, true)
	waitReady(t, b, 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("a never ran the jobs")
		}
		time.Sleep(5 * time.Millisecond)
	}
	a.Drain("")
	if !a.Drained() {
		t.Fatal("not drained")
	}
	if ok, why := a.Ready(); ok || why != NotReadyDraining {
		t.Fatalf("ready %v (%s) while drained", ok, why)
	}
	deadline = time.Now().Add(10 * time.Second)
	for a.RunsJobs() || !b.RunsJobs() || heartbeatOf(t, fos, a.ID()).State != StateDraining {
		if time.Now().After(deadline) {
			t.Fatalf("a runs jobs %v, b %v, a's state %q", a.RunsJobs(), b.RunsJobs(), heartbeatOf(t, fos, a.ID()).State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.Resume()
	waitReady(t, a, 5*time.Second)
	if a.Drained() || !b.RunsJobs() {
		t.Error("resuming moved the jobs back")
	}
}
