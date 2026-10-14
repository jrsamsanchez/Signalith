package shared

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// W19: level 3 is raised once every server seen in 24 hours reads it; a
// server of the version before (it reads up to level 2) holds it back.
// Settings become shared only once the founder's settings were imported
// at level 3, and a server of the version before then refuses to start.
func TestLevelSharedSettings(t *testing.T) {
	e := newEnv(t)
	usersIm := func() []Importer {
		return []Importer{{Name: ImportUsers, MinLevel: LevelSharedUsers}, {Name: ImportDirectory, MinLevel: LevelSharedUsers}}
	}
	// A version that reads up to level 2 founds the cluster.
	pr5 := e.server("siem-a", func(o *RuntimeOptions) {
		o.levelMax = 2
		o.Importers = usersIm()
	})
	pr5.holds.Store(true)
	pr5.step()
	pr5.wantMode(ModeMember)
	wantLevel(t, e, 2)
	k := pr5.key()

	// It is upgraded; the other server still runs the version before.
	var peers peerList
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}
	other := Peer{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: 2}
	peers.set(self, other)
	var fail atomic.Bool
	fail.Store(true)
	var runs atomic.Int32
	settingsIm := Importer{Name: ImportSettings, MinLevel: LevelSharedSettings, Source: func() (string, error) { return "h-settings", nil },
		Run: func(context.Context, string) error {
			runs.Add(1)
			if fail.Load() {
				return errors.New("settings.yaml cannot be read")
			}
			return nil
		}}
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, k)
		o.Peers = peers.get
		// This test is about level 3; later levels have tests of their own.
		o.levelMax = LevelSharedSettings
		o.Importers = append(usersIm(), settingsIm)
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	wantLevel(t, e, 2)
	if !a.rt.SharedUsers() || a.rt.SharedSettings() {
		t.Fatalf("users shared %v, settings shared %v at level 2", a.rt.SharedUsers(), a.rt.SharedSettings())
	}
	if n := runs.Load(); n != 0 {
		t.Fatalf("the settings were imported at level 2: %d", n)
	}

	// The other server is upgraded: the level goes up, but settings are
	// shared only once their import is done.
	// It reads level 3, not later ones, so the level stays there.
	other.LevelMax = LevelSharedSettings
	peers.set(self, other)
	a.step()
	wantLevel(t, e, 3)
	if runs.Load() != 1 || a.rt.SharedSettings() {
		t.Fatalf("import ran %d times; settings shared %v before it was done", runs.Load(), a.rt.SharedSettings())
	}
	if !a.rt.SharedUsers() {
		t.Error("users are no longer shared at level 3")
	}
	fail.Store(false)
	a.step()
	body := wantLevel(t, e, 3)
	if body.Import.Done[ImportSettings] != "h-settings" || !a.rt.SharedSettings() {
		t.Fatalf("import %+v, settings shared %v", body.Import, a.rt.SharedSettings())
	}

	// A server of the version before now refuses to start.
	old := e.server("siem-b", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, k)
		o.levelMax = 2
	})
	select {
	case err := <-old.rt.Fatal():
		var le *LevelError
		if !errors.As(err, &le) || le.Level != 3 || !strings.Contains(err.Error(), "reads up to level 2") {
			t.Errorf("fatal = %v", err)
		}
	default:
		t.Fatal("a version that reads up to level 2 started on a level 3 cluster")
	}
}

// W18: the requests that name a server run on that server, leader or not,
// from its own loop; the leader's loop runs only the requests for the
// leader, and a server's loop never runs those.
func TestServerRequestsRunOnEveryServer(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	b := e.server("siem-b", func(o *RuntimeOptions) { o.KeyFile = writeKeyFile(t, a.key()) })
	b.wantMode(ModeMember)
	ctx := context.Background()

	var mu sync.Mutex
	ran := map[string][]string{}
	handlers := func(name string) map[string]Handler {
		h := func(_ context.Context, r *Request) error {
			mu.Lock()
			defer mu.Unlock()
			ran[r.ID] = append(ran[r.ID], name)
			return nil
		}
		return map[string]Handler{"job": h, "restart": h}
	}
	ranOf := func(id string) []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(ran[id])
	}
	var wg sync.WaitGroup
	lctx, cancel := context.WithCancel(ctx)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	loop := func(fn func(context.Context, map[string]Handler), name string) {
		wg.Go(func() { fn(lctx, handlers(name)) })
	}
	reqs := a.rt.Requests()
	state := func(id string) *Request {
		r, found, err := reqs.Get(ctx, id)
		if err != nil || !found {
			t.Fatalf("request %s: %v %v", id, found, err)
		}
		return r
	}
	forLeader, err := reqs.Submit(ctx, "job", TargetLeader, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	forA, _ := reqs.Submit(ctx, "restart", "n_siem-a", nil, "sam")
	both, _ := reqs.SubmitTo(ctx, "restart", []string{"n_siem-a", "n_siem-b"}, true, nil, "sam")

	// The leader's loop runs the leader's request, and none that names a
	// server, not even the leader itself.
	loop(a.rt.RunRequests, "a-leader")
	waitFor(t, func() bool { return state(forLeader.ID).State == RequestDone })
	if got := state(forA.ID); got.State != RequestQueued || len(ranOf(forA.ID)) != 0 {
		t.Fatalf("the leader's loop ran a request for one server: %+v", got)
	}

	// B does not run the jobs, but runs what names it, in turn: its part
	// waits for A's. Its loop never runs the leader's requests.
	forLeader2, _ := reqs.Submit(ctx, "job", TargetLeader, nil, "sam")
	loop(b.rt.RunServerRequests, "b")
	b.step()
	if got := state(both.ID); got.Status["n_siem-b"] != RequestQueued {
		t.Fatalf("B went before A: %+v", got)
	}
	loop(a.rt.RunServerRequests, "a")
	waitFor(t, func() bool {
		return state(forA.ID).State == RequestDone && state(both.ID).Status["n_siem-a"] == RequestDone
	})
	// A's part bumps watch:requests, just after it is recorded done: B
	// acts at its next look once the bump is there.
	waitFor(t, func() bool {
		b.step()
		return state(both.ID).State == RequestDone
	})
	if got := ranOf(both.ID); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("order %v", got)
	}
	if got := ranOf(forA.ID); !slices.Equal(got, []string{"a"}) {
		t.Errorf("for A ran on %v", got)
	}
	got := state(both.ID)
	if got.Boots["n_siem-a"] != a.rt.BootID() || got.Boots["n_siem-b"] != b.rt.BootID() || a.rt.BootID() == b.rt.BootID() {
		t.Errorf("boots %v", got.Boots)
	}
	waitFor(t, func() bool { return state(forLeader2.ID).State == RequestDone })
	if got := ranOf(forLeader2.ID); !slices.Equal(got, []string{"a-leader"}) {
		t.Errorf("the leader's request ran on %v", got)
	}
}

// W17: a server that stops while it runs its part of a request (a
// restart that crashed): after its next start the part is failed, and a
// request in sequence goes on to nobody after it. The process that
// claimed the part leaves it alone, and a leader's runner never fails one.
func TestRequestPartLeftRunningByAStoppedServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, logs := e.hub("siem-a")
	notLeader := func() (int64, bool) { return 0, false }
	var runs atomic.Int32
	runner := func(id, boot, only string) *Runner {
		return &Runner{Requests: NewRequests(a, id), Lease: notLeader, Only: only, Boot: boot, Log: slog.New(slog.NewJSONHandler(logs, nil)),
			Handlers: map[string]Handler{"restart": func(context.Context, *Request) error { runs.Add(1); return nil }}}
	}
	get := func(id string) *Request {
		r, _, err := NewRequests(a, "x").Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	req, err := NewRequests(a, "n_a").SubmitTo(ctx, "restart", []string{"n_a", "n_b"}, true, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	// n_a claims its part and stops before it is over.
	first := runner("n_a", "b_1", RunServer)
	if ok, err := first.claim(ctx, get(req.ID), 0); !ok || err != nil {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if got := get(req.ID); got.Status["n_a"] != RequestRunning || got.Boots["n_a"] != "b_1" {
		t.Fatalf("claimed: %+v", got)
	}
	// While that process runs, its own loop leaves the part alone, and
	// n_b waits for it.
	nb := runner("n_b", "b_9", RunServer)
	for _, rn := range []*Runner{first, nb, runner("n_a", "b_2", RunLeader), runner("n_a", "", RunServer)} {
		if n, err := rn.RunOnce(ctx); n != 0 || err != nil {
			t.Fatalf("ran %d: %v", n, err)
		}
	}
	if got := get(req.ID); got.Status["n_a"] != RequestRunning || got.State != RequestRunning {
		t.Fatalf("the part was touched: %+v", got)
	}

	// n_a starts again: the part is failed, the sequence stops.
	again := runner("n_a", "b_2", RunServer)
	if n, err := again.RunOnce(ctx); n != 1 || err != nil {
		t.Fatalf("ran %d: %v", n, err)
	}
	got := get(req.ID)
	if got.State != RequestFailed || got.Status["n_a"] != RequestFailed || got.Status["n_b"] != RequestQueued ||
		!strings.Contains(got.Error, "n_a: "+ErrStoppedDuring.Error()) || got.Finished == nil {
		t.Fatalf("after the next start: %+v", got)
	}
	mustContain(t, "log", logs.String(), "marked failed")
	if n, _ := nb.RunOnce(ctx); n != 0 || runs.Load() != 0 {
		t.Fatalf("ran after the failed part: %d %d", n, runs.Load())
	}

	// A request for one server is failed the same way, and only once.
	one, _ := NewRequests(a, "n_a").Submit(ctx, "restart", "n_a", nil, "sam")
	if ok, err := first.claim(ctx, get(one.ID), 0); !ok || err != nil {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if n, err := again.RunOnce(ctx); n != 1 || err != nil {
		t.Fatalf("ran %d: %v", n, err)
	}
	if got := get(one.ID); got.State != RequestFailed || got.Error != ErrStoppedDuring.Error() || runs.Load() != 0 {
		t.Fatalf("one server: %+v", got)
	}
	if n, _ := again.RunOnce(ctx); n != 0 {
		t.Errorf("failed again: %d", n)
	}
}

// pr5NodeCfg is the nodecfg body as a version before shared settings
// reads it.
type pr5NodeCfg struct {
	Seen         map[string]map[string]string `json:"seen"`
	Applied      string                       `json:"applied,omitempty"`
	UsersApplied string                       `json:"users_applied,omitempty"`
	Extra        `json:"-"`
}

// Another server reads and changes a server's nodecfg with a Remote: a
// change of its own settings made on any server's page lands there next
// to what the server writes itself, neither is lost, and the server
// follows the change. Fields a version does not know are kept, so a
// server of the version before keeps the new ones.
func TestRemoteNodeCfg(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	own := NewDoc[NodeCfg](b, NodeCfgID("n_b"), NodeCfgKind, 1)
	own.Local = true
	remote := RemoteNodeCfg(a, "n_b")

	v, etag, _, err := remote.Read(ctx)
	if err != nil || etag != "" || v == nil || len(v.Values) != 0 {
		t.Fatalf("before there is one: %+v %q %v", v, etag, err)
	}
	if _, err := own.Mutate(ctx, "signalith", func(n *NodeCfg) error {
		n.Running = map[string]RunningValue{"server.listen": {Value: json.RawMessage(`"0.0.0.0:8443"`), Source: "file"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A saves B's listen address while B writes what it runs: A's write
	// is made again on B's newer copy.
	tries := 0
	at := e.clock.Now().UTC()
	err = remote.Mutate(ctx, "sam", func(n *NodeCfg) error {
		tries++
		if tries == 1 {
			if _, err := own.Mutate(ctx, "signalith", func(n *NodeCfg) error {
				n.Running["server.max_connections"] = RunningValue{Value: json.RawMessage(`500`), Source: "default"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if n.Values == nil {
			n.Values = map[string]PageValue{}
		}
		n.Values["server.listen"] = PageValue{Value: json.RawMessage(`"0.0.0.0:9443"`), Rev: n.Values["server.listen"].Rev + 1,
			From: From{Source: "page", Node: "siem-a", By: "sam", At: at}, Extra: Extra{"future": json.RawMessage(`true`)}}
		return nil
	})
	if err != nil || tries != 2 {
		t.Fatalf("mutate: %v after %d tries", err, tries)
	}
	cycle(t, b)
	n, ok := own.Get()
	if !ok || string(n.Values["server.listen"].Value) != `"0.0.0.0:9443"` || len(n.Running) != 2 || !n.Values["server.listen"].From.At.Equal(at) {
		t.Fatalf("B's copy: %+v", n)
	}
	if by, _, _ := own.Updated(); by.User != "sam" || by.Node != "siem-a" {
		t.Errorf("updated by %+v", by)
	}

	// A server of the version before writes its nodecfg: what it does
	// not know is kept, nested fields too.
	old, _ := e.hub("siem-b")
	pr5 := NewDoc[pr5NodeCfg](old, NodeCfgID("n_b"), NodeCfgKind, 1)
	if _, err := pr5.Mutate(ctx, "signalith", func(n *pr5NodeCfg) error { n.Applied = "2026-10-12T09:00:00Z"; return nil }); err != nil {
		t.Fatal(err)
	}
	v, etag, by, err := remote.Read(ctx)
	if err != nil || v.Applied != "2026-10-12T09:00:00Z" || string(v.Values["server.listen"].Value) != `"0.0.0.0:9443"` ||
		string(v.Values["server.listen"].Extra["future"]) != "true" || len(v.Running) != 2 || etag == "" || by.Node != "siem-b" {
		t.Fatalf("after the version before wrote it: %+v %q %+v %v", v, etag, by, err)
	}
}

// W24 (nodecfg): a nodecfg changed in OpenSearch outside Signalith is
// refused by its server, which reports it and keeps its last good copy,
// and by every other server reading or changing it, which never writes
// over it.
func TestForgedNodeCfgRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, aLogs := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	own := NewDoc[NodeCfg](b, NodeCfgID("n_b"), NodeCfgKind, 1)
	own.Local = true
	remote := RemoteNodeCfg(a, "n_b")
	if err := remote.Mutate(ctx, "sam", func(n *NodeCfg) error {
		n.Values = map[string]PageValue{"server.listen": {Value: json.RawMessage(`"0.0.0.0:8443"`), Rev: 1, From: From{Source: "page"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	if n, ok := own.Get(); !ok || string(n.Values["server.listen"].Value) != `"0.0.0.0:8443"` {
		t.Fatalf("B's copy: %+v", n)
	}

	// Someone with write access to OpenSearch, but not the cluster key,
	// points B at another address.
	src := e.os.Source(testIndex, NodeCfgID("n_b"))
	src["body"] = strings.Replace(src["body"].(string), "8443", "2222", 1)
	e.os.Put(testIndex, NodeCfgID("n_b"), src)

	cycle(t, b)
	if !slices.Contains(b.Tamper(), NodeCfgID("n_b")) {
		t.Errorf("B did not report it: %v", b.Tamper())
	}
	if n, _ := own.Get(); string(n.Values["server.listen"].Value) != `"0.0.0.0:8443"` {
		t.Errorf("B took the forged copy: %+v", n.Values)
	}
	var pe *ProblemError
	if _, _, _, err := remote.Read(ctx); !errors.As(err, &pe) || pe.Kind != ProblemTamper {
		t.Errorf("read: %v", err)
	}
	mustContain(t, "A's log", aLogs.String(), "config.tamper")
	if err := remote.Mutate(ctx, "sam", func(n *NodeCfg) error { return nil }); !errors.As(err, &pe) {
		t.Errorf("mutate over the forged copy: %v", err)
	}
	if got := e.os.Source(testIndex, NodeCfgID("n_b")); !strings.Contains(got["body"].(string), "2222") {
		t.Error("the forged copy was written over")
	}
	// A's hub reports nothing of its own: it does not follow B's nodecfg.
	if len(a.Tamper()) != 0 {
		t.Errorf("A reports %v", a.Tamper())
	}
}
