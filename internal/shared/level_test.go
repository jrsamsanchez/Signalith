package shared

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// peerList is the servers' heartbeats as a test sets them.
type peerList struct {
	mu    sync.Mutex
	peers []Peer
}

func (l *peerList) set(p ...Peer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.peers = slices.Clone(p)
}

func (l *peerList) get() []Peer {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.peers)
}

// writeKeyFile writes the cluster key k to a file, for SIGNALITH_CLUSTER_KEY_FILE.
func writeKeyFile(t *testing.T, k *ClusterKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cluster.key")
	if err := os.WriteFile(p, []byte(k.Text()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wantLevel(t *testing.T, e *testEnv, want int) ClusterBody {
	t.Helper()
	_, body := clusterBody(t, e)
	if body.Level != want {
		t.Fatalf("level = %d, want %d", body.Level, want)
	}
	return body
}

// V3: a cluster founded while a server of an older version is up starts
// at the level it reads; the server that runs the background jobs raises
// it once every server seen in 24 hours reads the next one (the old one
// went, or was upgraded), and an older version then refuses to start.
func TestLevelRaise(t *testing.T) {
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}
	old := Peer{NodeID: "n_siem-old", Name: "siem-old", Live: true} // no level_max: reads level 1
	t.Run("the old server goes", func(t *testing.T) {
		e := newEnv(t)
		var peers peerList
		peers.set(self, old)
		a := e.server("siem-a", func(o *RuntimeOptions) { o.Peers = peers.get })
		a.holds.Store(true)
		a.step()
		a.wantMode(ModeMember)
		wantLevel(t, e, 1)
		if a.rt.RaiseLevel(context.Background()) {
			t.Fatal("raised the level while a server that reads only level 1 is up")
		}

		// A member that does not run the background jobs never raises it.
		bPeers := peerList{}
		b := e.server("siem-b", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, a.key())
			o.Peers = bPeers.get
		})
		b.wantMode(ModeMember)

		gone := old
		gone.Live, gone.SeenAgo = false, LevelSeen-time.Minute
		peers.set(self, gone)
		a.step()
		wantLevel(t, e, 1)

		gone.SeenAgo = LevelSeen
		peers.set(self, gone)
		bPeers.set(Peer{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: LevelMax}, gone)
		b.step()
		wantLevel(t, e, 1)
		// Nor does a server that has not read the heartbeats yet.
		peers.set(gone)
		a.step()
		wantLevel(t, e, 1)

		peers.set(self, gone)
		a.step()
		wantLevel(t, e, 2)
		mustContain(t, "log", a.logs.String(), "raised the level of the shared settings")
		if st := a.rt.Status(); st.Level != 2 || st.LevelMax != LevelMax {
			t.Errorf("status = level %d, reads up to %d", st.Level, st.LevelMax)
		}
		b.step()
		if st := b.rt.Status(); st.Level != 2 {
			t.Errorf("the other member reads level %d", st.Level)
		}
		// One level at a time: every server reads the next one too.
		for l := 3; l <= LevelMax; l++ {
			if !a.rt.RaiseLevel(context.Background()) {
				t.Error("did not raise the level to the next one every server reads")
			}
			wantLevel(t, e, l)
		}
		if a.rt.RaiseLevel(context.Background()) {
			t.Error("raised the level above what this version reads")
		}

		// The old version comes back: it refuses to start.
		pr4 := e.server("siem-old", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, a.key())
			o.levelMax = 1
		})
		select {
		case err := <-pr4.rt.Fatal():
			var le *LevelError
			if !errors.As(err, &le) || le.Level != LevelMax || !strings.Contains(err.Error(), "reads up to level 1") {
				t.Errorf("fatal = %v", err)
			}
		default:
			t.Fatal("a version that reads only level 1 started on a level 2 cluster")
		}
	})
	t.Run("the old server is upgraded", func(t *testing.T) {
		e := newEnv(t)
		var peers peerList
		peers.set(self, old)
		a := e.server("siem-a", func(o *RuntimeOptions) { o.Peers = peers.get })
		a.holds.Store(true)
		a.step()
		wantLevel(t, e, 1)
		upgraded := old
		upgraded.LevelMax = LevelMax
		peers.set(self, upgraded)
		// Housekeeping raises it too.
		a.rt.Housekeep(context.Background())
		wantLevel(t, e, 2)
	})
	t.Run("a new install", func(t *testing.T) {
		e := newEnv(t)
		var peers peerList
		gone := old
		gone.Live, gone.SeenAgo = false, 2*LevelSeen
		peers.set(self, gone)
		a := e.server("siem-a", func(o *RuntimeOptions) { o.Peers = peers.get })
		a.holds.Store(true)
		a.step()
		wantLevel(t, e, LevelMax)
	})
}

// counter is an importer that counts its runs.
type counter struct {
	name string
	min  int
	runs atomic.Int32
}

func (c *counter) importer() Importer {
	return Importer{Name: c.name, MinLevel: c.min, Source: func() (string, error) { return "h-" + c.name, nil },
		Run: func(context.Context, string) error {
			c.runs.Add(1)
			return nil
		}}
}

// V4: importers a newer version added (users, directory: level 2) run
// once on a cluster a PR 4 version founded, after the level is raised: by
// the founder when it runs the background jobs, or, once the founder has
// not been seen for 7 days, by the server that runs them, which records
// which servers' users differ.
func TestLateImports(t *testing.T) {
	t.Run("by the founder", func(t *testing.T) {
		e := newEnv(t)
		feeds := &counter{name: "feeds"}
		usersIm := &counter{name: ImportUsers, min: LevelSharedUsers}
		// A PR 4 version founds the cluster with its importers.
		pr4 := e.server("siem-a", func(o *RuntimeOptions) {
			o.levelMax = 1
			o.Importers = []Importer{feeds.importer()}
		})
		pr4.holds.Store(true)
		pr4.step()
		pr4.wantMode(ModeMember)
		wantLevel(t, e, 1)
		k := pr4.key()

		// It is upgraded (the same server, node id and key).
		a := e.server("siem-a", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, k)
			o.Peers = func() []Peer { return []Peer{{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}} }
			o.Importers = []Importer{feeds.importer(), usersIm.importer(), {Name: ImportDirectory, MinLevel: LevelSharedUsers}}
		})
		a.wantMode(ModeMember)
		if a.rt.SharedUsers() {
			t.Error("users are shared at level 1")
		}
		a.holds.Store(true)
		a.step()
		body := wantLevel(t, e, 2)
		if n := usersIm.runs.Load(); n != 1 {
			t.Errorf("the users importer ran %d times", n)
		}
		if body.Import.Done[ImportUsers] != "h-users" || body.Import.Done[ImportDirectory] != importNone || body.Import.Late != nil {
			t.Errorf("import = %+v", body.Import)
		}
		if !a.rt.SharedUsers() {
			t.Error("users are not shared once imported at level 2")
		}
		a.step()
		a.step()
		if n, f := usersIm.runs.Load(), feeds.runs.Load(); n != 1 || f != 1 {
			t.Errorf("importers ran again: users %d, feeds %d", n, f)
		}
	})
	t.Run("by the leader once the founder is gone", func(t *testing.T) {
		e := newEnv(t)
		pr4 := e.server("siem-f", func(o *RuntimeOptions) { o.levelMax = 1 })
		pr4.holds.Store(true)
		pr4.step()
		pr4.holds.Store(false)
		wantLevel(t, e, 1)

		usersIm := &counter{name: ImportUsers, min: LevelSharedUsers}
		var peers peerList
		self := Peer{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: LevelMax, Users: "u1"}
		founder := Peer{NodeID: "n_siem-f", Name: "siem-f", SeenAgo: 3 * 24 * time.Hour, LevelMax: 1, Users: "u0"}
		others := []Peer{
			{NodeID: "n_siem-c", Name: "siem-c", Live: true, LevelMax: LevelMax, Users: "u2"},
			{NodeID: "n_siem-d", Name: "siem-d", Live: true, LevelMax: LevelMax, Users: "u1"},
		}
		peers.set(append([]Peer{self, founder}, others...)...)
		b := e.server("siem-b", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, pr4.key())
			o.Peers = peers.get
			o.Importers = []Importer{usersIm.importer()}
		})
		b.holds.Store(true)
		b.step()
		// The level goes up (the founder was not seen for a day), but the
		// founder's files are waited for.
		wantLevel(t, e, 2)
		if n := usersIm.runs.Load(); n != 0 {
			t.Fatalf("imported while the founder may come back: %d", n)
		}
		lateWarned := func() *Warning {
			for _, w := range b.rt.Warnings() {
				if strings.Contains(w.Text, "had not been seen for 7 days") {
					return &w
				}
			}
			return nil
		}
		if w := lateWarned(); w != nil {
			t.Errorf("warning before the import: %+v", w)
		}
		waitWarned := false
		for _, w := range b.rt.Warnings() {
			if strings.Contains(w.Text, "once siem-f, which founded the cluster, is back") && w.Level == "amber" {
				waitWarned = true
			}
		}
		if !waitWarned {
			t.Errorf("no warning naming the founder the users wait for: %+v", b.rt.Warnings())
		}

		founder.SeenAgo = FounderGone
		peers.set(append([]Peer{self, founder}, others...)...)
		b.step()
		body := wantLevel(t, e, 3)
		if n := usersIm.runs.Load(); n != 1 {
			t.Fatalf("the users importer ran %d times", n)
		}
		l := body.Import.Late
		if l == nil || l.By != "siem-b" || l.ByID != "n_siem-b" || !slices.Equal(l.Sources, []string{ImportUsers}) || !slices.Equal(l.Differ, []string{"siem-c", "siem-f"}) {
			t.Fatalf("late import = %+v", l)
		}
		w := lateWarned()
		if w == nil || w.Level != "amber" || !strings.Contains(w.Text, "siem-c, siem-f") || !strings.Contains(w.Text, "siem-b put its own users") {
			t.Errorf("warning = %+v", w)
		}
		mustContain(t, "log", b.logs.String(), "has not been seen for 7 days")
		b.step()
		if n := usersIm.runs.Load(); n != 1 {
			t.Errorf("the users importer ran %d times", n)
		}
	})
	t.Run("by the founder after a rolling upgrade", func(t *testing.T) {
		// The founder is restarted first, so another server takes the
		// job lease and keeps it: the founder imports without it.
		e := newEnv(t)
		pr4 := e.server("siem-a", func(o *RuntimeOptions) { o.levelMax = 1 })
		pr4.holds.Store(true)
		pr4.step()
		pr4.holds.Store(false)
		k := pr4.key()
		peers := func() []Peer {
			return []Peer{{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax},
				{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: LevelMax}}
		}
		usersIm := &counter{name: ImportUsers, min: LevelSharedUsers}
		b := e.server("siem-b", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, k)
			o.Peers = peers
			o.Importers = []Importer{usersIm.importer()}
		})
		b.holds.Store(true)
		b.step()
		wantLevel(t, e, 2)
		if n := usersIm.runs.Load(); n != 0 {
			t.Fatalf("the leader imported while the founder is live: %d", n)
		}
		a := e.server("siem-a", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, k)
			o.Peers = peers
			o.Importers = []Importer{usersIm.importer()}
		})
		a.step()
		a.wantMode(ModeMember)
		body := wantLevel(t, e, 2)
		if n := usersIm.runs.Load(); n != 1 || body.Import.Done[ImportUsers] != "h-users" || body.Import.Late != nil {
			t.Fatalf("runs %d, import %+v", n, body.Import)
		}
		b.step()
		a.step()
		if n := usersIm.runs.Load(); n != 1 {
			t.Errorf("the users importer ran %d times", n)
		}
	})
	t.Run("at founding on the highest level", func(t *testing.T) {
		e := newEnv(t)
		usersIm := &counter{name: ImportUsers, min: LevelSharedUsers}
		a := e.server("siem-a", func(o *RuntimeOptions) {
			o.Importers = []Importer{usersIm.importer(), {Name: ImportDirectory, MinLevel: LevelSharedUsers}}
		})
		a.holds.Store(true)
		a.step()
		body := wantLevel(t, e, LevelMax)
		if n := usersIm.runs.Load(); n != 1 || body.Import.State != ImportReady || body.Import.Late != nil {
			t.Errorf("runs %d, import %+v", n, body.Import)
		}
		if !a.rt.SharedUsers() {
			t.Error("users are not shared after founding on level 2")
		}
	})
}

func TestFounderGone(t *testing.T) {
	peers := []Peer{{NodeID: "a", Live: true}, {NodeID: "b", SeenAgo: FounderGone - time.Second}, {NodeID: "c", SeenAgo: FounderGone}}
	for id, want := range map[string]bool{"a": false, "b": false, "c": true, "removed": true} {
		if got := founderGone(peers, id); got != want {
			t.Errorf("founderGone(%s) = %v", id, got)
		}
	}
}
