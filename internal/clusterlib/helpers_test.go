package clusterlib

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const testPrefix = "signalith"

type testOS struct {
	fake *ostest.Server
	cl   *store.Client
}

func newOS(t *testing.T) *testOS {
	fake := ostest.New(t)
	return &testOS{fake: fake, cl: store.New(store.Config{URL: fake.URL})}
}

// server is one member of the cluster: its runtime, the library's
// documents, and a detection library and dashboard store over them.
type server struct {
	t      *testing.T
	name   string
	rt     *shared.Runtime
	docs   *Docs
	lib    *detect.Library
	boards *dashboards.Store
	detDir string
	dbDir  string
	state  string
}

// newServer starts a server named name. With key it joins the cluster;
// without, it founds it.
func newServer(t *testing.T, o *testOS, name string, key *shared.ClusterKey) *server {
	t.Helper()
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	if key != nil {
		if err := (shared.KeyStore{Dir: dir, Master: master}).SaveClusterKey(key); err != nil {
			t.Fatal(err)
		}
	}
	s := &server{t: t, name: name, docs: NewDocs(), detDir: filepath.Join(dir, "detections"), dbDir: filepath.Join(dir, "dashboards"), state: dir}
	s.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_" + name, Name: name},
		Content: s.docs.Track, Log: slog.New(slog.DiscardHandler)})
	s.rt.Use(o.cl, testPrefix, master)
	if key == nil {
		if err := s.rt.Found(context.Background(), "test"); err != nil {
			t.Fatal(err)
		}
	}
	if mode, why := s.rt.Mode(); mode != shared.ModeMember {
		t.Fatalf("%s: mode %s (%s)", name, mode, why)
	}
	lib, _, err := detect.NewLibrary(s.detDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.UseBackend(&Detections{Docs: s.docs, Node: name, Writable: s.rt.Writable}); err != nil {
		t.Fatal(err)
	}
	s.lib = lib
	s.boards, _ = dashboards.NewStore(s.dbDir)
	s.boards.UseBackend(&Dashboards{Docs: s.docs, Node: name, Writable: s.rt.Writable})
	return s
}

// pair founds a cluster on A and joins B.
func pair(t *testing.T) (*testOS, *server, *server) {
	t.Helper()
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	b := newServer(t, o, "siem-b", a.rt.Hub().Keys().Active())
	b.cycle()
	return o, a, b
}

// cycle reads the shared settings once, as the watcher does every 2
// seconds.
func (s *server) cycle() {
	s.t.Helper()
	if err := s.rt.Hub().Cycle(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

func (s *server) files() Files {
	return Files{DetectionsDir: func() string { return s.detDir }, DashboardsDir: func() string { return s.dbDir }, Node: s.name}
}

func (s *server) inbox(mirror bool) *Inbox {
	return &Inbox{Docs: s.docs, Files: s.files(), SeenFile: filepath.Join(s.state, SeenFileName),
		Mirror: func() bool { return mirror }, Writable: s.rt.Writable}
}

// builtinID is the id of a shipped detection.
func builtinID(t *testing.T) (string, bool) {
	t.Helper()
	bs, err := detect.Builtin()
	if err != nil || len(bs) == 0 {
		t.Fatal("no built-in detections", err)
	}
	return bs[0].ID, bs[0].Enabled
}

// custom returns a valid custom detection.
func custom(id, title string) *detect.Detection {
	d := &detect.Detection{ID: id, Title: title, Severity: "medium", Query: "event.action=failure", Schedule: "5m", Lookback: "5m", Enabled: true}
	d.Defaults()
	return d
}

func board(id, title string) *dashboards.Dashboard {
	return &dashboards.Dashboard{ID: id, Title: title, Panels: []dashboards.Panel{{Title: "Events", Query: "* | stats count", Viz: dashboards.VizSingle}}}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o666); err != nil {
		t.Fatal(err)
	}
}

func encodeDet(t *testing.T, d *detect.Detection) []byte {
	t.Helper()
	data, err := detect.Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func encodeBoard(t *testing.T, d *dashboards.Dashboard) []byte {
	t.Helper()
	c := *d
	c.Defaults()
	data, err := dashboards.Encode(&c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
