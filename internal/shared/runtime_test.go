package shared

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// testServer is one server's runtime on the fake, with a job lease the
// test hands out.
type testServer struct {
	t      *testing.T
	env    *testEnv
	rt     *Runtime
	dir    string
	master *secrets.Keyring
	holds  atomic.Bool
	logs   *logBuffer
}

// server returns a runtime named name on the fake, with its own state
// folder, pointed at it (the first look for the cluster is done).
func (e *testEnv) server(name string, change func(*RuntimeOptions)) *testServer {
	e.t.Helper()
	s := &testServer{t: e.t, env: e, dir: e.t.TempDir(), logs: &logBuffer{}}
	s.master = secrets.NewKeyring(s.dir)
	o := RuntimeOptions{StateDir: s.dir, Self: Self{NodeID: "n_" + name, Name: name},
		HoldsLease: s.holds.Load,
		LeaseCheck: func(context.Context) error {
			if !s.holds.Load() {
				return errors.New("this server lost the job lease")
			}
			return nil
		},
		LeaseEpoch: func() int64 { return 1 },
		Clock:      e.clock, Log: slog.New(slog.NewJSONHandler(s.logs, nil))}
	if change != nil {
		change(&o)
	}
	s.rt = NewRuntime(o)
	s.rt.Use(e.c, testPrefix, s.master)
	return s
}

// step runs one step of the runtime's loop.
func (s *testServer) step() {
	s.t.Helper()
	s.rt.step(context.Background())
}

func (s *testServer) mode() Mode {
	m, _ := s.rt.Mode()
	return m
}

func (s *testServer) wantMode(want Mode) {
	s.t.Helper()
	if m, why := s.rt.Mode(); m != want {
		s.t.Fatalf("mode = %s (%s), want %s", m, why, want)
	}
}

// key returns the cluster key the server signs with.
func (s *testServer) key() *ClusterKey {
	s.t.Helper()
	k := s.rt.Hub().Keys().Active()
	if k == nil {
		s.t.Fatal("the server has no cluster key")
	}
	return k
}

// give hands the server the cluster key k, as import-key does.
func (s *testServer) give(k *ClusterKey) {
	s.t.Helper()
	if err := (KeyStore{Dir: s.dir, Master: s.master}).SaveClusterKey(k); err != nil {
		s.t.Fatal(err)
	}
}

func clusterBody(t *testing.T, e *testEnv) (*Envelope, ClusterBody) {
	t.Helper()
	src := e.os.Source(testIndex, ClusterDocID)
	if src == nil {
		t.Fatal("no cluster document")
	}
	raw, _ := json.Marshal(src)
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var b ClusterBody
	if err := json.Unmarshal([]byte(env.Body), &b); err != nil {
		t.Fatal(err)
	}
	return &env, b
}

// U11: only the server that holds the job lease founds the cluster; two
// that found at the same moment leave one cluster, and the other server
// is not part of it (legacy b).
func TestFoundingByTheLeaseHolder(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	b := e.server("siem-b", nil)
	// The first look, while the components start, never founds.
	a.holds.Store(true)
	a.wantMode(ModeLegacyC)
	b.wantMode(ModeLegacyC)
	if e.os.Source(testIndex, ClusterDocID) != nil {
		t.Fatal("a cluster was founded before the loop ran")
	}
	b.step()
	b.wantMode(ModeLegacyC)
	if e.os.Source(testIndex, ClusterDocID) != nil {
		t.Fatal("a server without the job lease founded the cluster")
	}
	a.step()
	a.wantMode(ModeMember)
	env, body := clusterBody(t, e)
	if body.CreatedBy != "siem-a" || body.Level != LevelMax || body.Import.State != ImportReady || body.ClusterID == "" {
		t.Errorf("cluster document = %+v", body)
	}
	if macKID(env.MAC) != a.key().ID() {
		t.Errorf("cluster document signed with %s, want %s", macKID(env.MAC), a.key().ID())
	}
	if _, err := os.Stat(ClusterKeyPath(a.dir, a.key().ID())); err != nil {
		t.Errorf("the founder keeps no cluster key: %v", err)
	}
	kr, ok := a.rt.Keyring().Get()
	if !ok || kr.Active != a.key().ID() || kr.Members["n_siem-a"].AddedBy != AddedByFounder || kr.Members["n_siem-a"].Fingerprint == "" {
		t.Errorf("keyring = %+v", kr)
	}
	mustContain(t, "log", a.logs.String(), "founded the cluster")

	// The other server finds a cluster it has no key to.
	b.step()
	b.wantMode(ModeLegacyB)
	if why := b.rt.NotEligible(); why == "" {
		t.Error("a server outside the cluster may run the background jobs")
	}
	if ok, _ := b.rt.Ready(); !ok {
		t.Error("a server in legacy mode is not ready; it serves from its files")
	}
	if st := b.rt.Status(); st.Fingerprint == "" {
		t.Error("legacy (b) shows no fingerprint to approve the server by")
	}
}

func TestFoundingRaceLeavesOneCluster(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	b := e.server("siem-b", nil)
	a.holds.Store(true)
	b.holds.Store(true)
	var wg sync.WaitGroup
	for _, s := range []*testServer{a, b} {
		wg.Go(s.step)
	}
	wg.Wait()
	_, body := clusterBody(t, e)
	winner, loser := a, b
	if body.CreatedBy == "siem-b" {
		winner, loser = b, a
	}
	winner.wantMode(ModeMember)
	loser.step()
	loser.wantMode(ModeLegacyB)
	if files := ClusterKeyFiles(loser.dir); len(files) != 0 {
		t.Errorf("the loser kept a cluster key: %v", files)
	}
}

// U25, legacy part: OpenSearch down at the first start with no copy is
// legacy (a), which serves from files and runs no jobs; once OpenSearch
// answers, the lease holder founds.
func TestLegacyAThenFound(t *testing.T) {
	e := newEnv(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	down := store.New(store.Config{URL: dead.URL})
	s := &testServer{t: t, env: e, dir: t.TempDir(), logs: &logBuffer{}}
	s.master = secrets.NewKeyring(s.dir)
	s.rt = NewRuntime(RuntimeOptions{StateDir: s.dir, Self: Self{NodeID: "n_a", Name: "siem-a"}, HoldsLease: s.holds.Load,
		Clock: e.clock, Log: slog.New(slog.NewJSONHandler(s.logs, nil))})
	s.rt.Use(down, testPrefix, s.master)
	s.wantMode(ModeLegacyA)
	if ok, _ := s.rt.Ready(); !ok {
		t.Error("legacy (a) is not ready; it serves from its files")
	}
	if s.rt.NotEligible() == "" {
		t.Error("legacy (a) may run the background jobs")
	}
	// A restart in place with OpenSearch back.
	s.rt.Use(e.c, testPrefix, s.master)
	s.step()
	s.wantMode(ModeLegacyC)
	s.holds.Store(true)
	s.step()
	s.wantMode(ModeMember)
}

// A server that stopped after keeping its new cluster key but before the
// cluster document was made is not taken for a member that lost its
// cluster: it founds by itself, with the same key.
func TestFoundingCutShort(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := markFounding(a.dir, k.ID()); err != nil {
		t.Fatal(err)
	}
	a.give(k)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	if a.key().ID() != k.ID() {
		t.Errorf("founded with %s, not the key it kept (%s)", a.key().ID(), k.ID())
	}
	if _, err := os.Stat(foundingPath(a.dir, k.ID())); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the founding mark stays: %v", err)
	}
	// A key kept once a cluster was made is a member's: it never founds.
	b := e.server("siem-b", nil)
	b.give(k)
	e.os.Delete(testIndex, ClusterDocID)
	b.holds.Store(true)
	a.holds.Store(false)
	b.step()
	b.wantMode(ModeGone)
}

// A create whose answer was lost, while the document cannot be read
// either, keeps the key: the document may have been made with it. The
// next look joins it as the founder.
func TestFoundingWhoseAnswerWasLost(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	var dropped, reads atomic.Bool
	e.os.SetFault(func(method, path string) *ostest.Fault {
		switch {
		case method == http.MethodPut && strings.Contains(path, "/_create/"+ClusterDocID) && !dropped.Load():
			dropped.Store(true)
			reads.Store(true)
			return &ostest.Fault{Drop: true}
		case method == http.MethodGet && strings.Contains(path, "/_doc/"+ClusterDocID) && reads.Load():
			return &ostest.Fault{Status: http.StatusServiceUnavailable, Type: "unavailable"}
		}
		return nil
	})
	a.holds.Store(true)
	if err := a.rt.found(context.Background(), "signalith", false); err == nil {
		t.Fatal("founding did not fail")
	}
	files := ClusterKeyFiles(a.dir)
	if len(files) != 1 || e.os.Source(testIndex, ClusterDocID) == nil {
		t.Fatalf("keys %v after a create whose answer was lost", files)
	}
	reads.Store(false)
	a.step()
	a.wantMode(ModeMember)
	env, body := clusterBody(t, e)
	if macKID(env.MAC) != a.key().ID() || body.Import.State != ImportReady {
		t.Errorf("cluster %+v signed with %s, key %s", body, macKID(env.MAC), a.key().ID())
	}
	if _, err := os.Stat(foundingPath(a.dir, a.key().ID())); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the founding mark stays: %v", err)
	}
}

// While the founder moves its files into OpenSearch, a server that joins
// keeps using its own files and says why; a founder that takes long is
// reported.
func TestJoinDuringImport(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	fail.Store(true)
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.Importers = []Importer{{Name: "feeds", Source: func() (string, error) { return "h", nil },
			Run: func(context.Context, string) error {
				if fail.Load() {
					return errors.New("cut short")
				}
				return nil
			}}}
	})
	a.holds.Store(true)
	if err := a.rt.found(context.Background(), "signalith", false); err == nil {
		t.Fatal("the import was not cut short")
	}
	a.holds.Store(false)
	b := e.server("siem-b", nil)
	b.give(a.key())
	b.step()
	b.wantMode(ModeMember)
	if b.rt.SharedContent() {
		t.Error("a server uses the shared content before the founder moved its files")
	}
	warn := func() Warning {
		t.Helper()
		for _, w := range b.rt.Warnings() {
			if strings.Contains(w.Text, "moving its files") {
				return w
			}
		}
		t.Fatalf("no warning: %+v", b.rt.Warnings())
		return Warning{}
	}
	if w := warn(); w.Level != "amber" || !strings.Contains(w.Text, "siem-a") {
		t.Errorf("warning %+v", w)
	}
	e.clock.Advance(ImportStalled)
	if w := warn(); w.Level != "red" {
		t.Errorf("a stalled import: %+v", w)
	}
	fail.Store(false)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	b.step()
	if !b.rt.SharedContent() {
		t.Error("the shared content is not used once the import is done")
	}
	for _, w := range b.rt.Warnings() {
		if strings.Contains(w.Text, "moving its files") {
			t.Errorf("warning after the import: %+v", w)
		}
	}
}

// U12: a member that finds the cluster document gone never founds a new
// one; import -from-cache writes its copy back with the original MACs and
// revisions, and the other member resumes.
func TestGoneAndRestoredFromCache(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	ctx, cancel := context.WithCancel(context.Background())
	defer a.rt.Wait()
	defer cancel()
	a.rt.Start(ctx)
	waitFor(t, func() bool { return a.rt.FlushCache() == nil && fileExists(CachePath(a.dir)) })
	b := e.server("siem-b", nil)
	b.give(a.key())
	b.step()
	b.wantMode(ModeMember)
	// The copy has b in the keyring.
	a.step()
	if err := a.rt.FlushCache(); err != nil {
		t.Fatal(err)
	}
	before, _ := clusterBody(t, e)

	if err := e.c.Do(context.Background(), http.MethodDelete, "/"+testIndex, nil, nil); err != nil {
		t.Fatal(err)
	}
	a.step()
	b.step()
	a.wantMode(ModeGone)
	b.wantMode(ModeGone)
	if e.os.Source(testIndex, ClusterDocID) != nil {
		t.Fatal("a member founded a new cluster")
	}
	if ok, _ := a.rt.Ready(); ok {
		t.Error("a server whose shared settings are gone is ready")
	}
	if a.rt.NotEligible() == "" {
		t.Error("a server whose shared settings are gone may run the background jobs")
	}

	id, prefix, err := CacheHeader(CachePath(a.dir))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Cache{Path: CachePath(a.dir), Master: a.master, ClusterID: id, Prefix: prefix}.Read(e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	written, there, err := RestoreFromCache(context.Background(), e.c, testPrefix, d)
	if err != nil || len(written) < 2 || len(there) != 0 {
		t.Fatalf("restore: written %v, there %v, err %v", written, there, err)
	}
	after, _ := clusterBody(t, e)
	if after.MAC != before.MAC || after.Rev != before.Rev {
		t.Errorf("restored cluster document: rev %d mac %s, want rev %d mac %s", after.Rev, after.MAC, before.Rev, before.MAC)
	}
	b.step()
	b.wantMode(ModeMember)
	a.step()
	a.wantMode(ModeMember)
	if tamper := b.rt.Hub().Tamper(); len(tamper) != 0 {
		t.Errorf("tamper after the restore: %v", tamper)
	}
	// Again: everything is there now.
	if written, there, err = RestoreFromCache(context.Background(), e.c, testPrefix, d); err != nil || len(written) != 0 || len(there) == 0 {
		t.Errorf("second restore: written %v, there %v, err %v", written, there, err)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// U13: a cluster at a level above this version's stops the server;
// Migrate runs once across the servers.
func TestLevelAndMigrate(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.give(a.key())
	b.step()
	b.wantMode(ModeMember)

	runs := 0
	fn := func(context.Context) error { runs++; return nil }
	if ran, err := a.rt.Migrate(context.Background(), "findings-fields@1.5.0", fn); !ran || err != nil {
		t.Fatalf("first migration: ran %v, err %v", ran, err)
	}
	b.step()
	if ran, err := b.rt.Migrate(context.Background(), "findings-fields@1.5.0", fn); ran || err != nil {
		t.Fatalf("the migration ran again: ran %v, err %v", ran, err)
	}
	if runs != 1 {
		t.Errorf("migration ran %d times", runs)
	}
	_, body := clusterBody(t, e)
	if body.Migrations["findings-fields@1.5.0"] == "" {
		t.Errorf("migrations = %v", body.Migrations)
	}
	// A server not a member does not run them.
	c := e.server("siem-c", nil)
	if _, err := c.rt.Migrate(context.Background(), "x", fn); !errors.Is(err, ErrNotMember) {
		t.Errorf("Migrate on legacy (b) = %v", err)
	}

	// A newer version raised the level.
	if _, err := a.rt.Cluster().Mutate(context.Background(), "test", func(b *ClusterBody) error { b.Level = LevelMax + 1; return nil }); err != nil {
		t.Fatal(err)
	}
	b.step()
	select {
	case err := <-b.rt.Fatal():
		var le *LevelError
		if !errors.As(err, &le) || le.Level != LevelMax+1 {
			t.Errorf("fatal = %v", err)
		}
	default:
		t.Fatal("a cluster at a newer level did not stop the server")
	}
}

// U14: a server with SIGNALITH_CLUSTER_KEY_FILE and no key of its own
// joins, keeps the key and adds itself to the keyring.
func TestKeyFileJoins(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	file := filepath.Join(t.TempDir(), "cluster.key")
	if err := os.WriteFile(file, []byte(a.key().Text()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := e.server("siem-b", func(o *RuntimeOptions) { o.KeyFile = file })
	b.wantMode(ModeMember)
	if !fileExists(ClusterKeyPath(b.dir, a.key().ID())) {
		t.Error("the key from the key file was not kept in the state folder")
	}
	a.step()
	kr, _ := a.rt.Keyring().Get()
	if m := kr.Members["n_siem-b"]; m.AddedBy != AddedByKeyFile || m.Fingerprint == "" {
		t.Errorf("keyring member = %+v", m)
	}

	// Founding with the key file's key.
	e2 := newEnv(t)
	c := e2.server("siem-c", func(o *RuntimeOptions) { o.KeyFile = file })
	c.holds.Store(true)
	c.step()
	c.wantMode(ModeMember)
	if c.key().ID() != a.key().ID() {
		t.Errorf("founded with key %s, want the key file's %s", c.key().ID(), a.key().ID())
	}
}

// U15: a document signed with a key the keyring lists but this server
// lacks is a missed key change: not ready, no tamper; importing the key
// recovers.
func TestMissedKeyChange(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.give(a.key())
	b.step()
	b.wantMode(ModeMember)

	k2, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.rt.Keyring().Mutate(context.Background(), "test", func(kr *KeyringBody) error {
		kr.Keys = append(kr.Keys, KeyInfo{KID: k2.ID()})
		kr.Active = k2.ID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.step()
	// The cluster document, signed with the new key.
	env, _ := clusterBody(t, e)
	e.putSigned(k2, ClusterDocID, "cluster", 1, env.Rev+1, env.Body, nil)
	b.step()
	b.wantMode(ModeKeyMissing)
	if ok, _ := b.rt.Ready(); ok {
		t.Error("a server that missed a key change is ready")
	}
	if b.rt.NotEligible() == "" {
		t.Error("a server that missed a key change may run the background jobs")
	}
	if tamper := b.rt.Hub().Tamper(); len(tamper) != 0 {
		t.Errorf("a missed key change raised tamper: %v", tamper)
	}
	if logs := b.logs.String(); strings.Contains(logs, "config.tamper") {
		t.Errorf("tamper logged:\n%s", logs)
	}

	b.give(k2)
	b.step()
	b.step()
	b.wantMode(ModeMember)
	if b.key().ID() != k2.ID() {
		t.Errorf("signs with %s, want %s", b.key().ID(), k2.ID())
	}
}

// A copy in cache.enc is used until OpenSearch answers; a member that
// cannot reach OpenSearch is degraded.
func TestCacheAtStartAndDegraded(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	ctx, cancel := context.WithCancel(context.Background())
	a.rt.Start(ctx)
	waitFor(t, func() bool { return a.rt.FlushCache() == nil && fileExists(CachePath(a.dir)) })
	cancel()
	a.rt.Wait()

	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	again := NewRuntime(RuntimeOptions{StateDir: a.dir, Self: Self{NodeID: "n_siem-a", Name: "siem-a"}, Clock: e.clock})
	again.Use(store.New(store.Config{URL: dead.URL}), testPrefix, a.master)
	if m, _ := again.Mode(); m != ModeDegraded {
		t.Fatalf("mode = %s, want degraded", m)
	}
	st := again.Status()
	if !st.Provisional || st.ClusterID == "" {
		t.Errorf("status = %+v", st)
	}
	if body, ok := again.Cluster().Get(); !ok || body.CreatedBy != "siem-a" {
		t.Error("the copy is not in use")
	}
	if ok, _ := again.Ready(); ok {
		t.Error("a degraded server is ready")
	}
	again.Use(e.c, testPrefix, a.master)
	again.step(context.Background())
	if m, _ := again.Mode(); m != ModeMember {
		t.Fatalf("mode = %s, want member once OpenSearch answers", m)
	}
	if again.Status().Provisional {
		t.Error("still provisional")
	}
}

// Requests run on the lease holder through the runtime.
func TestRunRequests(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	req, err := a.rt.Requests().Submit(context.Background(), "test", TargetLeader, map[string]any{"x": 1}, "sam")
	if err != nil {
		t.Fatal(err)
	}
	ran := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.rt.RunRequests(ctx, map[string]Handler{"test": func(_ context.Context, r *Request) error { ran <- r.ID; return nil }})
	select {
	case id := <-ran:
		if id != req.ID {
			t.Errorf("ran %s, want %s", id, req.ID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request did not run")
	}
}

// reset-key empties values sealed with the lost key and keeps the rest of
// the body, numbers as written.
func TestDropSealed(t *testing.T) {
	body := `{"feeds":[{"name":"otx","headers":{"X-Key":"enc:v1:aaaa1111:c2VjcmV0"},"n":12345678901234567890}],"pw":"enc:v1:bbbb2222:eA==","keep":"enc:v1:cccc3333:eA=="}`
	out, paths, err := dropSealed(body, "cccc3333")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"feeds[0].headers.X-Key", "pw"}; strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	for _, s := range []string{`"X-Key":""`, `"pw":""`, `"keep":"enc:v1:cccc3333:eA=="`, `12345678901234567890`} {
		mustContain(t, "body", out, s)
	}
	if same, paths, _ := dropSealed(`{"a":1.50}`, "x"); same != `{"a":1.50}` || len(paths) != 0 {
		t.Errorf("a body with nothing sealed changed: %s %v", same, paths)
	}
}

// A cache.enc older than 30 days is not used, but the revisions it
// applied are: a copy of the cluster document written back from before is
// refused by a server that starts with it.
func TestOldCacheKeepsRevisions(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	before := e.os.Source(testIndex, ClusterDocID)
	if _, err := a.rt.Migrate(context.Background(), "x@1", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	a.step()
	ctx, cancel := context.WithCancel(context.Background())
	a.rt.Start(ctx)
	waitFor(t, func() bool { return a.rt.FlushCache() == nil && fileExists(CachePath(a.dir)) })
	cancel()
	a.rt.Wait()

	e.os.Put(testIndex, ClusterDocID, before)
	e.clock.SetWall(e.clock.Now().Add(CacheMaxAge + time.Hour))
	again := NewRuntime(RuntimeOptions{StateDir: a.dir, Self: Self{NodeID: "n_siem-a", Name: "siem-a"}, Clock: e.clock})
	again.Use(e.c, testPrefix, a.master)
	if body, ok := again.Cluster().Get(); ok && body.Migrations["x@1"] == "" {
		t.Error("the cluster document written back from before is in use")
	}
	if tamper := again.Hub().Tamper(); len(tamper) != 1 || tamper[0] != ClusterDocID {
		t.Errorf("tamper = %v", tamper)
	}
	if !fileExists(CachePath(a.dir)) {
		t.Error("the old copy was removed with the revisions it keeps")
	}
}

// A server that keeps the key of a cluster it was a member of, but no
// copy of its shared settings, does not take a cluster document of
// another cluster signed with a key it does not have for a cluster it is
// not part of, which would put it back on its own files (legacy b).
func TestReplacedClusterWithoutCache(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.give(a.key())
	b.step()
	b.wantMode(ModeMember)
	if fileExists(CachePath(b.dir)) {
		t.Fatal("the server keeps a copy")
	}
	env, body := clusterBody(t, e)
	body.ClusterID = "c_other"
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e.putSigned(k2, ClusterDocID, "cluster", 1, env.Rev+1, string(raw), nil)
	again := NewRuntime(RuntimeOptions{StateDir: b.dir, Self: Self{NodeID: "n_siem-b", Name: "siem-b"}, Clock: e.clock})
	again.Use(e.c, testPrefix, b.master)
	if m, why := again.Mode(); m != ModeKeyMissing {
		t.Fatalf("mode = %s (%s), want %s", m, why, ModeKeyMissing)
	}
	if ok, _ := again.Ready(); ok {
		t.Error("the server is ready")
	}
}
