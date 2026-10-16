package clustercfg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const testPrefix = "signalith"

// logBuffer is a log that tests can read.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// member is one server of the cluster on the fake: its runtime, with the
// content's documents and importers.
type member struct {
	t      *testing.T
	name   string
	dir    string
	master *secrets.Keyring
	rt     *shared.Runtime
	docs   *Docs
	cfg    atomic.Pointer[config.Config]
	logs   *logBuffer
	log    *slog.Logger
}

// testOS is one fake OpenSearch.
type testOS struct {
	fake *ostest.Server
	cl   *store.Client
}

func newOS(t *testing.T) *testOS {
	fake := ostest.New(t)
	return &testOS{fake: fake, cl: store.New(store.Config{URL: fake.URL})}
}

// loadConfig loads a signalith.yaml with extra in dir.
func loadConfig(t *testing.T, dir, extra string) *config.Config {
	t.Helper()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	body := "auth:\n  admin_password_hash: " + h + "\ningest:\n  tokens: [tok-0123456789abcdef]\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newMember starts a server named name with signalith.yaml extra. With
// key it has the cluster key and joins; without, it founds the cluster
// (with its files), and peers are the other servers' retention
// fingerprints its import sees.
func newMember(t *testing.T, o *testOS, name, extra string, key *shared.ClusterKey, peers map[string]string) *member {
	t.Helper()
	m := &member{t: t, name: name, dir: t.TempDir(), docs: NewDocs(), logs: &logBuffer{}}
	m.log = slog.New(slog.NewJSONHandler(m.logs, nil))
	m.master = secrets.NewKeyring(m.dir)
	m.cfg.Store(loadConfig(t, m.dir, extra))
	if key != nil {
		if err := (shared.KeyStore{Dir: m.dir, Master: m.master}).SaveClusterKey(key); err != nil {
			t.Fatal(err)
		}
	}
	files := Files{Config: func() *config.Config { return m.cfg.Load() }, Node: name, NodeID: "n_" + name,
		Client: func() (*store.Client, string) { return o.cl, testPrefix }, LeaseEpoch: func() int64 { return 1 },
		Peers: func() map[string]string { return peers }}
	m.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: m.dir, Self: shared.Self{NodeID: "n_" + name, Name: name},
		Content: m.docs.Track, Importers: Importers(m.docs, files), Log: m.log})
	m.rt.Use(o.cl, testPrefix, m.master)
	if key == nil {
		if err := m.rt.Found(context.Background(), "test"); err != nil {
			t.Fatal(err)
		}
	}
	if mode, why := m.rt.Mode(); mode != shared.ModeMember {
		t.Fatalf("%s: mode %s (%s)", name, mode, why)
	}
	return m
}

// cycle reads the shared settings once.
func (m *member) cycle() {
	m.t.Helper()
	if err := m.rt.Hub().Cycle(context.Background()); err != nil {
		m.t.Fatal(err)
	}
}

func (m *member) key() *shared.ClusterKey { return m.rt.Hub().Keys().Active() }

// feeds returns a downloader of the shared feeds on this server; leads
// says whether it runs the background jobs.
func (m *member) feeds(o *testOS, leads bool) (*intel.Feeds, *StatusStore) {
	st := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Node: "n_" + m.name,
		Leads: func() bool { return leads }, Epoch: func() int64 { return 1 }, Log: m.log}
	f := &intel.Feeds{Store: intel.NewStore(intel.NewMemory()), Saved: &FeedList{Docs: m.docs, Node: m.name},
		StatusStore: st, AllowLoopback: true, Allowed: func() bool { return leads }, Log: m.log}
	if err := f.Load(); err != nil {
		m.t.Fatal(err)
	}
	return f, st
}

// feedServer counts the downloads of a feed.
func feedServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("203.0.113.9\n198.51.100.7\n"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// U19: a feed added on B, a member that does not download, is seen by A's
// downloader after one watch cycle; it is downloaded exactly once, by A,
// and B shows the status A wrote.
func TestFeedsAcrossServers(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	b := newMember(t, o, "siem-b", "", a.key(), nil)
	fa, sa := a.feeds(o, true)
	fb, _ := b.feeds(o, false)
	srv, hits := feedServer(t)

	ctx := context.Background()
	if _, err := fb.AddFeedAs(ctx, "bob", intel.FeedInput{Name: "blocklist", URL: srv.URL, Format: intel.FormatLines, Type: "ip",
		Interval: "1h", MaxAge: "1d"}); err != nil {
		t.Fatal(err)
	}
	fb.RunDue(ctx)
	if n := hits.Load(); n != 0 {
		t.Fatalf("B downloaded %d times", n)
	}
	a.cycle()
	if _, ok := fa.Get("blocklist"); !ok {
		t.Fatal("A does not see the feed B added")
	}
	fa.RunDue(ctx)
	fa.RunDue(ctx)
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d downloads, want 1", n)
	}
	sa.Flush(ctx)
	time.Sleep(2100 * time.Millisecond) // B's cache of the status
	st := fb.Status()
	if len(st) != 1 || st[0].Status.Count != 2 || st[0].Status.LastSuccess.IsZero() {
		t.Fatalf("B's view of the status: %+v", st)
	}
	// The change is recorded with who made it, on which server.
	body, _ := a.docs.Feeds().Get()
	if len(body.Feeds) != 1 || body.Feeds[0].From == nil || body.Feeds[0].From.Source != FromPage || body.Feeds[0].From.Node != "siem-b" {
		t.Fatalf("shared feeds %+v", body.Feeds)
	}
	if by, _, _ := a.docs.Feeds().Updated(); by.User != "bob" || by.Node != "siem-b" {
		t.Errorf("updated by %+v", by)
	}
	// A feed's version read on one server holds on the other; it is
	// keyed, so it cannot be used to test guesses of its secrets.
	ea, _ := fa.ETag("blocklist")
	eb, _ := fb.ETag("blocklist")
	plain := &intel.Feeds{}
	if _, err := plain.AddFeed(intel.FeedInput{Name: "blocklist", URL: srv.URL, Format: intel.FormatLines, Type: "ip", Interval: "1h", MaxAge: "1d"}); err != nil {
		t.Fatal(err)
	}
	ep, _ := plain.ETag("blocklist")
	if ea == "" || ea != eb || ea == ep {
		t.Errorf("etags %s %s, unshared %s", ea, eb, ep)
	}
	if _, err := fb.UpdateFeedIf(ctx, "bob", "blocklist", ea, intel.FeedInput{URL: srv.URL, Format: intel.FormatLines, Type: "ip", Interval: "2h", MaxAge: "1d"}); err != nil {
		t.Fatalf("update with A's version: %v", err)
	}
}

// U20: feed secrets are sealed with the cluster key for the address they
// are sent to. A page change that points the feed elsewhere must enter
// them again; a stored value moved to another address cannot be opened,
// and the feed shows a problem instead of sending it.
func TestFeedSecretsBoundToOrigin(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	fa, _ := a.feeds(o, true)
	ctx := context.Background()
	if _, err := fa.AddFeedAs(ctx, "admin", intel.FeedInput{Name: "otx", URL: "https://otx.example.com/feed", Format: intel.FormatLines,
		Type: "ip", Headers: []intel.HeaderInput{{Name: "X-Key", Value: "very-secret"}}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o.fake.Source(shared.ConfigIndex(testPrefix), FeedsID))
	if bytes.Contains(raw, []byte("very-secret")) {
		t.Fatal("the header is stored in plain text")
	}
	body, _ := a.docs.Feeds().Get()
	sealed := body.Feeds[0].Headers["X-Key"]
	if !strings.HasPrefix(sealed, "enc:v1:"+a.key().ID()+":") {
		t.Fatalf("header stored as %q", sealed)
	}
	if fd, _ := fa.Get("otx"); fd.Headers["X-Key"] != "very-secret" || fd.Problem != "" {
		t.Fatalf("feed in use %+v", fd)
	}

	// The page: another address without the header again is refused.
	in, _ := fa.InputFor("otx")
	in.URL = "https://elsewhere.example.net/feed"
	in.Headers = []intel.HeaderInput{{Name: "X-Key"}}
	var ie *intel.InputError
	if _, err := fa.UpdateFeedAs(ctx, "admin", "otx", in); !errorsAs(err, &ie) || !strings.Contains(err.Error(), "enter the value of header X-Key again") {
		t.Fatalf("moved without the header: %v", err)
	}

	// The stored value moved to another address (as a copy of the entry
	// would) cannot be opened there.
	if _, err := a.docs.Feeds().Mutate(ctx, "test", func(b *FeedsBody) error {
		b.Feeds[0].URL = "https://elsewhere.example.net/feed"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fd, _ := fa.Get("otx")
	if fd.Headers["X-Key"] == "very-secret" || fd.Problem == "" {
		t.Fatalf("a moved secret was opened: %+v", fd)
	}
	if _, err := fa.Refresh(ctx, "otx"); err == nil {
		t.Fatal("a feed whose secret cannot be opened was downloaded")
	}
}

func errorsAs(err error, target **intel.InputError) bool {
	ie, ok := err.(*intel.InputError)
	if ok {
		*target = ie
	}
	return ok
}

// U5 for feeds: fields of a later version, on the list and on each feed,
// survive a change made by this one.
func TestFeedFieldsOfLaterVersionsSurvive(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	fa, _ := a.feeds(o, true)
	ctx := context.Background()
	for _, n := range []string{"one", "two"} {
		if _, err := fa.AddFeedAs(ctx, "admin", intel.FeedInput{Name: n, URL: "https://" + n + ".example.com/f", Format: intel.FormatLines, Type: "ip"}); err != nil {
			t.Fatal(err)
		}
	}
	// A later version's fields, written as that version would.
	if _, err := a.docs.Feeds().Mutate(ctx, "later", func(b *FeedsBody) error {
		b.Extra = shared.Extra{"future": json.RawMessage(`{"x":1}`)}
		for i := range b.Feeds {
			b.Feeds[i].Extra = shared.Extra{"schedule_jitter": json.RawMessage(`"5m"`)}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	in, _ := fa.InputFor("one")
	in.Description = "changed"
	if _, err := fa.UpdateFeedAs(ctx, "admin", "one", in); err != nil {
		t.Fatal(err)
	}
	body, _ := a.docs.Feeds().Get()
	if string(body.Extra["future"]) != `{"x":1}` {
		t.Errorf("list fields lost: %v", body.Extra)
	}
	for _, e := range body.Feeds {
		if string(e.Extra["schedule_jitter"]) != `"5m"` {
			t.Errorf("feed %s lost its fields: %v", e.Name, e.Extra)
		}
	}
}

// U22: a setting in signalith.yaml applies to the shared value when it
// changes, once and audited; an unchanged file at a restart does not undo
// a page edit, and a removed key changes nothing.
func TestAppliedWhenChanged(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "retention:\n  days: 30\n", nil, nil)
	b := newMember(t, o, "siem-b", "retention:\n  days: 45\n", a.key(), nil)
	ctx := context.Background()
	days := func(m *member) int {
		m.t.Helper()
		m.cycle()
		body, ok := m.docs.Retention().Get()
		if !ok || body.Days == nil {
			m.t.Fatal("no shared retention.days")
		}
		return *body.Days
	}
	apply := func(m *member) Applied {
		m.t.Helper()
		m.cycle()
		res, err := Apply(ctx, m.rt, m.docs, m.cfg.Load(), m.name, m.log)
		if err != nil {
			m.t.Fatal(err)
		}
		return res
	}
	// The founder's 30 was imported. B's first start as a member only
	// records what its file says: it differs, which is drift.
	if res := apply(a); len(res.Applied) != 0 || len(res.Drift) != 0 {
		t.Fatalf("founder's first apply %+v", res)
	}
	if res := apply(b); len(res.Applied) != 0 || len(res.Drift) != 1 || res.Drift[0] != "retention.days" {
		t.Fatalf("B's first apply %+v", res)
	}
	if d := days(a); d != 30 {
		t.Fatalf("days %d after B's first start", d)
	}

	// A page edit to 60, then B restarts with its file unchanged.
	ps := &PolicyStore{Docs: a.docs, Log: a.log}
	if err := ps.Update(func(s *retention.Saved) { v := 60; s.Days = &v }); err != nil {
		t.Fatal(err)
	}
	if res := apply(b); len(res.Applied) != 0 {
		t.Fatalf("an unchanged file applied %v", res.Applied)
	}
	if d := days(a); d != 60 {
		t.Fatalf("the page edit was undone: %d", d)
	}

	// B's file changes to 90: applied once, audited.
	b.cfg.Store(loadConfig(t, b.dir, "retention:\n  days: 90\n"))
	if res := apply(b); len(res.Applied) != 1 || res.Applied[0] != "retention.days" || len(res.Drift) != 0 {
		t.Fatalf("changed file %+v", res)
	}
	if d := days(a); d != 90 {
		t.Fatalf("days %d after the change", d)
	}
	if !strings.Contains(b.logs.String(), "retention.days applied from signalith.yaml on siem-b") {
		t.Errorf("not audited:\n%s", b.logs.String())
	}
	body, _ := a.docs.Retention().Get()
	if f := body.From["days"]; f.Source != FromYAML || f.Node != "siem-b" {
		t.Errorf("provenance %+v", f)
	}
	if res := apply(b); len(res.Applied) != 0 {
		t.Fatalf("applied twice: %v", res.Applied)
	}

	// Removed from the file: nothing changes.
	b.cfg.Store(loadConfig(t, b.dir, ""))
	if res := apply(b); len(res.Applied) != 0 || len(res.Drift) != 0 {
		t.Fatalf("removed key %+v", res)
	}
	if d := days(a); d != 90 {
		t.Fatalf("days %d after the key was removed", d)
	}
}

// After reset-key, a restart with the same signalith.yaml applies
// nothing: the recorded hashes were made with the old key, so the values
// are only recorded again, and the page's change stays.
func TestAppliedAfterResetKey(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "retention:\n  days: 30\n", nil, nil)
	ctx := context.Background()
	if _, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{Docs: a.docs, Log: a.log}
	if err := ps.Update(func(s *retention.Saved) { v := 365; s.Days = &v }); err != nil {
		t.Fatal(err)
	}
	docs, _, err := shared.ReadAll(ctx, o.cl, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := shared.Resign(ctx, o.cl, testPrefix, docs, k2, 100, "sam", a.name, at, "n_"+a.name, shared.KeyringMember{Name: a.name}); err != nil {
		t.Fatal(err)
	}
	a.rt.Hub().SetKeys(shared.NewKeySet(k2))
	a.cycle()
	res, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 0 {
		t.Fatalf("applied after reset-key: %v", res.Applied)
	}
	a.cycle()
	if body, ok := a.docs.Retention().Get(); !ok || body.Days == nil || *body.Days != 365 {
		t.Fatalf("the page's change was undone: %+v", body)
	}
	// The file's value is recorded under the new key: a change applies.
	a.cfg.Store(loadConfig(t, a.dir, "retention:\n  days: 40\n"))
	a.cycle()
	if res, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err != nil || len(res.Applied) != 1 {
		t.Fatalf("changed file after reset-key: %+v %v", res, err)
	}
}

// Feeds in signalith.yaml apply when they change too, with their ${ENV}
// references filled in on the server whose file it is.
func TestYAMLFeedApplied(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	ctx := context.Background()
	if _, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_FEED_KEY", "from-env")
	a.cfg.Store(loadConfig(t, a.dir, "intel:\n  feeds:\n    - name: abuse\n      url: https://abuse.example.com/list\n      format: lines\n      type: ip\n      headers:\n        X-Key: ${TEST_FEED_KEY}\n"))
	res, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 1 || res.Applied[0] != "intel.feeds[abuse]" {
		t.Fatalf("applied %+v", res)
	}
	fa, _ := a.feeds(o, true)
	fd, ok := fa.Get("abuse")
	if !ok || fd.Headers["X-Key"] != "from-env" || fd.Source != intel.SourceUI || !strings.Contains(fd.From, "applied from signalith.yaml on siem-a") {
		t.Fatalf("feed %+v", fd)
	}
	// A changed environment value applies again.
	t.Setenv("TEST_FEED_KEY", "rotated")
	if res, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err != nil || len(res.Applied) != 1 {
		t.Fatalf("rotated %+v %v", res, err)
	}
}

// U24 (import part): the founder imports its own retention policies, and
// they wait to be confirmed when another server's own policies differed;
// a server that already shares them (the sentinel) does not count.
func TestImportRetentionHold(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "retention:\n  days: 30\n", nil,
		map[string]string{"siem-b": "sha256:other", "siem-c": cluster.SharedFingerprint("c_x")})
	body, _ := a.docs.Retention().Get()
	if body.Confirm == nil || len(body.Confirm.Servers) != 1 || body.Confirm.Servers["siem-b"] == "" || body.Days == nil || *body.Days != 30 {
		t.Fatalf("imported %+v", body)
	}
	ps := &PolicyStore{Docs: a.docs, Log: a.log}
	if held, why := ps.Hold(); !held || !strings.Contains(why, "siem-b") {
		t.Fatalf("hold %v %q", held, why)
	}
	m := &retention.Manager{Store: ps, Shared: true, Hold: ps.Hold, ConfirmHold: ps.Confirm}
	if err := m.Confirm(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if held, _ := ps.Hold(); held {
		t.Fatal("still held after the confirmation")
	}
	if err := m.Confirm(context.Background(), "admin"); err != retention.ErrNoHold {
		t.Fatalf("second confirmation: %v", err)
	}
	if !strings.Contains(a.logs.String(), "retention.confirm") {
		t.Error("the confirmation was not audited")
	}

	// The same policies elsewhere: no hold.
	o2 := newOS(t)
	c := loadConfig(t, t.TempDir(), "retention:\n  days: 30\n")
	same := newMember(t, o2, "siem-x", "retention:\n  days: 30\n", nil, map[string]string{"siem-y": RetentionFingerprint(c)})
	if body, _ := same.docs.Retention().Get(); body.Confirm != nil {
		t.Fatalf("held for equal policies: %+v", body.Confirm)
	}
}

// The founder imports the feeds added on its page, the feeds in its
// signalith.yaml (which win on a name both use) and their status, so
// downloads stay on their schedules.
func TestImportFeeds(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	c := loadConfig(t, dir, "intel:\n  feeds:\n    - name: dup\n      url: https://yaml.example.com/l\n      format: lines\n      type: ip\n")
	page := &intel.FileList{Path: c.IntelFeedsFile()}
	if _, err := page.Mutate(context.Background(), "", func(s *intel.FeedSet) error {
		s.UI = []intel.FeedSpec{{Name: "dup", URL: "https://page.example.com/l"}, {Name: "mine", URL: "https://mine.example.com/l"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	next := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	sf := &intel.StatusFile{Path: FeedStatusFile(c)}
	sf.Save("mine", &intel.FeedStatus{NextRun: next, Count: 7})

	m := &member{t: t, name: "siem-a", dir: dir, docs: NewDocs(), logs: &logBuffer{}}
	m.log = slog.New(slog.NewJSONHandler(m.logs, nil))
	m.master = secrets.NewKeyring(dir)
	m.cfg.Store(c)
	files := Files{Config: func() *config.Config { return m.cfg.Load() }, Node: "siem-a", NodeID: "n_siem-a",
		Client: func() (*store.Client, string) { return o.cl, testPrefix }, LeaseEpoch: func() int64 { return 4 }}
	m.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_siem-a", Name: "siem-a"},
		Content: m.docs.Track, Importers: Importers(m.docs, files), Log: m.log})
	m.rt.Use(o.cl, testPrefix, m.master)
	if err := m.rt.Found(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	f, _ := m.feeds(o, true)
	dup, _ := f.Get("dup")
	mine, _ := f.Get("mine")
	if dup.URL != "https://yaml.example.com/l" || !strings.Contains(dup.From, "signalith.yaml") || mine.URL == "" || !strings.Contains(mine.From, "imported") {
		t.Fatalf("imported feeds %+v / %+v", dup, mine)
	}
	st := o.fake.Source(cluster.RuntimeIndex(testPrefix), StatusID("mine"))
	if st == nil || fmt.Sprint(st["epoch"]) != "4" {
		t.Fatalf("status %v", st)
	}
	for _, v := range f.Status() {
		if v.Name == "mine" && (v.Status.Count != 7 || !v.Status.NextRun.Equal(next)) {
			t.Fatalf("status in use %+v", v.Status)
		}
	}
}

// A feed's status written by a later holder of the job lease is never
// written over by an earlier one.
func TestStatusEpoch(t *testing.T) {
	o := newOS(t)
	ctx := context.Background()
	newer := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Node: "n_b", Epoch: func() int64 { return 5 }}
	older := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Node: "n_a", Epoch: func() int64 { return 4 }}
	if err := newer.write(ctx, "x", &intel.FeedStatus{Count: 2}, 5); err != nil {
		t.Fatal(err)
	}
	if err := older.write(ctx, "x", &intel.FeedStatus{Count: 1}, 4); err != nil {
		t.Fatal(err)
	}
	got := newer.Load()
	if got["x"] == nil || got["x"].Count != 2 {
		t.Fatalf("status %+v", got["x"])
	}
}

// A status whose write failed is written at the next flush, with the
// epoch it was saved under even when the lease was let go since.
func TestStatusWriteFailedIsKept(t *testing.T) {
	o := newOS(t)
	ctx := context.Background()
	epoch := int64(7)
	s := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Node: "n_a", Epoch: func() int64 { return epoch }}
	s.Save("x", &intel.FeedStatus{Count: 3})
	o.fake.FailN(1, http.MethodGet, "feedstatus:x", http.StatusBadRequest, "illegal_argument_exception")
	if n := s.Flush(ctx); n != 1 {
		t.Fatalf("%d kept after a failed write", n)
	}
	epoch = 0
	if n := s.Flush(ctx); n != 0 {
		t.Fatalf("%d kept after the second flush", n)
	}
	src := o.fake.Source(cluster.RuntimeIndex(testPrefix), StatusID("x"))
	if src == nil || fmt.Sprint(src["epoch"]) != "7" {
		t.Fatalf("stored %v", src)
	}
	// A newer status saved after the write failed wins.
	s.Save("y", &intel.FeedStatus{Count: 1})
	o.fake.FailN(1, http.MethodGet, "feedstatus:y", http.StatusBadRequest, "illegal_argument_exception")
	s.Flush(ctx)
	s.Save("y", &intel.FeedStatus{Count: 2})
	s.Flush(ctx)
	if got := s.Load(); got["y"] == nil || got["y"].Count != 2 {
		t.Fatalf("status %+v", got["y"])
	}
}
