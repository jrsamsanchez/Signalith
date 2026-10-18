package baselines

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeRunner answers the baselines' searches from a function of the
// search's group-by fields and its hour.
type fakeRunner struct {
	mu       sync.Mutex
	rows     func(by string, start time.Time) []search.Row
	searches int
}

func (f *fakeRunner) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches++
	var by []string
	for _, c := range q.Commands {
		if s, ok := c.(*query.Stats); ok {
			by = s.By
		}
	}
	start, err := time.Parse(time.RFC3339, q.Earliest)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(q.Search.String(), "NOT signalith_sample=*") {
		return nil, fmt.Errorf("sample data not left out: %s", q.Search)
	}
	var rows []search.Row
	if f.rows != nil {
		rows = f.rows(strings.Join(by, ","), start)
	}
	return &search.Result{Kind: "table", Rows: rows}, nil
}

// fakeRisk keeps risk events by ID, as the risk index does.
type fakeRisk struct {
	mu     sync.Mutex
	events map[string]detect.RiskEvent
	writes int
}

func (f *fakeRisk) Write(_ context.Context, evs []detect.RiskEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events == nil {
		f.events = map[string]detect.RiskEvent{}
	}
	for _, e := range evs {
		f.writes++
		f.events[e.ID] = e
	}
	return nil
}

func (f *fakeRisk) Exists(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}

func (f *fakeRisk) of(check string) []detect.RiskEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []detect.RiskEvent
	for _, e := range f.events {
		if e.DetectionID == DetectionID(check) {
			out = append(out, e)
		}
	}
	return out
}

const testIPDB = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"5.5.0.0\t5.5.255.255\t64500\tUS\tEXAMPLE-ISP\n" +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
	"177.0.0.0\t177.0.255.255\t28573\tBR\tCLARO\n" +
	"2.0.0.0\t2.0.0.255\t0\tNone\tNot routed\n" +
	"2600::\t2600::ffff\t7018\tUS\tATT-INTERNET4\n"

type rig struct {
	t      *testing.T
	os     *ostest.Server
	store  *Store
	runner *fakeRunner
	risk   *fakeRisk
	e      *Engine
	now    time.Time
	allow  bool
}

func newRig(t *testing.T, set Settings) *rig {
	t.Helper()
	srv := ostest.New(t)
	cl := store.New(store.Config{URL: srv.URL})
	st := NewStore(cl, "t")
	ctx := context.Background()
	if err := st.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if set.IPDatabase == "" {
		if err := os.WriteFile(filepath.Join(dir, "ip2asn.tsv"), []byte(testIPDB), 0o600); err != nil {
			t.Fatal(err)
		}
		set.IPDatabase = "file:ip2asn.tsv"
	}
	if _, err := st.SaveSettings(ctx, set, store.Version{}); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, os: srv, store: st, runner: &fakeRunner{}, risk: &fakeRisk{}, allow: true,
		now: time.Date(2026, 10, 16, 12, 10, 0, 0, time.UTC)}
	r.e = &Engine{Store: st, Search: r.runner, Risk: r.risk, Now: func() time.Time { return r.now },
		Allowed: func() bool { return r.allow }, Epoch: func() int64 { return 1 }, NodeID: "n1", FileDir: dir,
		history: set.Learning() + 2*24*time.Hour}
	return r
}

// run runs rounds until nothing is waiting.
func (r *rig) run() {
	r.t.Helper()
	for range 100 {
		more, err := r.e.Round(context.Background())
		if err != nil {
			r.t.Fatal(err)
		}
		if !more {
			return
		}
	}
	r.t.Fatal("rounds never caught up")
}

func (r *rig) profile(check, entity string) *Profile {
	r.t.Helper()
	ps, err := r.store.Profiles(context.Background(), check, []string{entity})
	if err != nil {
		r.t.Fatal(err)
	}
	return ps[0]
}

func row(kv ...any) search.Row {
	out := search.Row{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

// A user who always signs in from one country is learned from the
// history first, without risk; a sign-in from another country once
// learning is over adds risk, once, however often that hour is learned.
func TestNewCountryAfterLearning(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 2})
	brazilAt := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,src" {
			return nil
		}
		rows := []search.Row{row("user", "Alice", "src", "5.5.1.2", "count", 3.0, "first", float64(start.Add(time.Minute).Unix()))}
		// Bob has no history: he is still learning when he goes abroad.
		if start.Equal(brazilAt) {
			rows = append(rows,
				row("user", "alice", "src", "177.0.3.4", "count", 1.0, "first", float64(start.Add(7*time.Minute).Unix())),
				row("user", "bob", "src", "177.0.3.5", "count", 1.0),
				// Private and unknown addresses say nothing.
				row("user", "alice", "src", "10.1.2.3", "count", 1.0),
				row("user", "alice", "src", "9.9.9.9", "count", 1.0))
		}
		return rows
	}
	r.run()
	if n := len(r.risk.events); n != 0 {
		t.Fatalf("history raised %d risk events", n)
	}
	p := r.profile(NewCountry, "alice")
	if p == nil || len(p.Values) != 1 || p.Values[0].V != "US" {
		t.Fatalf("profile %+v", p)
	}
	r.now = brazilAt.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(NewCountry)
	if len(evs) != 1 {
		t.Fatalf("raised %d new-country events: %+v", len(evs), evs)
	}
	ev := evs[0]
	// The name as the hour's events first spell it.
	if ev.Object != "Alice" || ev.ObjectType != "user" || ev.Score != 40 || ev.Fields["src_country"] != "BR" ||
		ev.Fields["src"] != "177.0.3.4" || ev.Fields["baseline"] != NewCountry || ev.Fields["src_asn"] != "AS28573" {
		t.Errorf("event %+v", ev)
	}
	if !ev.Time.Equal(brazilAt.Add(7 * time.Minute)) {
		t.Errorf("event time %v, want the first sign-in's", ev.Time)
	}
	if !strings.Contains(ev.Message, "Brazil (BR)") {
		t.Errorf("message %q", ev.Message)
	}
	// The new network is the same news: not raised again.
	if evs := r.risk.of(NewNetwork); len(evs) != 0 {
		t.Errorf("new network raised with the new country: %+v", evs)
	}
	// Learning the same hour again changes nothing.
	writes := r.risk.writes
	st, v, _, _ := r.store.State(context.Background())
	st.Through = brazilAt
	if _, err := r.store.SaveState(context.Background(), st, v); err != nil {
		t.Fatal(err)
	}
	r.run()
	if r.risk.writes != writes {
		t.Errorf("the hour learned again wrote %d more risk events", r.risk.writes-writes)
	}
	p = r.profile(NewCountry, "alice")
	for _, v := range p.Values {
		if v.V == "BR" && v.N != 1 {
			t.Errorf("BR counted %d times", v.N)
		}
	}
}

// A new network in a known country adds the network's own, smaller risk.
func TestNewNetwork(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1})
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,src" {
			return nil
		}
		src := "5.5.1.2"
		if start.Equal(at) {
			src = "8.8.8.8"
		}
		return []search.Row{row("user", "carol", "src", src)}
	}
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(NewNetwork)
	if len(evs) != 1 || evs[0].Fields["src_asn"] != "AS15169" || !strings.Contains(evs[0].Message, "AS15169 (GOOGLE)") {
		t.Fatalf("events %+v", evs)
	}
	if evs := r.risk.of(NewCountry); len(evs) != 0 {
		t.Errorf("same country raised: %+v", evs)
	}
}

// A program new on a learned host adds risk only while few hosts ran it.
func TestRareProcess(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "dest,process_name" {
			return nil
		}
		var rows []search.Row
		for i := range 6 {
			h := fmt.Sprintf("ws-%02d", i)
			rows = append(rows, row("dest", h, "process_name", "explorer.exe"))
			if start.Equal(at) {
				// A rollout reaches every host at once: common, not rare.
				rows = append(rows, row("dest", h, "process_name", "NewAgent.exe"))
			}
		}
		if start.Equal(at) {
			rows = append(rows, row("dest", "WS-03", "process_name", "Mimikatz.EXE"))
		}
		return rows
	}
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(RareProcess)
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	ev := evs[0]
	if ev.Object != "ws-03" || ev.ObjectType != "system" || ev.Fields["process_name"] != "Mimikatz.EXE" || ev.Fields["baseline_value"] != "mimikatz.exe" {
		t.Errorf("event %+v", ev)
	}
	if p := r.profile(prevalenceCheck, "newagent.exe"); p == nil || len(p.Values) != 6 {
		t.Errorf("fleet profile %+v", p)
	}
}

// A sign-in at an hour a user is rarely active adds risk, after enough
// history.
func TestUnusualHour(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 7, IPDatabase: "off"})
	r.now = time.Date(2026, 10, 16, 0, 10, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user" {
			return nil
		}
		if h := start.Hour(); h >= 8 && h < 17 && start.Weekday() != time.Saturday && start.Weekday() != time.Sunday {
			return []search.Row{row("user", "dave")}
		}
		if start.Equal(time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)) {
			return []search.Row{row("user", "dave", "first", float64(start.Add(12*time.Minute).Unix()))}
		}
		return nil
	}
	r.run()
	r.now = time.Date(2026, 10, 16, 4, 10, 0, 0, time.UTC)
	r.run()
	evs := r.risk.of(UnusualHour)
	if len(evs) != 1 || evs[0].Fields["baseline_value"] != "03:00 UTC" || !strings.Contains(evs[0].Message, "between 03:00 and 04:00 UTC") {
		t.Fatalf("events %+v", evs)
	}
	p := r.profile(UnusualHour, "dave")
	if p.ByHour[9] == 0 || p.Hours < minHourHistory {
		t.Errorf("profile %+v", p)
	}
}

// An hour that sends far more than a host usually does adds risk; its
// usual busy hours do not.
func TestDataVolume(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 5, IPDatabase: "off"})
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "src" {
			return nil
		}
		rows := []search.Row{row("src", "10.0.0.5", "bytes", 20e6), row("src", "10.0.0.6", "bytes", float64(150e6+int(start.Hour())*1e6)),
			// Outside addresses are not learned.
			row("src", "8.8.8.8", "bytes", 9e9)}
		if start.Equal(at) {
			rows[0]["bytes"] = 3e9
		}
		return rows
	}
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(DataVolume)
	if len(evs) != 1 || evs[0].Object != "10.0.0.5" || evs[0].Fields["bytes_out"] != int64(3e9) {
		t.Fatalf("events %+v", evs)
	}
	if !strings.Contains(evs[0].Message, "3.0 GB") || !strings.Contains(evs[0].Message, "its usual 20 MB") {
		t.Errorf("message %q", evs[0].Message)
	}
	if p := r.profile(DataVolume, "8.8.8.8"); p != nil {
		t.Errorf("outside address learned: %+v", p)
	}
}

// New kinds of change: cloud API calls by name, others by action and
// object.
func TestNewChange(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		switch by {
		case "user,command":
			rows := []search.Row{row("user", "erin", "command", "DescribeInstances")}
			if start.Equal(at) {
				rows = append(rows, row("user", "erin", "command", "CreateAccessKey"))
			}
			return rows
		case "user,action,object_category":
			rows := []search.Row{row("user", "frank", "action", "modified", "object_category", "user")}
			if start.Equal(at) {
				rows = append(rows, row("user", "frank", "action", "deleted", "object_category", "group"))
			}
			return rows
		}
		return nil
	}
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	got := map[string]string{}
	for _, e := range r.risk.of(NewChange) {
		got[e.Object] = e.Fields["baseline_value"].(string)
	}
	if len(got) != 2 || got["erin"] != "CreateAccessKey" || got["frank"] != "deleted group" {
		t.Fatalf("events %v", got)
	}
}

// Exceptions hold back risk but the behavior is still learned; no more
// than MaxRaisedPerHour events come from one hour of one check.
func TestExceptionsAndCap(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off", Exceptions: []detect.Exception{
		{ID: "ex-1", Match: map[string]string{"baseline": NewChange, "risk_object": "svc_*"}, Added: time.Now()},
	}})
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,command" {
			return nil
		}
		var rows []search.Row
		for i := range 80 {
			u := fmt.Sprintf("user%02d", i)
			if i < 10 {
				u = fmt.Sprintf("svc_%02d", i)
			}
			rows = append(rows, row("user", u, "command", "ListBuckets"))
			if start.Equal(at) {
				rows = append(rows, row("user", u, "command", "PutBucketPolicy"))
			}
		}
		return rows
	}
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(NewChange)
	if len(evs) != MaxRaisedPerHour {
		t.Fatalf("raised %d", len(evs))
	}
	for _, e := range evs {
		if strings.HasPrefix(e.Object, "svc_") {
			t.Errorf("excepted %s raised", e.Object)
		}
	}
	st, _, _, _ := r.store.State(context.Background())
	cs := st.Checks[NewChange]
	if cs.Excepted != 10 || cs.Capped != 20 || cs.Raised != MaxRaisedPerHour {
		t.Errorf("counts %+v", cs)
	}
	if p := r.profile(NewChange, "svc_01"); p == nil || !p.has("PutBucketPolicy") {
		t.Errorf("excepted behavior not learned: %+v", p)
	}
}

// A server that no longer runs the jobs writes nothing.
func TestNotAllowedWritesNothing(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	r.runner.rows = func(string, time.Time) []search.Row { return []search.Row{row("user", "x", "command", "Y")} }
	r.allow = false
	r.run()
	if _, _, found, _ := r.store.State(context.Background()); found {
		t.Error("state written")
	}
	if r.runner.searches != 0 {
		t.Errorf("%d searches", r.runner.searches)
	}
}

// Turned off, nothing runs; a check turned off is not searched.
func TestOff(t *testing.T) {
	r := newRig(t, Settings{Off: true})
	r.run()
	if r.runner.searches != 0 {
		t.Errorf("%d searches while off", r.runner.searches)
	}
	r2 := newRig(t, Settings{LearningDays: 1, IPDatabase: "off", Checks: map[string]CheckSettings{
		UnusualHour: {Off: true}, RareProcess: {Off: true}, NewChange: {Off: true}}})
	var mu sync.Mutex
	asked := map[string]bool{}
	r2.runner.rows = func(by string, _ time.Time) []search.Row {
		mu.Lock()
		asked[by] = true
		mu.Unlock()
		return nil
	}
	r2.run()
	if len(asked) != 1 || !asked["src"] {
		t.Errorf("searched %v", asked)
	}
}

// Reset forgets a check's profiles, so it learns again.
func TestReset(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	r.runner.rows = func(by string, _ time.Time) []search.Row {
		if by == "dest,process_name" {
			return []search.Row{row("dest", "h1", "process_name", "a.exe")}
		}
		return nil
	}
	r.run()
	if r.profile(RareProcess, "h1") == nil || r.profile(prevalenceCheck, "a.exe") == nil {
		t.Fatal("not learned")
	}
	ctx := context.Background()
	set, v, _ := r.store.Settings(ctx)
	r.now = r.now.Add(time.Minute)
	set.Checks = map[string]CheckSettings{RareProcess: {ResetAt: r.now}}
	if _, err := r.store.SaveSettings(ctx, set, v); err != nil {
		t.Fatal(err)
	}
	r.runner.rows = nil
	r.run()
	if r.profile(RareProcess, "h1") != nil || r.profile(prevalenceCheck, "a.exe") != nil {
		t.Error("not forgotten")
	}
	st, _, _, _ := r.store.State(ctx)
	if !st.Checks[RareProcess].Started.Equal(r.now) {
		t.Errorf("started %v", st.Checks[RareProcess].Started)
	}
}

// The first run learns from 30 days of history (or the learning period), and
// a server that took the jobs over after a long gap skips what is older
// than maxCatchUp.
func TestBackfillAndCatchUp(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 3, IPDatabase: "off"})
	r.e.history = 0
	r.run()
	// Thirty days, at least the learning period, five searches an hour.
	if n := r.runner.searches; n != 30*24*5 {
		t.Errorf("first run made %d searches", n)
	}
	st, v, _, _ := r.store.State(context.Background())
	if want := r.now.Truncate(time.Hour); !st.Through.Equal(want) {
		t.Errorf("through %v, want %v", st.Through, want)
	}
	if !st.LiveFrom.Equal(r.now) {
		t.Errorf("live from %v", st.LiveFrom)
	}
	searches := r.runner.searches
	st.Through, st.LiveFrom = r.now.Add(-30*24*time.Hour), r.now.Add(-60*24*time.Hour)
	if _, err := r.store.SaveState(context.Background(), st, v); err != nil {
		t.Fatal(err)
	}
	r.run()
	// Seven days of hours, five searches each (no IP database).
	if n := r.runner.searches - searches; n > 7*24*5+5 {
		t.Errorf("%d searches making up a month", n)
	}
}

// A state write from a server with an older lease is refused.
func TestStaleState(t *testing.T) {
	r := newRig(t, Settings{IPDatabase: "off"})
	ctx := context.Background()
	if _, err := r.store.SaveState(ctx, State{Epoch: 5}, store.Version{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.SaveState(ctx, State{Epoch: 4}, store.Version{}); err != ErrStale {
		t.Errorf("older epoch: %v", err)
	}
	if _, err := r.store.SaveState(ctx, State{Epoch: 6}, store.Version{}); err != nil {
		t.Errorf("newer epoch: %v", err)
	}
}

// The IP database is downloaded once a week, kept, and read back by the
// next server.
func TestIPDBKept(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1})
	ctx := context.Background()
	// Not downloaded while no sign-in comes from the internet.
	r.run()
	if meta, _, _ := r.store.IPDBStatus(ctx); !meta.TriedAt.IsZero() {
		t.Fatalf("downloaded with no sign-in from the internet: %+v", meta)
	}
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by == "user,src" {
			return []search.Row{row("user", "dave", "src", "1.0.0.9")}
		}
		return nil
	}
	r.now = r.now.Add(time.Hour)
	r.run()
	meta, _, err := r.store.IPDBStatus(ctx)
	if err != nil || meta.Rows != 5 || meta.Error != "" || meta.FetchedAt.IsZero() {
		t.Fatalf("status %+v %v", meta, err)
	}
	// Another server reads the stored copy without the file.
	set, v, _ := r.store.Settings(ctx)
	e2 := &Engine{Store: r.store, Search: r.runner, Now: r.e.Now, FileDir: r.e.FileDir}
	if err := os.Remove(filepath.Join(r.e.FileDir, "ip2asn.tsv")); err != nil {
		t.Fatal(err)
	}
	e2.maintainIPDB(ctx, set, r.now, false)
	if db := e2.currentIPDB(); db == nil || db.Rows() != 5 {
		t.Fatalf("stored copy not read: %v", db)
	}
	// A week later the download is tried again; a failure keeps the copy.
	r.now = r.now.Add(ipdbFresh)
	e2.maintainIPDB(ctx, set, r.now, false)
	meta, _, _ = r.store.IPDBStatus(ctx)
	if meta.Error == "" || meta.Rows != 5 || e2.currentIPDB() == nil {
		t.Errorf("after a failed download: %+v", meta)
	}
	// Off drops it.
	set.IPDatabase = "off"
	if _, err := r.store.SaveSettings(ctx, set, v); err != nil {
		t.Fatal(err)
	}
	e2.maintainIPDB(ctx, set, r.now, false)
	if e2.currentIPDB() != nil {
		t.Error("still loaded while off")
	}
}
