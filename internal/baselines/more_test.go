package baselines

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// failRunner fails every search.
type failRunner struct{}

func (failRunner) Execute(context.Context, *query.Query) (*search.Result, error) {
	return nil, errors.New("search backend gone")
}

// failRisk refuses every risk event.
type failRisk struct{ fakeRisk }

func (*failRisk) Write(context.Context, []detect.RiskEvent) error {
	return errors.New("risk index read-only")
}

// only turns every check off but one.
func only(check string, set Settings) Settings {
	set.Checks = map[string]CheckSettings{}
	for _, c := range Checks {
		if c.ID != check {
			set.Checks[c.ID] = CheckSettings{Off: true}
		}
	}
	return set
}

func volumeRows(at time.Time) func(string, time.Time) []search.Row {
	return func(by string, start time.Time) []search.Row {
		if by != "src" {
			return nil
		}
		rows := []search.Row{row("src", "10.0.0.5", "bytes", 20e6, "first", "not a time")}
		if start.Equal(at) {
			rows[0]["bytes"] = 3e12
			rows[0]["first"] = float64(at.Add(10 * time.Minute).Unix())
		}
		return rows
	}
}

// Risk is scaled by the asset list's priority, and a risk index that
// refuses it stops the hour.
func TestVolumeRiskScaledAndRefused(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 5, IPDatabase: "off"})
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lists.SetAssets(assets.MarshalAssets([]assets.Asset{{IP: []string{"10.0.0.5"}, Priority: "critical"}})); err != nil {
		t.Fatal(err)
	}
	r.e.Assets = lists
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	r.runner.rows = volumeRows(at)
	r.run()
	r.now = at.Add(time.Hour + settle)
	r.run()
	evs := r.risk.of(DataVolume)
	if len(evs) != 1 || evs[0].Priority != "critical" || evs[0].Score <= float64(evs[0].BaseScore) {
		t.Fatalf("events = %+v", evs)
	}
	if !strings.Contains(evs[0].Message, "3.0 TB") || !evs[0].Time.Equal(at.Add(10*time.Minute)) {
		t.Errorf("message %q at %v", evs[0].Message, evs[0].Time)
	}

	r2 := newRig(t, Settings{LearningDays: 5, IPDatabase: "off"})
	r2.runner.rows = volumeRows(at)
	r2.run()
	r2.e.Risk = &failRisk{}
	r2.now = at.Add(time.Hour + settle)
	if _, err := r2.e.Round(context.Background()); err == nil || !strings.Contains(err.Error(), DataVolume) {
		t.Errorf("refused risk = %v", err)
	}
	st, _, _, err := r2.store.State(context.Background())
	if err != nil || !strings.Contains(st.LastError, "read-only") {
		t.Errorf("state = %+v %v", st.LastError, err)
	}
}

// A failing search stops the round, for each check, and is kept in the
// state.
func TestSearchFailuresStopTheRound(t *testing.T) {
	for _, check := range []string{RareProcess, NewChange, DataVolume, UnusualHour} {
		r := newRig(t, only(check, Settings{LearningDays: 1, IPDatabase: "off"}))
		r.e.Search = failRunner{}
		if _, err := r.e.Round(context.Background()); err == nil || !strings.Contains(err.Error(), "search backend gone") {
			t.Errorf("%s: %v", check, err)
			continue
		}
		st, _, _, _ := r.store.State(context.Background())
		if !strings.Contains(st.LastError, "search backend gone") {
			t.Errorf("%s: state error %q", check, st.LastError)
		}
	}
}

func TestRoundStoreFailures(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	fault := func(method, part string) {
		r.os.SetFault(func(m, p string) *ostest.Fault {
			if m == method && strings.Contains(p, part) {
				return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
			}
			return nil
		})
	}
	fault("GET", "/_doc/settings")
	if _, err := r.e.Round(ctx); err == nil {
		t.Error("settings unreadable")
	}
	fault("GET", "/_doc/state")
	if _, err := r.e.Round(ctx); err == nil {
		t.Error("state unreadable")
	}
	// Housekeeping that fails is only logged.
	fault("POST", "_delete_by_query")
	r.run()
	r.os.SetFault(nil)

	// The state cannot be written.
	r.now = r.now.Add(2 * time.Hour)
	fault("PUT", "/_doc/state")
	if _, err := r.e.Round(ctx); err == nil {
		t.Error("state unwritable")
	}
	r.os.SetFault(nil)

	// Learning stops when this server no longer runs the jobs: after an
	// hour, or before the first write.
	r.now = r.now.Add(3 * time.Hour)
	var calls atomic.Int32
	r.e.Allowed = func() bool { return calls.Add(1) < 4 }
	if more, err := r.e.Round(ctx); err != nil || more {
		t.Errorf("stopped = %v %v", more, err)
	}
	r.e.Allowed = func() bool { return false }
	if more, err := r.e.Round(ctx); err != nil || more {
		t.Errorf("not allowed = %v %v", more, err)
	}

	// A reset that cannot be done.
	r.e.Allowed = func() bool { return true }
	set, v, _ := r.store.Settings(ctx)
	set.Checks = map[string]CheckSettings{NewChange: {ResetAt: r.now.Add(time.Minute)}}
	if _, err := r.store.SaveSettings(ctx, set, v); err != nil {
		t.Fatal(err)
	}
	fault("POST", "_delete_by_query")
	if _, err := r.e.Round(ctx); err == nil {
		t.Error("a failed reset was ignored")
	}
	r.os.SetFault(nil)
}

func TestRunStops(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	r.e.mu.Lock()
	r.e.counts = map[string]int64{"x": 1}
	r.e.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.e.Run(ctx)
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	if r.e.counts != nil || r.e.ipdb != nil {
		t.Error("what only the job runner keeps was kept")
	}
	if (&Engine{}).epoch() != 0 || (&Engine{}).log() == nil || (&Engine{}).now().IsZero() {
		t.Error("defaults")
	}
}

func TestValueHelpers(t *testing.T) {
	if str(nil) != "" || str([]any{"a", "b"}) != "a" || str([]any{}) != "" || str(3) != "3" {
		t.Error("str")
	}
	if num(int64(2)) != 2 || num(3) != 3 || num(" 4.5 ") != 4.5 || num(true) != 0 {
		t.Error("num")
	}
	start := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	h := &hourRun{start: start}
	end := start.Add(time.Hour - time.Second)
	for v, want := range map[any]time.Time{
		start.Add(time.Minute).Format(time.RFC3339Nano): start.Add(time.Minute),
		fmt.Sprint(start.Add(3 * time.Minute).Unix()):   start.Add(3 * time.Minute),
		fmt.Sprint(start.Add(-3 * time.Minute).Unix()):  end, // outside the hour
		float64(start.Add(2 * time.Minute).Unix()):      start.Add(2 * time.Minute),
		"junk": end,
	} {
		if got := h.timeOf(search.Row{"first": v}); !got.Equal(want) {
			t.Errorf("timeOf(%v) = %v, want %v", v, got, want)
		}
	}
	for b, want := range map[float64]string{2e12: "2.0 TB", 5e3: "5 KB", 12: "12 bytes", 3e6: "3 MB"} {
		if got := size(b); got != want {
			t.Errorf("size(%v) = %s", b, got)
		}
	}
	if redactSource("https://user@example.com/path?key=1") != "user@example.com" || redactSource("file:x.tsv") != "file:x.tsv" {
		t.Errorf("redact = %s", redactSource("https://user@example.com/path?key=1"))
	}
	if sentence(errors.New("")) != "" {
		t.Error("sentence")
	}
}

func TestFetchIPDBProblems(t *testing.T) {
	ctx := context.Background()
	e := &Engine{}
	if _, err := e.fetchIPDB(ctx, "file:ip2asn.tsv"); err == nil || !strings.Contains(err.Error(), "no ipdb folder") {
		t.Errorf("no folder = %v", err)
	}
	e.FileDir = filepath.Join(t.TempDir(), "missing")
	if _, err := e.fetchIPDB(ctx, "file:ip2asn.tsv"); err == nil || !strings.Contains(err.Error(), "can't be opened") {
		t.Errorf("missing folder = %v", err)
	}
	if _, err := e.fetchIPDB(ctx, "https://ipdb.example/x.tsv"); err == nil || !strings.Contains(err.Error(), "not set up") {
		t.Errorf("no client = %v", err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/loop":
			http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
		case "/ok":
			w.Write([]byte(testIPDB))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e.HTTP = srv.Client()
	if _, err := e.fetchIPDB(ctx, srv.URL+"/gone"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("not found = %v", err)
	}
	if _, err := e.fetchIPDB(ctx, srv.URL+"/loop"); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("loop = %v", err)
	}
	if _, err := e.fetchIPDB(ctx, "https://bad host/"); err == nil {
		t.Error("a bad address was fetched")
	}
	if db, err := e.fetchIPDB(ctx, srv.URL+"/ok"); err != nil || db.Rows() == 0 {
		t.Errorf("ok = %v", err)
	}
}

// The IP database's status cannot be read or saved: the last copy is
// used, and nothing fails.
func TestIPDBStatusFailures(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, Settings{LearningDays: 1})
	set, _, _ := r.store.Settings(ctx)
	r.os.SetFault(func(m, p string) *ostest.Fault {
		if m == "GET" && strings.Contains(p, "ipdb_meta") {
			return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
		}
		return nil
	})
	r.e.maintainIPDB(ctx, set, r.now, true)
	if r.e.currentIPDB() != nil {
		t.Error("loaded without a status")
	}
	r.os.SetFault(func(m, p string) *ostest.Fault {
		if m == "PUT" && strings.Contains(p, "ipdb_meta") {
			return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
		}
		return nil
	})
	r.e.maintainIPDB(ctx, set, r.now, true)
	if r.e.currentIPDB() == nil {
		t.Error("not loaded although the download worked")
	}
	r.os.SetFault(nil)

	// Another server downloaded a newer copy: this one loads it, and
	// keeps its own when the stored copy cannot be read.
	other := &Engine{Store: r.store, FileDir: r.e.FileDir, Now: r.e.Now}
	other.maintainIPDB(ctx, set, r.now.Add(8*24*time.Hour), true)
	r.os.SetFault(func(m, p string) *ostest.Fault {
		if m == "GET" && strings.Contains(p, "/_doc/ipdb?") || m == "GET" && strings.HasSuffix(p, "/_doc/ipdb") {
			return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
		}
		return nil
	})
	before := r.e.currentIPDB()
	r.e.maintainIPDB(ctx, set, r.now.Add(8*24*time.Hour+time.Minute), false)
	if r.e.currentIPDB() != before {
		t.Error("the copy in memory was dropped")
	}
	r.os.SetFault(nil)
	r.e.maintainIPDB(ctx, set, r.now.Add(8*24*time.Hour+time.Minute), false)
	if r.e.currentIPDB() == before {
		t.Error("the newer stored copy was not loaded")
	}
}
