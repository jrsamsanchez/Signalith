package sample

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// countSearcher answers every search with no hits, or with err, and counts
// the searches; onSearch runs before each.
type countSearcher struct {
	n        atomic.Int64
	err      error
	onSearch func()
}

func (c *countSearcher) Search(context.Context, string, map[string]any) (map[string]any, error) {
	c.n.Add(1)
	if c.onSearch != nil {
		c.onSearch()
	}
	if c.err != nil {
		return nil, c.err
	}
	return map[string]any{"hits": map[string]any{"total": map[string]any{"value": 0}, "hits": []any{}}}, nil
}

func builtinLibrary(t *testing.T) *detect.Library {
	t.Helper()
	lib, problems, err := detect.NewLibrary("")
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	return lib
}

// TestLoadRunsDetections: with a library and an engine, a load runs the
// enabled detections at each scenario's end, the risk ones last, and a
// detection that fails does not stop the load.
func TestLoadRunsDetections(t *testing.T) {
	ctx := context.Background()
	lib := builtinLibrary(t)
	enabled, risk := 0, 0
	for _, d := range lib.List() {
		if d.Enabled {
			enabled++
			if isRiskModel(d) {
				risk++
			}
		}
	}
	if enabled == 0 || risk == 0 {
		t.Fatalf("built-ins: %d enabled, %d on the risk model", enabled, risk)
	}

	for _, fail := range []bool{false, true} {
		l, _, _, _, _ := newTestLoader(t, t.TempDir())
		cs := &countSearcher{}
		if fail {
			cs.err = &store.Error{Status: http.StatusBadRequest, Body: `{"error":{"type":"parse_exception","reason":"bad"}}`}
		}
		l.Library, l.Engine = lib, &search.Engine{Store: cs}
		var phases []string
		st, err := l.Load(ctx, SizeSmall, func(p Progress) { phases = append(phases, p.Phase) })
		if err != nil {
			t.Fatalf("fail=%v: %v", fail, err)
		}
		if st.Findings != 0 || st.RiskEvents != 0 || cs.n.Load() == 0 {
			t.Errorf("fail=%v: state %+v after %d searches", fail, st, cs.n.Load())
		}
		if !strings.Contains(strings.Join(phases, "|"), "Running detections") {
			t.Errorf("fail=%v: phases %v", fail, phases)
		}
	}

	// A load stopped while the detections run returns why.
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	l.Library, l.Engine = lib, &search.Engine{Store: &countSearcher{onSearch: cancel}}
	if _, err := l.Load(cctx, SizeSmall, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled load = %v", err)
	}
}

func TestCannotFire(t *testing.T) {
	if got := (&Loader{}).CannotFire(); len(got) != 0 {
		t.Errorf("no library = %v", got)
	}
	lib := builtinLibrary(t)
	got := (&Loader{Library: lib}).CannotFire()
	off := 0
	for _, d := range lib.List() {
		_, listed := got[d.ID]
		want := !d.Enabled && d.Origin == nil
		if want {
			off++
		}
		if listed != want {
			t.Errorf("%s (enabled %v) listed %v", d.ID, d.Enabled, listed)
		}
	}
	if len(got) != off {
		t.Errorf("listed %d, want %d", len(got), off)
	}
	for id, why := range got {
		if !strings.Contains(why, "Off by default") {
			t.Errorf("%s: %q", id, why)
		}
	}
}

// errOS fails every call, as an unreachable OpenSearch would.
type errOS struct{}

func (errOS) Do(context.Context, string, string, any, any) error {
	return &store.Error{Status: http.StatusServiceUnavailable, Body: "down"}
}

func TestEventsSince(t *testing.T) {
	ctx := context.Background()
	if n := (&Loader{}).EventsSince(ctx, time.Hour); n != -1 {
		t.Errorf("no OpenSearch = %d", n)
	}
	if _, err := (&Loader{}).AnyEventSince(ctx, time.Hour); !errors.Is(err, errNoDocs) {
		t.Errorf("no OpenSearch = %v", err)
	}
	l, _, fos, _, _ := newTestLoader(t, t.TempDir())
	if n := l.EventsSince(ctx, time.Hour); n != 2 {
		t.Errorf("EventsSince = %d", n)
	}
	if ok, err := l.AnyEventSince(ctx, time.Hour); !ok || err != nil {
		t.Errorf("AnyEventSince = %v %v", ok, err)
	}
	fos.cleared = map[string]bool{fos.indices[0]: true, fos.indices[1]: true}
	if ok, err := l.AnyEventSince(ctx, time.Hour); ok || err != nil {
		t.Errorf("AnyEventSince with none = %v %v", ok, err)
	}
	l.OS = errOS{}
	if n := l.EventsSince(ctx, time.Hour); n != -1 {
		t.Errorf("EventsSince failing = %d", n)
	}
	if _, err := l.AnyEventSince(ctx, time.Hour); err == nil {
		t.Error("AnyEventSince failing gave no error")
	}
}

func TestWatchListsStops(t *testing.T) {
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.WatchLists(ctx, 5*time.Millisecond)
		close(done)
	}()
	// Let it tick at least once, then stop it.
	time.AfterFunc(30*time.Millisecond, cancel)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("WatchLists did not stop")
	}

	// An unreachable record is logged, not fatal.
	l.Docs = nil
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	l.WatchLists(ctx2, time.Hour)
}

func TestSmallHelpers(t *testing.T) {
	if !SizeSmall.Valid() || !SizeStandard.Valid() || Size("huge").Valid() || SizeSmall.String() != string(SizeSmall) {
		t.Error("Size")
	}
	e := &OldJobsServerError{Name: "siem-b"}
	if !strings.Contains(e.Error(), "siem-b, runs") {
		t.Errorf("no version: %s", e)
	}
	e.Version = "1.2.0"
	if !strings.Contains(e.Error(), "siem-b (version 1.2.0)") {
		t.Errorf("version: %s", e)
	}
	if !isRiskModel(&detect.Detection{Query: "datamodel = Risk | stats count"}) || isRiskModel(&detect.Detection{Query: "datamodel=Authentication"}) {
		t.Error("isRiskModel")
	}
	r := newRNG(1)
	if r.intn(0) != 0 || r.pick(nil) != "" {
		t.Error("rng on nothing")
	}
	at := time.Now().Add(-time.Hour)
	if got := r.timeIn(at, at); !got.Equal(at) {
		t.Errorf("between an empty span = %v", got)
	}
	if statusText(304) != "Not Modified" || statusText(999) != "" || lastSlash("abc") != -1 {
		t.Error("statusText")
	}
}
