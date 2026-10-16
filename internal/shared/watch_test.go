package shared

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// V2: BumpWith adds fields to the watch document and WatchDoc hands it to
// the subscriber: a server that sees _version move by one drops the one
// session named, by more it clears everything.
func TestBumpWithAndWatchDoc(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")

	var mu sync.Mutex
	cache := map[string]bool{}
	fill := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, id := range []string{"s1", "s2", "s3", "s4"} {
			cache[id] = true
		}
	}
	var last store.Version
	calls := 0
	b.WatchDoc("sessions", func(_ context.Context, raw json.RawMessage, v store.Version) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if v.Same(last) {
			return nil
		}
		var w struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
			At   string `json:"at"`
			Last string `json:"last"`
		}
		if raw != nil {
			if err := json.Unmarshal(raw, &w); err != nil {
				return err
			}
			if w.Kind != "watch" || w.ID != "watch:sessions" || w.At == "" {
				t.Errorf("watch document %s", raw)
			}
		}
		if !last.IsZero() && v.Version == last.Version+1 && w.Last != "" {
			delete(cache, w.Last)
		} else {
			clear(cache)
		}
		last = v
		return nil
	})
	keys := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Sorted(maps.Keys(cache))
	}

	// The first bump: b has seen nothing before, so it clears.
	if _, err := a.BumpWith(ctx, "sessions", map[string]any{"last": "s0"}); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	fill()
	// One sign-out between polls drops that session only.
	seq, err := a.BumpWith(ctx, "sessions", map[string]any{"last": "s2"})
	if err != nil || seq <= 0 {
		t.Fatalf("bump: %d %v", seq, err)
	}
	if src := e.os.Source(testIndex, "watch:sessions"); src["last"] != "s2" || src["kind"] != "watch" {
		t.Errorf("stored %v", src)
	}
	cycle(t, b)
	if got := keys(); !slices.Equal(got, []string{"s1", "s3", "s4"}) {
		t.Errorf("after one sign-out: %v", got)
	}
	// Nothing new: nothing dropped.
	cycle(t, b)
	if got := keys(); len(got) != 3 {
		t.Errorf("after an idle cycle: %v", got)
	}
	// Three between polls: everything goes.
	for _, id := range []string{"s1", "s3", "s4"} {
		if _, err := a.BumpWith(ctx, "sessions", map[string]any{"last": id}); err != nil {
			t.Fatal(err)
		}
	}
	fill()
	cycle(t, b)
	if got := keys(); len(got) != 0 {
		t.Errorf("after three sign-outs: %v", got)
	}
	// A plain Bump leaves no field behind.
	if _, err := a.Bump(ctx, "sessions"); err != nil {
		t.Fatal(err)
	}
	if src := e.os.Source(testIndex, "watch:sessions"); src["last"] != nil {
		t.Errorf("stored %v", src)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n < 3 {
		t.Errorf("%d calls", n)
	}
}

// Poll reads only the config index's mark while nothing changed, and
// reads everything once anything did: a document, an item, a delete made
// outside Signalith, or new keys.
func TestPollStopsAtAnUnchangedMark(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "feeds", "feeds", 1)
	db := NewDoc[testBody](b, "feeds", "feeds", 1)
	ca := NewCollection[testBody](a, "detection", "detections", 1)
	cb := NewCollection[testBody](b, "detection", "detections", 1)
	poll := func() []string {
		t.Helper()
		e.os.Requests()
		if err := b.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		return e.os.Requests()
	}
	reads := func(reqs []string, what string) int {
		n := 0
		for _, r := range reqs {
			if strings.Contains(r, what) {
				n++
			}
		}
		return n
	}

	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "one"; return nil }); err != nil {
		t.Fatal(err)
	}
	if reqs := poll(); reads(reqs, "_mget") == 0 {
		t.Fatalf("the first poll reads the versions: %v", reqs)
	}
	if v, ok := db.Get(); !ok || v.Name != "one" {
		t.Fatalf("b: %+v %v", v, ok)
	}
	confirmed := b.Confirmed()
	e.clock.Advance(DefaultTiming.Poll)
	if reqs := poll(); reads(reqs, "_mget") != 0 || reads(reqs, "_search") != 1 {
		t.Errorf("nothing changed, yet the poll read more than the mark: %v", reqs)
	}
	if !b.Confirmed().After(confirmed) {
		t.Error("an unchanged mark confirms the settings")
	}

	// A change to a document, then to a collection.
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "two"; return nil }); err != nil {
		t.Fatal(err)
	}
	poll()
	if v, _ := db.Get(); v.Name != "two" {
		t.Errorf("b after a change: %+v", v)
	}
	if _, err := ca.Create(ctx, "sam", "brute-force", &testBody{Name: "brute-force"}); err != nil {
		t.Fatal(err)
	}
	poll()
	if got := names(cb.List()); !slices.Equal(got, []string{"brute-force"}) {
		t.Errorf("b's items: %v", got)
	}
	if reqs := poll(); reads(reqs, "_mget") != 0 {
		t.Errorf("read again after the change was applied: %v", reqs)
	}

	// A document removed outside Signalith lowers the count.
	e.os.Delete(testIndex, "feeds")
	poll()
	if !slices.Contains(b.Tamper(), "feeds") {
		t.Errorf("a vanished document is noticed at the next poll: %v", b.Tamper())
	}

	// New keys make the next poll read every document again.
	poll()
	b.SetKeys(NewKeySet(e.key))
	if reqs := poll(); reads(reqs, "_mget") == 0 {
		t.Errorf("new keys, yet nothing read: %v", reqs)
	}
}
