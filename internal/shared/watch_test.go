package shared

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
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
