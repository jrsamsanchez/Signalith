package intel

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// U21: ReplaceSource removes the indicators of the source that are in
// OpenSearch, including those another server wrote after this one last
// loaded them.
func TestReplaceSourceFromOpenSearch(t *testing.T) {
	ctx := context.Background()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	backend := NewOpenSearch(cl, "sig")
	if err := backend.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	a := NewStore(NewOpenSearch(cl, "sig"))
	b := NewStore(NewOpenSearch(cl, "sig"))
	a.Now, b.Now = func() time.Time { return now }, func() time.Time { return now }
	if err := b.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// A downloads the feed after B loaded; B never sees it.
	var bumps int
	a.AfterWrite = func() { bumps++ }
	if _, _, err := a.ReplaceSource(ctx, "feed", []Indicator{{Type: TypeIP, Value: "192.0.2.1"}, {Type: TypeIP, Value: "192.0.2.2"},
		{Type: TypeIP, Value: "192.0.2.3"}}); err != nil {
		t.Fatal(err)
	}
	if bumps != 1 {
		t.Errorf("AfterWrite called %d times", bumps)
	}
	// Another source's indicators are left alone.
	if _, _, err := a.ReplaceSource(ctx, "other", []Indicator{{Type: TypeIP, Value: "192.0.2.9"}}); err != nil {
		t.Fatal(err)
	}
	if len(b.Lookup("192.0.2.3")) != 0 {
		t.Fatal("B saw A's write without reloading")
	}
	// B now runs the feed, which lists only one of them.
	added, removed, err := b.ReplaceSource(ctx, "feed", []Indicator{{Type: TypeIP, Value: "192.0.2.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || removed != 2 {
		t.Errorf("added %d removed %d, want 0 and 2", added, removed)
	}
	ids, err := backend.SourceIDs(ctx, "feed")
	if err != nil || len(ids) != 1 {
		t.Fatalf("left in OpenSearch: %v %v", ids, err)
	}
	if other, _ := backend.SourceIDs(ctx, "other"); len(other) != 1 {
		t.Errorf("the other source lost indicators: %v", other)
	}
	c := NewStore(NewOpenSearch(cl, "sig"))
	if err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.Lookup("192.0.2.1")) != 0 || len(c.Lookup("192.0.2.3")) != 0 || len(c.Lookup("192.0.2.2")) != 1 {
		t.Error("a fresh load still finds removed indicators")
	}
}
