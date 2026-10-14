package cases

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// modifyStores returns each Store to test Modify on, with a way to make
// the next n conditional writes conflict (nil when the store has none)
// and a way to delete a case behind the store's back.
func modifyStores(t *testing.T) map[string]func() (Store, func(n int), func(id string)) {
	return map[string]func() (Store, func(n int), func(id string)){
		"memory": func() (Store, func(n int), func(id string)) {
			m := NewMemory()
			return m, nil, func(id string) { _ = m.Delete(context.Background(), id) }
		},
		"opensearch": func() (Store, func(n int), func(id string)) {
			fake := ostest.New(t)
			s := NewOpenSearch(store.New(store.Config{URL: fake.URL}), "sig")
			conflicts := func(n int) {
				fake.FailN(n, http.MethodPut, "if_seq_no", http.StatusConflict, "version_conflict_engine_exception")
			}
			return s, conflicts, func(id string) { fake.Delete(s.Index, id) }
		},
	}
}

func comment(text string) func(c *Case) (bool, error) {
	return func(c *Case) (bool, error) {
		_, err := c.AddEntry(Entry{Kind: KindNote, Text: text}, "ana", time.Now().UTC())
		return err == nil, err
	}
}

// TestModifyKeepsEveryConcurrentChange: many writers add timeline
// entries to the same case at once; no entry is lost.
func TestModifyKeepsEveryConcurrentChange(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := mk()
			if err := s.Create(ctx, &Case{ID: "c1", Title: "t", Status: findings.StatusNew}); err != nil {
				t.Fatal(err)
			}
			const n = 10
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := s.Modify(ctx, "c1", comment(fmt.Sprint("note ", i))); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			c, err := s.Get(ctx, "c1")
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, e := range c.Entries {
				seen[e.Text] = true
			}
			if len(c.Entries) != n || len(seen) != n {
				t.Errorf("%d timeline entries kept (%d different), want %d", len(c.Entries), len(seen), n)
			}
		})
	}
}

func TestModifyConflictsAndMissing(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, conflicts, del := mk()
			if err := s.Create(ctx, &Case{ID: "c1", Title: "t", Status: findings.StatusNew}); err != nil {
				t.Fatal(err)
			}
			if conflicts != nil {
				// A few conflicts: the change is applied again and lands once.
				conflicts(3)
				runs := 0
				c, err := s.Modify(ctx, "c1", func(c *Case) (bool, error) {
					runs++
					return comment("after conflicts")(c)
				})
				if err != nil || runs != 4 || len(c.Entries) != 1 {
					t.Fatalf("modify after 3 conflicts = %v, %d runs, %+v", err, runs, c)
				}
				// Conflicts on every try: busy, and nothing written.
				conflicts(store.ModifyTries)
				runs = 0
				_, err = s.Modify(ctx, "c1", func(c *Case) (bool, error) {
					runs++
					return comment("never")(c)
				})
				if !errors.Is(err, ErrBusy) || runs != store.ModifyTries {
					t.Fatalf("modify under constant conflicts = %v after %d runs", err, runs)
				}
				conflicts(0)
				if c, _ := s.Get(ctx, "c1"); len(c.Entries) != 1 {
					t.Errorf("entries = %+v", c.Entries)
				}
			}

			// The change's own error comes back as it is, even one that
			// looks like a conflict, and is not retried.
			runs := 0
			mine := fmt.Errorf("refused: %w", store.ErrConflict)
			if _, err := s.Modify(ctx, "c1", func(*Case) (bool, error) { runs++; return false, mine }); err != mine || runs != 1 {
				t.Errorf("change error = %v after %d runs", err, runs)
			}

			// Deleted while the change ran: not found.
			_, err := s.Modify(ctx, "c1", func(c *Case) (bool, error) {
				del("c1")
				return comment("too late")(c)
			})
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("modify of a deleted case = %v", err)
			}
			if _, err := s.Modify(ctx, "nope", comment("x")); !errors.Is(err, ErrNotFound) {
				t.Errorf("modify of a missing case = %v", err)
			}
		})
	}
}

// TestCreateNeverReplacesACaseInEitherStore: a second Create with the same
// ID is ErrExists and leaves the first case as it was.
func TestCreateNeverReplacesACaseInEitherStore(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := mk()
			if err := s.Create(ctx, &Case{ID: "c1", Title: "first", Status: findings.StatusNew}); err != nil {
				t.Fatal(err)
			}
			if err := s.Create(ctx, &Case{ID: "c1", Title: "second", Status: findings.StatusNew}); !errors.Is(err, ErrExists) {
				t.Fatalf("second create = %v", err)
			}
			if c, err := s.Get(ctx, "c1"); err != nil || c.Title != "first" {
				t.Errorf("case = %+v %v", c, err)
			}
		})
	}
}
