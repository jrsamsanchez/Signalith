package findings

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// modifyStores returns each Store to test Modify on, with a way to make
// the next n conditional writes conflict (nil when the store has none)
// and a way to delete a finding behind the store's back.
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

func comment(text string) func(f *Finding) (bool, error) {
	return func(f *Finding) (bool, error) {
		return f.Apply(Update{Comment: text}, "ana", time.Now().UTC()), nil
	}
}

// TestModifyKeepsEveryConcurrentChange: many writers comment on the same
// finding at once; no comment is lost.
func TestModifyKeepsEveryConcurrentChange(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := mk()
			if err := s.Create(ctx, &Finding{ID: "f1", Status: StatusNew, Severity: "high"}); err != nil {
				t.Fatal(err)
			}
			const n = 10
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := s.Modify(ctx, "f1", comment(fmt.Sprint("note ", i))); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			f, err := s.Get(ctx, "f1")
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, c := range f.Comments {
				seen[c.Text] = true
			}
			if len(f.Comments) != n || len(seen) != n {
				t.Errorf("%d comments kept (%d different), want %d", len(f.Comments), len(seen), n)
			}
		})
	}
}

func TestModifyConflictsAndMissing(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, conflicts, del := mk()
			if err := s.Create(ctx, &Finding{ID: "f1", Status: StatusNew}); err != nil {
				t.Fatal(err)
			}
			if conflicts != nil {
				// A few conflicts: the change is applied again and lands once.
				conflicts(3)
				runs := 0
				f, err := s.Modify(ctx, "f1", func(f *Finding) (bool, error) {
					runs++
					return comment("after conflicts")(f)
				})
				if err != nil || runs != 4 || len(f.Comments) != 1 {
					t.Fatalf("modify after 3 conflicts = %v, %d runs, %+v", err, runs, f)
				}
				// Conflicts on every try: busy, and nothing written.
				conflicts(store.ModifyTries)
				runs = 0
				_, err = s.Modify(ctx, "f1", func(f *Finding) (bool, error) {
					runs++
					return comment("never")(f)
				})
				if !errors.Is(err, ErrBusy) || runs != store.ModifyTries {
					t.Fatalf("modify under constant conflicts = %v after %d runs", err, runs)
				}
				conflicts(0)
				if f, _ := s.Get(ctx, "f1"); len(f.Comments) != 1 {
					t.Errorf("comments = %+v", f.Comments)
				}
			}

			// The change's own error comes back as it is, even one that
			// looks like a conflict, and is not retried.
			runs := 0
			mine := fmt.Errorf("refused: %w", store.ErrConflict)
			if _, err := s.Modify(ctx, "f1", func(*Finding) (bool, error) { runs++; return false, mine }); err != mine || runs != 1 {
				t.Errorf("change error = %v after %d runs", err, runs)
			}

			// Deleted while the change ran: not found.
			_, err := s.Modify(ctx, "f1", func(f *Finding) (bool, error) {
				del("f1")
				return comment("too late")(f)
			})
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("modify of a deleted finding = %v", err)
			}
			if _, err := s.Modify(ctx, "nope", comment("x")); !errors.Is(err, ErrNotFound) {
				t.Errorf("modify of a missing finding = %v", err)
			}
		})
	}
}

// TestCreateNeverReplacesAFinding: a second Create with the same ID is
// ErrExists and leaves the first finding as it was.
func TestCreateNeverReplacesAFinding(t *testing.T) {
	for name, mk := range modifyStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := mk()
			if err := s.Create(ctx, &Finding{ID: "f1", Title: "first", Status: StatusNew}); err != nil {
				t.Fatal(err)
			}
			if err := s.Create(ctx, &Finding{ID: "f1", Title: "second", Status: StatusNew}); !errors.Is(err, ErrExists) {
				t.Fatalf("second create = %v", err)
			}
			if f, err := s.Get(ctx, "f1"); err != nil || f.Title != "first" {
				t.Errorf("finding = %+v %v", f, err)
			}
		})
	}
}
