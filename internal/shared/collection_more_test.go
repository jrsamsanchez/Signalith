package shared

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// An item another server wrote that Validate or ValidateItem refuses is
// not used, and reported as invalid.
func TestCollectionValidatesWhatItReads(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	cb.Validate = func(v *testBody) error {
		if v.Name == "" {
			return errors.New("a rule needs a name")
		}
		return nil
	}
	cb.ValidateItem = func(name string, v *testBody) error {
		if strings.HasPrefix(name, "bad") {
			return errors.New("not a rule name: " + name)
		}
		return nil
	}
	for name, body := range map[string]testBody{"good": {Name: "good"}, "empty": {}, "bad1": {Name: "x"}} {
		if _, err := ca.Create(ctx, "sam", name, &body); err != nil {
			t.Fatal(err)
		}
	}
	cycle(t, b)
	if got := names(cb.List()); len(got) != 1 || got[0] != "good" {
		t.Errorf("b uses %v", got)
	}
	reasons := map[string]string{}
	for _, p := range b.Problems() {
		if p.Kind == ProblemInvalid {
			reasons[p.ID] = p.Reason
		}
	}
	if reasons["rule:empty"] != "a rule needs a name" || reasons["rule:bad1"] != "not a rule name: bad1" {
		t.Errorf("problems %v", reasons)
	}
}

// Refresh and Load read now what another server wrote, without waiting
// for the next poll.
func TestCollectionRefreshAndDocLoad(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	da := NewDoc[testBody](a, "users", "users", 1)
	db := NewDoc[testBody](b, "users", "users", 1)
	cycle(t, b)
	if _, err := ca.Create(ctx, "sam", "r1", &testBody{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := cb.Get("r1"); ok {
		t.Fatal("b has the item before reading it")
	}
	if err := cb.Refresh(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if v, _, ok := cb.Get("r1"); !ok || v.Name != "one" {
		t.Errorf("after Refresh: %+v %v", v, ok)
	}
	if err := cb.Refresh(ctx, "never"); err != nil {
		t.Errorf("Refresh of an item not there = %v", err)
	}
	if err := db.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := db.Get(); !ok || v.Name != "jlee" {
		t.Errorf("after Load: %+v %v", v, ok)
	}
}

// A create of an item another server made that this one has not read is
// refused; one over a tombstone this server has not read is written.
func TestCollectionCreateOverUnread(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	cycle(t, a)
	if _, err := cb.Create(ctx, "bob", "r1", &testBody{Name: "b's"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Create(ctx, "sam", "r1", &testBody{Name: "a's"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("a create over an item not read = %v", err)
	}
	if _, err := cb.Create(ctx, "bob", "r2", &testBody{Name: "gone"}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := cb.Get("r2")
	if _, err := cb.Delete(ctx, "bob", "r2", etag); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Create(ctx, "sam", "r2", &testBody{Name: "again"}); err != nil {
		t.Fatalf("a create over a tombstone not read = %v", err)
	}
	cycle(t, b)
	if v, _, ok := cb.Get("r2"); !ok || v.Name != "again" {
		t.Errorf("r2 = %+v %v", v, ok)
	}
}

func TestStaleAndProblemErrors(t *testing.T) {
	for _, c := range []struct {
		e    StaleError
		want string
	}{
		{StaleError{}, "it was changed since it was read; reload it"},
		{StaleError{By: "bob"}, "it was changed by bob; reload it"},
		{StaleError{Node: "siem-b", By: "bob", At: "2026-10-12T09:00:00Z"}, "it was changed on siem-b by bob at 2026-10-12T09:00:00Z; reload it"},
		{StaleError{Node: "siem-b"}, "it was changed on siem-b; reload it"},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("%+v: %q", c.e, got)
		}
	}
	pe := &ProblemError{Problem{ID: "users", Reason: "it fails its check"}}
	if pe.Error() != "users cannot be changed now: it fails its check" {
		t.Errorf("%q", pe.Error())
	}
}

// A hub started with the real clock reads what another server writes on
// its own.
func TestHubStartPolls(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b := NewHub(Options{NodeName: "siem-b", Timing: Timing{Poll: 15 * time.Millisecond, Resync: time.Minute, Wait: time.Second, CacheEvery: time.Second}})
	b.SetKeys(NewKeySet(e.key))
	b.Use(e.c, testPrefix)
	da := NewDoc[testBody](a, "users", "users", 1)
	db := NewDoc[testBody](b, "users", "users", 1)
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	b.Start(run)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		v, ok := db.Get()
		return ok && v.Name == "jlee"
	})
}

// A server given the cluster key again on purpose leaves the removed
// list; one not on it changes nothing.
func TestForgetRemoved(t *testing.T) {
	rc := newRotationCluster(t)
	ctx := context.Background()
	if _, err := rc.a.rt.RemoveMember(ctx, "n_siem-c", "siem-c", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := rc.a.rt.Removed(); len(got) != 1 || got[0].NodeID != "n_siem-c" {
		t.Fatalf("removed %+v", got)
	}
	if err := rc.a.rt.ForgetRemoved(ctx, "n_never"); err != nil {
		t.Fatal(err)
	}
	if len(rc.a.rt.Removed()) != 1 {
		t.Error("forgetting a server never removed changed the list")
	}
	if err := rc.a.rt.ForgetRemoved(ctx, "n_siem-c"); err != nil {
		t.Fatal(err)
	}
	if got := rc.a.rt.Removed(); len(got) != 0 {
		t.Errorf("removed %+v", got)
	}
	idle := NewRuntime(RuntimeOptions{StateDir: t.TempDir(), Self: Self{NodeID: "n_z", Name: "siem-z"}})
	if err := idle.ForgetRemoved(ctx, "n_siem-c"); err != nil {
		t.Errorf("ForgetRemoved without a cluster = %v", err)
	}
}

// A batch whose watch bump is refused is saved all the same, with no
// sequence number and a warning; an item the checks refuse, or one
// changed outside Signalith, stops it.
func TestMutateManyRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, logs := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	write := func(name string, _ *testBody) (*testBody, bool, error) { return &testBody{Name: name}, true, nil }
	failing(e, func(method, path string) bool {
		return strings.HasSuffix(path, "/_refresh") || method == "PUT" && strings.Contains(path, "watch:rules")
	})
	n, seq, err := ca.MutateMany(ctx, "sam", []string{"r1", "r2"}, write)
	if err != nil || n != 2 || seq != 0 {
		t.Errorf("MutateMany = %d, %d, %v", n, seq, err)
	}
	mustContain(t, "log", logs.String(), "saved, but the other servers may not see it")
	e.os.SetFault(nil)

	ca.Validate = func(v *testBody) error {
		if v.Name == "bad" {
			return errors.New("not that name")
		}
		return nil
	}
	if n, _, err := ca.MutateMany(ctx, "sam", []string{"bad"}, write); err == nil || n != 0 {
		t.Errorf("MutateMany that Validate refuses = %d, %v", n, err)
	}
	ca.Validate = nil

	// r1 changed outside Signalith: b refuses to write over it.
	cycle(t, b)
	src := e.os.Source(testIndex, ca.ItemID("r1"))
	src["body"] = `{"name":"forged"}`
	e.os.Put(testIndex, ca.ItemID("r1"), src)
	cycle(t, b)
	var pe *ProblemError
	if _, _, err := cb.MutateMany(ctx, "bob", []string{"r1"}, write); !errors.As(err, &pe) {
		t.Errorf("MutateMany over a tampered item = %v", err)
	}
	// Reads refused while an item is read again after a conflict.
	if _, err := cb.Mutate(ctx, "bob", "r2", func(v *testBody) error { v.Items = []string{"b"}; return nil }); err != nil {
		t.Fatal(err)
	}
	failing(e, func(method, path string) bool { return method == "GET" && strings.Contains(path, "rule:r2") })
	if _, _, err := ca.MutateMany(ctx, "sam", []string{"r2"}, write); err == nil {
		t.Error("MutateMany with the item unreadable after a conflict")
	}
}
