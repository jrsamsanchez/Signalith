// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// failing makes the fake answer 500 to the requests match picks.
func failing(e *testEnv, match func(method, path string) bool) {
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if match(method, path) {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
}

func writes(method, path string) bool {
	return method == http.MethodPut || method == http.MethodDelete || method == http.MethodPost && !strings.Contains(path, "_search")
}

func everything(string, string) bool { return true }

// A document's writes report what OpenSearch, the key or the checks
// refuse, and change nothing.
func TestDocWriteRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "users", "users", 1)
	db := NewDoc[testBody](b, "users", "users", 1)
	set := func(name string) func(*testBody) error {
		return func(v *testBody) error { v.Name = name; return nil }
	}

	// Not read yet, and OpenSearch does not answer.
	failing(e, everything)
	if _, err := da.Mutate(ctx, "sam", set("x")); err == nil {
		t.Error("Mutate with OpenSearch down")
	}
	if _, err := da.MutateIf(ctx, "sam", "", set("x")); err == nil {
		t.Error("MutateIf with OpenSearch down")
	}
	if err := da.Load(ctx); err == nil {
		t.Error("Load with OpenSearch down")
	}
	e.os.SetFault(nil)

	// Reads work, writes do not.
	failing(e, writes)
	if _, err := da.Mutate(ctx, "sam", set("x")); err == nil {
		t.Error("Mutate with writes refused")
	}
	if _, err := da.Create(ctx, "sam", &testBody{Name: "x"}); err == nil {
		t.Error("Create with writes refused")
	}
	e.os.SetFault(nil)

	if _, err := da.Create(ctx, "sam", &testBody{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	if _, err := da.Create(ctx, "sam", &testBody{Name: "again"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("Create of a document that is there = %v", err)
	}
	// A page that read nothing, of a document that is there: stale.
	var stale *StaleError
	if _, err := db.MutateIf(ctx, "bob", "", set("y")); !errors.As(err, &stale) || stale.By != "sam" {
		t.Errorf("MutateIf from nothing = %v", err)
	}
	// B changes it while A holds the old copy: A's save at the etag it
	// read is stale and names B's change.
	etag := da.ETag()
	if _, err := db.Mutate(ctx, "bob", set("bob's")); err != nil {
		t.Fatal(err)
	}
	if _, err := da.MutateIf(ctx, "sam", etag, set("sam's")); !errors.As(err, &stale) || stale.By != "bob" || stale.Node != "siem-b" {
		t.Errorf("MutateIf over a change = %v", err)
	}
	if v, _ := da.Get(); v.Name != "bob's" {
		t.Errorf("after the stale save, a has %+v", v)
	}
	if _, err := da.SaveIf(ctx, "sam", &testBody{Name: "saved"}, da.ETag()); err != nil {
		t.Errorf("SaveIf at the current etag = %v", err)
	}
	boom := errors.New("no")
	if _, err := da.MutateIf(ctx, "sam", da.ETag(), func(*testBody) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("MutateIf whose fn refuses = %v", err)
	}

	// The checks and the key.
	da.Validate = func(v *testBody) error {
		if v.Name == "bad" {
			return errors.New("not that name")
		}
		return nil
	}
	if _, err := da.Mutate(ctx, "sam", set("bad")); err == nil || err.Error() != "not that name" {
		t.Errorf("Mutate that Validate refuses = %v", err)
	}
	if _, err := da.MutateIf(ctx, "sam", da.ETag(), set("bad")); err == nil {
		t.Error("MutateIf that Validate refuses")
	}
	nokey := NewHub(Options{NodeName: "siem-z", Clock: e.clock})
	nokey.Use(e.c, testPrefix)
	dz := NewDoc[testBody](nokey, "other", "other", 1)
	if _, err := dz.Mutate(ctx, "sam", set("x")); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("Mutate without a key = %v", err)
	}
	if _, err := dz.Create(ctx, "sam", &testBody{}); err == nil {
		t.Error("Create without a key")
	}

	// A document changed outside Signalith cannot be changed.
	src := e.os.Source(testIndex, "users")
	src["body"] = `{"name":"forged"}`
	e.os.Put(testIndex, "users", src)
	cycle(t, b)
	var pe *ProblemError
	if _, err := db.Mutate(ctx, "bob", set("y")); !errors.As(err, &pe) {
		t.Errorf("Mutate of a tampered document = %v", err)
	}
	if _, err := db.MutateIf(ctx, "bob", db.ETag(), set("y")); !errors.As(err, &pe) {
		t.Errorf("MutateIf of a tampered document = %v", err)
	}
}

// A collection's writes report what OpenSearch and the checks refuse.
func TestCollectionWriteRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	set := func(name string) func(*testBody) error {
		return func(v *testBody) error { v.Name = name; return nil }
	}
	if _, err := ca.Create(ctx, "sam", "r1", &testBody{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)

	failing(e, writes)
	if _, err := ca.Create(ctx, "sam", "r2", &testBody{Name: "two"}); err == nil {
		t.Error("Create with writes refused")
	}
	if _, err := ca.Mutate(ctx, "sam", "r1", set("x")); err == nil {
		t.Error("Mutate with writes refused")
	}
	_, etag, _ := ca.Get("r1")
	if _, err := ca.SaveIf(ctx, "sam", "r1", &testBody{Name: "x"}, etag); err == nil {
		t.Error("SaveIf with writes refused")
	}
	if _, err := ca.Delete(ctx, "sam", "r1", etag); err == nil {
		t.Error("Delete with writes refused")
	}
	if _, _, err := ca.MutateMany(ctx, "sam", []string{"r1"}, func(string, *testBody) (*testBody, bool, error) {
		return &testBody{Name: "x"}, true, nil
	}); err == nil {
		t.Error("MutateMany with writes refused")
	}
	e.os.SetFault(nil)
	failing(e, everything)
	if err := ca.Refresh(ctx, "r1"); err == nil {
		t.Error("Refresh with OpenSearch down")
	}
	if _, err := ca.Mutate(ctx, "sam", "new", set("x")); err == nil {
		t.Error("Mutate of an unread item with OpenSearch down")
	}
	e.os.SetFault(nil)

	// B changes r1 while A holds the old copy.
	if _, err := cb.Mutate(ctx, "bob", "r1", set("bob's")); err != nil {
		t.Fatal(err)
	}
	var stale *StaleError
	if _, err := ca.MutateIf(ctx, "sam", "r1", etag, set("sam's")); !errors.As(err, &stale) || stale.By != "bob" {
		t.Errorf("MutateIf over a change = %v", err)
	}
	if _, err := ca.MutateIf(ctx, "sam", "never", "", set("x")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("MutateIf of an item that is not there = %v", err)
	}
	boom := errors.New("no")
	if _, err := ca.Mutate(ctx, "sam", "r1", func(*testBody) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("Mutate whose fn refuses = %v", err)
	}
	ca.Validate = func(v *testBody) error {
		if v.Name == "bad" {
			return errors.New("not that name")
		}
		return nil
	}
	if _, err := ca.Mutate(ctx, "sam", "r1", set("bad")); err == nil {
		t.Error("Mutate that Validate refuses")
	}
	if _, err := ca.Create(ctx, "sam", "r9", &testBody{Name: "bad"}); err == nil {
		t.Error("Create that Validate refuses")
	}

	// Housekeeping whose deletes are refused keeps the tombstone.
	_, etag, _ = ca.Get("r1")
	if _, err := ca.Delete(ctx, "sam", "r1", etag); err != nil {
		t.Fatal(err)
	}
	failing(e, func(method, _ string) bool { return method == http.MethodDelete })
	later := e.clock.Now().Add(TombstoneAge + time.Hour)
	if n, _, err := ca.Housekeep(ctx, later); err == nil || n != 0 || !strings.Contains(err.Error(), "rule:r1") {
		t.Errorf("Housekeep with deletes refused = %d, %v", n, err)
	}
	if _, err := a.Housekeep(ctx, later); err == nil {
		t.Error("Hub.Housekeep with deletes refused")
	}
	e.os.SetFault(nil)
	if n, _, err := ca.Housekeep(ctx, later); err != nil || n != 1 {
		t.Errorf("Housekeep = %d, %v", n, err)
	}
}

// The requests and chunks report what OpenSearch refuses.
func TestRequestsAndChunksRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	ra := NewRequests(a, "n_a")
	req, err := ra.Submit(ctx, "test", TargetLeader, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	ref, sum, err := a.PutChunks(ctx, "sam", ChunkRef{Kind: "assetlist", Name: "hosts", Gen: 1}, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	failing(e, writes)
	if _, err := ra.Submit(ctx, "test", TargetLeader, nil, "sam"); err == nil {
		t.Error("Submit with writes refused")
	}
	if err := ra.SetProgress(ctx, req, 1, 2); err == nil {
		t.Error("SetProgress with writes refused")
	}
	if err := ra.SaveResult(ctx, req); err == nil {
		t.Error("SaveResult with writes refused")
	}
	if _, _, err := a.PutChunks(ctx, "sam", ChunkRef{Kind: "assetlist", Name: "other", Gen: 1}, []byte("data")); err == nil {
		t.Error("PutChunks with writes refused")
	}
	e.os.SetFault(nil)
	failing(e, everything)
	if _, _, err := ra.Get(ctx, req.ID); err == nil {
		t.Error("Get with OpenSearch down")
	}
	if _, err := ra.Housekeep(ctx, e.clock.Now()); err == nil {
		t.Error("Housekeep with OpenSearch down")
	}
	if _, err := a.ReadChunks(ctx, ref, sum); err == nil || errors.Is(err, ErrChunkMissing) {
		t.Errorf("ReadChunks with OpenSearch down = %v", err)
	}
	if err := a.AcceptRestore(ctx, "sam", 0); err == nil {
		t.Error("AcceptRestore with OpenSearch down")
	}
	e.os.SetFault(nil)
	if _, err := ra.SubmitTo(ctx, "test", nil, false, nil, "sam"); err == nil {
		t.Error("a request for no server")
	}
	nokey := NewHub(Options{NodeName: "siem-z", Clock: e.clock})
	nokey.Use(e.c, testPrefix)
	if err := nokey.AcceptRestore(ctx, "sam", 0); err == nil {
		t.Error("AcceptRestore without a key")
	}
}

// accept-restore leaves a document that fails its MAC as it is, and
// reports a write OpenSearch refuses.
func TestAcceptRestoreRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, logs := e.hub("siem-a")
	d := NewDoc[testBody](a, "users", "users", 1)
	c := NewCollection[testBody](a, "rule", "rules", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Create(ctx, "sam", "r1", &testBody{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	stranger, _ := NewClusterKey()
	e.putSigned(stranger, "forged", "settings", 1, 1, `{}`, nil)
	failing(e, func(method, path string) bool {
		return method == http.MethodPut && strings.Contains(path, "/_doc/users")
	})
	err := a.AcceptRestore(ctx, "sam", 10)
	if err == nil || !strings.Contains(err.Error(), "users") {
		t.Errorf("AcceptRestore = %v", err)
	}
	mustContain(t, "log", logs.String(), "accept-restore left documents that fail their checks")
	if src := e.os.Source(testIndex, "forged"); fmt.Sprint(src["rev"]) != "1" {
		t.Errorf("the forged document was written again: %v", src)
	}
	if _, _, rev := d.Updated(); rev > 10 {
		t.Errorf("users at rev %d although its write was refused", rev)
	}
	if _, etag, _ := c.Get("r1"); etag == "" {
		t.Error("r1 is gone")
	}
}

// A Remote reports what it cannot read or write.
func TestRemoteRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	r := NewRemote[testBody](a, "nodecfg:n_b", "nodecfg", 1)
	set := func(v *testBody) error { v.Name = "x"; return nil }
	failing(e, everything)
	if _, _, _, err := r.Read(ctx); err == nil {
		t.Error("Read with OpenSearch down")
	}
	if err := r.Mutate(ctx, "sam", set); err == nil {
		t.Error("Mutate with OpenSearch down")
	}
	e.os.SetFault(nil)
	boom := errors.New("no")
	if err := r.Mutate(ctx, "sam", func(*testBody) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("Mutate whose fn refuses = %v", err)
	}
	r.Validate = func(v *testBody) error { return errors.New("never") }
	if err := r.Mutate(ctx, "sam", set); err == nil {
		t.Error("Mutate that Validate refuses")
	}
	r.Validate = nil
	if err := r.Mutate(ctx, "sam", set); err != nil {
		t.Fatal(err)
	}
	// A body this version cannot decode is invalid.
	r.Validate = func(v *testBody) error { return errors.New("never") }
	if _, _, _, err := r.Read(ctx); err == nil {
		t.Error("Read of a body Validate refuses")
	}
	unused := NewRemote[testBody](NewHub(Options{NodeName: "x"}), "nodecfg:n_c", "nodecfg", 1)
	if _, _, _, err := unused.Read(ctx); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Errorf("Read without OpenSearch = %v", err)
	}
}

// A forged request for listed servers is refused for this server's part,
// recorded in its status, and logged by the hub's log when the runner has
// none.
func TestRequestsRefuseForgedListed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, logs := e.hub("siem-a")
	r := NewRequests(a, "n_a")
	ran := 0
	rn := &Runner{Requests: r, Lease: (&lease{epoch: 1, holding: true}).get,
		Handlers: map[string]Handler{"restart": func(context.Context, *Request) error { ran++; return nil }}}
	forged := &Request{Kind: "request", ID: "rq_forged", Type: "restart", Targets: []string{"n_a", "n_b"}, State: RequestQueued,
		RequestedBy: "admin", RequestedOn: "siem-a", Created: e.clock.Now().UTC()}
	if _, err := e.c.Create(ctx, r.index(), requestDocID(forged.ID), forged, true); err != nil {
		t.Fatal(err)
	}
	if _, err := rn.RunOnce(ctx); err != nil || ran != 0 {
		t.Fatalf("ran %d: %v", ran, err)
	}
	got, _, err := r.Get(ctx, forged.ID)
	if err != nil || got.State != RequestFailed || got.Status["n_a"] != RequestFailed || !strings.HasPrefix(got.Error, "refused: ") {
		t.Errorf("forged = %+v, %v", got, err)
	}
	mustContain(t, "log", logs.String(), "refused to run a request")
}
