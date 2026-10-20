// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// memBackend is a Backend in memory, as a cluster's shared settings are:
// it records who changed what, and calls its listeners after a change.
type memBackend struct {
	mu      sync.Mutex
	items   map[string]Stored
	loadErr error
	listen  []func()
	changes int
}

func (b *memBackend) Load() (map[string]Stored, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loadErr != nil {
		return nil, b.loadErr
	}
	out := make(map[string]Stored, len(b.items))
	for k, v := range b.items {
		out[k] = v
	}
	return out, nil
}

func (b *memBackend) Change(_ context.Context, by string, ids []string, fn func(string, Stored) (Stored, bool, error)) error {
	for _, id := range ids {
		b.mu.Lock()
		cur := b.items[id]
		b.mu.Unlock()
		next, write, err := fn(id, cur)
		if err != nil {
			return err
		}
		if !write {
			continue
		}
		b.mu.Lock()
		next.By, next.Node, next.At = by, "node-1", "2026-10-19T12:00:00Z"
		if next.Custom == nil && next.State == nil {
			delete(b.items, id)
		} else {
			b.items[id] = next
		}
		b.changes++
		b.mu.Unlock()
	}
	b.mu.Lock()
	ls := append([]func(){}, b.listen...)
	b.mu.Unlock()
	for _, f := range ls {
		f()
	}
	return nil
}

func (b *memBackend) OnChange(fn func()) {
	b.mu.Lock()
	b.listen = append(b.listen, fn)
	b.mu.Unlock()
}

// A library with a backend keeps its custom detections and the state of
// the shipped ones there, and reads them again when it changes.
func TestLibraryBackend(t *testing.T) {
	lib, _, err := NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	if lib.Shared() {
		t.Fatal("shared before a backend")
	}
	off := false
	b := &memBackend{items: map[string]Stored{
		"auth-brute-force": {State: &State{Enabled: &off}, By: "alice", Node: "node-0", At: "2026-10-18T09:00:00Z"},
		"theirs":           {Custom: &Detection{ID: "theirs", Title: "Theirs", Query: "user=eve", Source: "custom"}},
		"nothing":          {State: &State{}},
	}}
	if err := lib.UseBackend(b); err != nil {
		t.Fatal(err)
	}
	if !lib.Shared() {
		t.Fatal("not shared")
	}
	if d, err := lib.Get("auth-brute-force"); err != nil || d.Enabled {
		t.Fatalf("shipped detection's state not read: %+v %v", d, err)
	}
	if by, node, at := lib.Changed("auth-brute-force"); by != "alice" || node != "node-0" || at == "" {
		t.Errorf("changed = %s %s %s", by, node, at)
	}
	if d, err := lib.Get("theirs"); err != nil || d.Title != "Theirs" {
		t.Fatalf("custom detection not read: %+v %v", d, err)
	}

	// A change goes to the backend, by its user, and is read back.
	if err := lib.PutIf(context.Background(), "bob", &Detection{ID: "mine", Title: "Mine", Query: "user=bob"}, ""); err != nil {
		t.Fatal(err)
	}
	if b.items["mine"].Custom == nil || b.items["mine"].By != "bob" {
		t.Fatalf("backend = %+v", b.items["mine"])
	}
	if d, err := lib.Get("mine"); err != nil || d.Source != "custom" {
		t.Fatalf("mine = %+v %v", d, err)
	}
	etag := lib.ETag("mine")
	if etag == "" || etag == ETag(nil, nil) {
		t.Fatalf("etag = %q", etag)
	}
	if got := lib.ETags()["mine"]; got != etag {
		t.Errorf("ETags = %q, ETag %q", got, etag)
	}
	if lib.ETag("no-such-detection") != "" {
		t.Error("an unknown detection has an ETag")
	}

	// Another server changes it: the page's etag is stale.
	b.mu.Lock()
	it := b.items["mine"]
	c := *it.Custom
	c.Severity = "high"
	it.Custom, it.By, it.Node = &c, "carol", "node-2"
	b.items["mine"] = it
	b.mu.Unlock()
	err = lib.PutIf(context.Background(), "bob", &Detection{ID: "mine", Title: "Mine 2", Query: "user=bob"}, etag)
	var stale *StaleError
	if !errors.As(err, &stale) || stale.By != "carol" || !strings.Contains(err.Error(), "carol changed this on node-2") {
		t.Fatalf("stale put: %v", err)
	}
	// Writing the same detection again changes nothing in the backend.
	cur, _ := lib.Get("mine")
	n := b.changes
	if err := lib.Put(cur); err != nil {
		t.Fatal(err)
	}
	if b.changes != n {
		t.Errorf("an unchanged put wrote the backend")
	}

	// Turning shipped detections on records the choice there.
	if err := lib.SetEnabledBy(context.Background(), "bob", []string{"auth-brute-force"}, true); err != nil {
		t.Fatal(err)
	}
	if _, kept := b.items["auth-brute-force"]; kept {
		t.Errorf("a choice equal to the default was kept: %+v", b.items["auth-brute-force"])
	}
	if d, _ := lib.Get("auth-brute-force"); !d.Enabled {
		t.Error("not turned on")
	}
	// An exception on a shipped detection is state.
	until := time.Now().Add(time.Hour)
	if _, err := lib.UpdateExceptionsIf(context.Background(), "bob", "auth-brute-force", "", func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: NewExceptionID(), Match: map[string]string{"src": "10.*"}, Until: &until}), nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := b.items["auth-brute-force"].State; st == nil || len(st.Exceptions) != 1 {
		t.Fatalf("exception state = %+v", b.items["auth-brute-force"])
	}
	if !strings.HasPrefix(b.items["auth-brute-force"].State.Exceptions[0].ID, "ex-") {
		t.Error("exception id")
	}

	// A change on another server reaches the library through OnChange.
	b.mu.Lock()
	b.items["late"] = Stored{Custom: &Detection{ID: "late", Title: "Late", Query: "x=1"}}
	b.mu.Unlock()
	b.Change(context.Background(), "dave", nil, nil)
	if _, err := lib.Get("late"); err != nil {
		t.Errorf("change elsewhere not read: %v", err)
	}
	// A backend that cannot be read keeps the library's copy.
	b.mu.Lock()
	b.loadErr = errors.New("offline")
	b.mu.Unlock()
	lib.reload()
	if _, err := lib.Get("late"); err != nil {
		t.Errorf("lost the copy: %v", err)
	}
	b.mu.Lock()
	b.loadErr = nil
	b.mu.Unlock()

	// Deleting: a custom one goes, a shipped one cannot.
	if err := lib.DeleteIf(context.Background(), "bob", "late", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Get("late"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted detection still there: %v", err)
	}
	if err := lib.Delete("auth-brute-force"); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Errorf("deleted a built-in: %v", err)
	}
	if err := lib.Delete("never-was"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete unknown: %v", err)
	}

	// A backend that cannot be read at first is an error.
	lib2, _, _ := NewLibrary("")
	if err := lib2.UseBackend(&memBackend{loadErr: errors.New("offline")}); err == nil {
		t.Error("used an unreadable backend")
	}
}

func TestStaleErrorWithoutWho(t *testing.T) {
	if got := (&StaleError{}).Error(); !strings.Contains(got, "reload") {
		t.Errorf("error = %q", got)
	}
}

// A state file is read strictly and written as it is read.
func TestStateFiles(t *testing.T) {
	st, err := DecodeState(nil)
	if err != nil || !st.empty() {
		t.Fatalf("empty file = %+v %v", st, err)
	}
	if _, err := DecodeState([]byte("bogus: 1\n")); err == nil {
		t.Error("read an unknown key")
	}
	on := true
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	in := &State{Enabled: &on, Exceptions: []Exception{{ID: "ex-1", Match: map[string]string{"user": "svc_*"}, Until: &until, Added: until.Add(-time.Hour)}}}
	data, err := EncodeState(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeState(data)
	if err != nil || out.Enabled == nil || !*out.Enabled || len(out.Exceptions) != 1 || out.Exceptions[0].Match["user"] != "svc_*" {
		t.Errorf("round trip = %+v %v", out, err)
	}
	if p := ExceptionProblems([]Exception{{ID: "a"}, {ID: "a", Match: map[string]string{"bad field!": " "}}}); len(p) < 3 {
		t.Errorf("problems = %v", p)
	}
}

// Exceptions match values of every kind, and describe themselves.
func TestExceptionMatching(t *testing.T) {
	e := &Exception{Match: map[string]string{"user": "SVC_*", "port": "44?"}}
	for _, c := range []struct {
		row  map[string]any
		want bool
	}{
		{map[string]any{"user": "svc_backup", "port": int64(443)}, true},
		{map[string]any{"user": []any{"bob", "svc_x"}, "port": "445"}, true},
		{map[string]any{"user": []string{"bob", "svc_y"}, "port": 440}, true},
		{map[string]any{"user": []string{"bob"}, "port": 443}, false},
		{map[string]any{"user": []any{"bob"}, "port": 443}, false},
		{map[string]any{"port": 443}, false},
	} {
		if got := e.Matches(c.row); got != c.want {
			t.Errorf("Matches(%v) = %v", c.row, got)
		}
	}
	if got := e.Describe(); got != "port=44? and user=SVC_*" {
		t.Errorf("describe = %q", got)
	}
	if got := (&Exception{}).Describe(); got != "every result" {
		t.Errorf("describe all = %q", got)
	}
	now := time.Now()
	past := now.Add(-time.Hour)
	if !(&Exception{Until: &past}).Expired(now) || (&Exception{}).Expired(now) {
		t.Error("expired")
	}
}
