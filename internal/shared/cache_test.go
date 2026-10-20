// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// U10: cache.enc round trip, a cache older than 30 days is not used, and
// rotate-master re-seals it.
func TestCacheRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	da := NewDoc[testBody](a, "retention", "retention", 1)
	ca := NewCollection[testBody](a, "user", "users", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "90 days"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "60 days"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Create(ctx, "sam", "jlee", &testBody{Name: "J. Lee"}); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)

	state := t.TempDir()
	master := secrets.NewKeyring(state)
	c := Cache{Path: CachePath(state), Master: master, ClusterID: "c_1", Prefix: testPrefix}
	w := NewCacheWriter(a, c)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(c.Path)
	if strings.Contains(string(raw), "60 days") || !strings.Contains(string(raw), `"sealed": "enc:v1:`) {
		t.Errorf("cache.enc:\n%s", raw)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(c.Path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode())
		}
	}
	if id, prefix, err := CacheHeader(c.Path); id != "c_1" || prefix != testPrefix || err != nil {
		t.Errorf("header %q %q %v", id, prefix, err)
	}
	d, err := c.Read(e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A new item starts above every revision applied here.
	if len(d.Docs) != 2 || d.Floors["retention"] != 2 || d.Floors["user:jlee"] != 3 || d.MaxRev != 3 || d.IndexUUID == "" || d.AppliedSeq == 0 {
		t.Errorf("cache %+v", d)
	}

	// Another server's hub, with OpenSearch out of reach, runs from it.
	b := NewHub(Options{NodeName: "siem-a", Clock: e.clock})
	b.SetKeys(NewKeySet(e.key))
	b.Use(nil, testPrefix)
	db := NewDoc[testBody](b, "retention", "retention", 1)
	cb := NewCollection[testBody](b, "user", "users", 1)
	b.Restore(d)
	if v, ok := db.Get(); !ok || v.Name != "60 days" {
		t.Errorf("restored doc %+v %v", v, ok)
	}
	if v, _, ok := cb.Get("jlee"); !ok || v.Name != "J. Lee" {
		t.Errorf("restored item %+v %v", v, ok)
	}
	if b.MaxRev() != 3 || len(b.Problems()) != 0 {
		t.Errorf("max rev %d, problems %+v", b.MaxRev(), b.Problems())
	}
	// A cache whose documents were changed is not trusted either.
	d.Docs[0].Source = []byte(strings.Replace(string(d.Docs[0].Source), "60 days", "1 day", 1))
	b2 := NewHub(Options{NodeName: "siem-a", Clock: e.clock})
	b2.SetKeys(NewKeySet(e.key))
	b2.Use(nil, testPrefix)
	d2 := NewDoc[testBody](b2, "retention", "retention", 1)
	b2.Restore(d)
	if _, ok := d2.Get(); ok || len(b2.Tamper()) != 1 {
		t.Errorf("changed cache used: tamper %v", b2.Tamper())
	}

	// Too old.
	if _, err := c.Read(e.clock.Now().Add(CacheMaxAge + time.Hour)); !errors.Is(err, ErrCacheOld) {
		t.Errorf("old cache: %v", err)
	}
	// Another prefix.
	other := c
	other.Prefix = "other"
	if _, err := other.Read(e.clock.Now()); !errors.Is(err, ErrCacheOther) {
		t.Errorf("other prefix: %v", err)
	}
	// The header is sealed with the rest: a cache.enc relabelled as
	// another cluster's or prefix's does not open.
	other.Path = filepath.Join(state, "relabelled.enc")
	relabelled := strings.Replace(string(raw), `"prefix": "`+testPrefix+`"`, `"prefix": "other"`, 1)
	if relabelled == string(raw) {
		t.Fatalf("no prefix in:\n%s", raw)
	}
	if err := os.WriteFile(other.Path, []byte(relabelled), 0o600); err != nil {
		t.Fatal(err)
	}
	var oe *secrets.OpenError
	if _, err := other.Read(e.clock.Now()); !errors.As(err, &oe) {
		t.Errorf("relabelled: %v", err)
	}
	if err := c.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(e.clock.Now()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("removed: %v", err)
	}
}

func TestCacheResealedByRotateMaster(t *testing.T) {
	state := t.TempDir()
	master := secrets.NewKeyring(state)
	c := Cache{Path: CachePath(state), Master: master, Prefix: testPrefix}
	if err := c.Write(CacheData{WrittenAt: time.Now(), Floors: map[string]int64{"feeds": 3}}); err != nil {
		t.Fatal(err)
	}
	oldID := master.KeyID()
	r, err := master.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(c.Path)
	next, n, err := ResealCacheFile(data, func(s secrets.Stored) (string, error) {
		if s.Field != cacheField("", testPrefix) || !strings.Contains(s.Label, "shared settings") {
			t.Errorf("stored %+v", s)
		}
		plain, err := master.Open(s.Field, s.Value)
		if err != nil {
			return "", err
		}
		return r.Seal(s.Field, plain)
	})
	if err != nil || n != 1 {
		t.Fatalf("reseal: %d %v", n, err)
	}
	if err := os.WriteFile(c.Path, next, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Done()
	newID := secrets.NewKeyring(state).KeyID()
	if newID == oldID || !strings.Contains(string(next), "enc:v1:"+newID+":") {
		t.Errorf("not resealed with %s:\n%s", newID, next)
	}
	// Without the previous key, it opens with the new one.
	if err := os.Remove(filepath.Join(state, "keys", filepath.Base(secrets.NewKeyring(state).DefaultPath())+".old")); err != nil {
		t.Fatal(err)
	}
	c.Master = secrets.NewKeyring(state)
	if d, err := c.Read(time.Now()); err != nil || d.Floors["feeds"] != 3 {
		t.Errorf("read after rotation: %+v %v", d, err)
	}
}

func TestCacheWriterWritesAfterChanges(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	a, _ := e.hub("siem-a")
	da := NewDoc[testBody](a, "retention", "retention", 1)
	state := t.TempDir()
	c := Cache{Path: CachePath(state), Master: secrets.NewKeyring(state), Prefix: testPrefix}
	w := NewCacheWriter(a, c)
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "first"; return nil }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		d, err := c.Read(e.clock.Now())
		return err == nil && len(d.Docs) == 1
	})
	// The next change waits for CacheEvery, then is written. On Windows a
	// read can meet the writer replacing the file, so a failed read counts
	// as "not written yet" (-1) and the wait tries again.
	floor := func() int64 {
		d, err := c.Read(e.clock.Now())
		if err != nil {
			return -1
		}
		return d.Floors["retention"]
	}
	// The writer waits for CacheEvery after the write. Each pass of its
	// loop also leaves a CacheRefresh timer on the fake clock, which never
	// fires here, so the CacheEvery wait is the second timer: advancing
	// the clock before the writer set it would leave it waiting for good.
	waitFor(t, func() bool { return e.clock.Waiting() == 2 })
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "second"; return nil }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := floor(); n != 1 {
		t.Fatalf("written before CacheEvery: floor %d", n)
	}
	e.clock.Advance(DefaultTiming.CacheEvery)
	waitFor(t, func() bool { return floor() == 2 })
	// One left at the end is written as the writer stops.
	// Two CacheRefresh timers and the next CacheEvery wait.
	waitFor(t, func() bool { return e.clock.Waiting() == 3 })
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "third"; return nil }); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if n := floor(); n != 3 {
		t.Errorf("after stop: floor %d", n)
	}
}

// A write that fails is tried again after CacheEvery, not dropped until
// the next change.
func TestCacheWriterRetriesAFailedWrite(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _ := e.hub("siem-a")
	da := NewDoc[testBody](a, "retention", "retention", 1)
	state := t.TempDir()
	// A file where the cache's folder goes makes the write fail.
	blocker := filepath.Join(state, "shared")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c := Cache{Path: filepath.Join(blocker, "cache.enc"), Master: secrets.NewKeyring(state), Prefix: testPrefix}
	w := NewCacheWriter(a, c)
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "first"; return nil }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w.Err() != nil })
	// The CacheRefresh timer and the CacheEvery wait after the failure.
	waitFor(t, func() bool { return e.clock.Waiting() == 2 })
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(DefaultTiming.CacheEvery)
	waitFor(t, func() bool {
		d, err := c.Read(e.clock.Now())
		return err == nil && len(d.Docs) == 1
	})
	cancel()
	<-done
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A cache the shared settings do not change is written again every
// CacheRefresh while the hub reads OpenSearch, so it never gets too old
// to use.
func TestCacheWriterRefreshes(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	a, _ := e.hub("siem-a")
	da := NewDoc[testBody](a, "retention", "retention", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "first"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	state := t.TempDir()
	c := Cache{Path: CachePath(state), Master: secrets.NewKeyring(state), Prefix: testPrefix}
	w := NewCacheWriter(a, c)
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	w.Changed()
	usable := func() bool { _, err := c.Read(e.clock.Now()); return err == nil }
	waitFor(t, usable)
	for range (CacheMaxAge + 10*24*time.Hour) / time.Hour {
		cycle(t, a)
		e.clock.Advance(time.Hour)
		time.Sleep(time.Millisecond)
	}
	waitFor(t, usable)
	cancel()
	<-done
}
