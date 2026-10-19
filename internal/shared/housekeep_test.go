// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The level is not raised by a server that lost the job lease, nor when
// the cluster document cannot be written.
func TestRaiseLevelRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}
	old := Peer{NodeID: "n_siem-old", Name: "siem-old", Live: true}
	var peers peerList
	peers.set(self, old)
	a := e.server("siem-a", func(o *RuntimeOptions) { o.Peers = peers.get })
	a.holds.Store(true)
	a.step()
	wantLevel(t, e, 1)
	upgraded := old
	upgraded.LevelMax = LevelMax
	peers.set(self, upgraded)

	a.holds.Store(false)
	if a.rt.RaiseLevel(ctx) {
		t.Error("raised the level without the job lease")
	}
	a.holds.Store(true)
	failing(e, func(method, path string) bool {
		return method == http.MethodPut && strings.Contains(path, "/_doc/"+ClusterDocID)
	})
	if a.rt.RaiseLevel(ctx) {
		t.Error("raised the level although the cluster document could not be written")
	}
	mustContain(t, "log", a.logs.String(), "could not raise the level")
	e.os.SetFault(nil)
	wantLevel(t, e, 1)
	if !a.rt.RaiseLevel(ctx) {
		t.Error("the level was not raised")
	}
	wantLevel(t, e, 2)
}

// Housekeeping removes old tombstones and logs it; a server that is not a
// member does nothing.
func TestRuntimeHousekeep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	c := NewCollection[testBody](a.rt.Hub(), "rule", "rules", 1)
	if _, err := c.Create(ctx, "sam", "r1", &testBody{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := c.Get("r1")
	if _, err := c.Delete(ctx, "sam", "r1", etag); err != nil {
		t.Fatal(err)
	}
	e.clock.SetWall(e.clock.Now().Add(TombstoneAge + time.Hour))
	a.rt.Housekeep(ctx)
	mustContain(t, "log", a.logs.String(), "removed the records of items deleted more than 30 days ago")
	if e.os.Source(testIndex, c.ItemID("r1")) != nil {
		t.Error("the tombstone is still there")
	}
	// With OpenSearch refusing searches and deletes, it only logs.
	failing(e, func(method, path string) bool {
		return strings.Contains(path, "_search") || method == http.MethodDelete
	})
	a.rt.Housekeep(ctx)
	e.os.SetFault(nil)

	b := e.server("siem-b", nil)
	b.rt.Housekeep(ctx)
	if strings.Contains(b.logs.String(), "removed") {
		t.Error("a server outside the cluster housekeeps")
	}
}

// signalith cluster found uses the only key the state folder keeps, and
// needs a master key to keep one.
func TestFoundByHandWithAKeptKey(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	a.give(k)
	if err := a.rt.Found(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if a.key().ID() != k.ID() {
		t.Errorf("founded with %s, not the kept key %s", a.key().ID(), k.ID())
	}

	// A founding whose lease check fails keeps no key.
	e3 := newEnv(t)
	c := e3.server("siem-c", func(o *RuntimeOptions) {
		o.LeaseCheck = func(context.Context) error { return errors.New("the lease moved") }
	})
	c.holds.Store(true)
	if err := c.rt.found(context.Background(), "signalith", false); err == nil || err.Error() != "the lease moved" {
		t.Errorf("found = %v", err)
	}
	if files := ClusterKeyFiles(c.dir); len(files) != 0 || e3.os.Source(testIndex, ClusterDocID) != nil {
		t.Errorf("keys %v after a founding cut short by the lease", files)
	}

	e2 := newEnv(t)
	dir := t.TempDir()
	rt := NewRuntime(RuntimeOptions{StateDir: dir, Self: Self{NodeID: "n_x", Name: "siem-x"}, Clock: e2.clock})
	rt.Use(e2.c, testPrefix, nil)
	if err := rt.Found(context.Background(), "admin"); err == nil || !strings.Contains(err.Error(), "no master key") {
		t.Errorf("Found without a master key = %v", err)
	}
}

// An import whose source cannot be read cuts the founding short, naming
// it; it goes on once the source reads.
func TestFoundWithAnImportSourceThatFails(t *testing.T) {
	e := newEnv(t)
	var broken atomic.Bool
	broken.Store(true)
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.Importers = []Importer{{Name: "feeds", Source: func() (string, error) {
			if broken.Load() {
				return "", errors.New("feeds.json is damaged")
			}
			return "h", nil
		}}}
	})
	a.holds.Store(true)
	err := a.rt.found(context.Background(), "signalith", false)
	if err == nil || !strings.Contains(err.Error(), "could not read what to import for feeds: feeds.json is damaged") {
		t.Fatalf("found = %v", err)
	}
	broken.Store(false)
	a.step()
	a.wantMode(ModeMember)
	if _, body := clusterBody(t, e); body.Import.Done["feeds"] != "h" {
		t.Errorf("imports done %v", body.Import.Done)
	}
}

// failSealer is a master key that cannot seal.
type failSealer struct{}

func (failSealer) Seal(string, string) (string, error) {
	return "", errors.New("the master key is locked")
}
func (failSealer) Open(string, string) (string, error) {
	return "", errors.New("the master key is locked")
}

// A master key that cannot seal keeps no node or cluster key.
func TestKeyStoreWithALockedMasterKey(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir, Master: failSealer{}}
	if _, err := ks.NodeKey(); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("NodeKey = %v", err)
	}
	k, _ := NewClusterKey()
	if err := ks.SaveClusterKey(k); err == nil {
		t.Error("a cluster key was kept with a master key that cannot seal")
	}
	if len(ClusterKeyFiles(dir)) != 0 {
		t.Error("a key file was written")
	}
}
