// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package reportkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

type cluster struct {
	t   *testing.T
	cl  *store.Client
	key *shared.ClusterKey
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	if err := shared.EnsureConfig(context.Background(), cl, prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	return &cluster{t: t, cl: cl, key: key}
}

func (c *cluster) server(name string, writable func() error) (*Shared, *shared.Hub) {
	c.t.Helper()
	h := shared.NewHub(shared.Options{NodeName: name})
	h.SetKeys(shared.NewKeySet(c.key))
	h.Use(c.cl, prefix)
	s := NewShared(writable)
	s.Track(h)
	s.Reset()
	if err := h.Cycle(context.Background()); err != nil {
		c.t.Fatal(err)
	}
	return s, h
}

func newKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestSharedNotOpen(t *testing.T) {
	ctx := context.Background()
	s := NewShared(nil)
	if _, err := s.List(ctx); !errors.Is(err, errClosed) {
		t.Errorf("List: %v", err)
	}
	if err := s.Use(ctx, newKey(t), FromCluster, time.Now()); !errors.Is(err, errClosed) {
		t.Errorf("Use: %v", err)
	}
	if err := s.Revoke(ctx, "abcdefabcdef", "ann", "", time.Now()); !errors.Is(err, errClosed) {
		t.Errorf("Revoke: %v", err)
	}
	if err := Importer(s, func() string { return filepath.Join(t.TempDir(), FileName) }).Run(ctx, "ann"); !errors.Is(err, errClosed) {
		t.Errorf("import: %v", err)
	}
}

// TestSharedRotationAcrossServers: a key used on one server is listed on
// another, a newer key retires it there too, and a revocation made on
// either server holds.
func TestSharedRotationAcrossServers(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	a, _ := c.server("siem-a", nil)
	b, hb := c.server("siem-b", nil)
	k1, k2 := newKey(t), newKey(t)
	now := time.Now()

	if err := a.Use(ctx, k1, FromCluster, now); err != nil {
		t.Fatal(err)
	}
	// Using the same key again changes nothing.
	if err := a.Use(ctx, k1, FromCluster, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := hb.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	ks, err := b.List(ctx)
	if err != nil || len(ks) != 1 || ks[0].ID != KeyID(k1) || ks[0].Status() != Current {
		t.Fatalf("siem-b lists %+v %v", ks, err)
	}
	if err := b.Use(ctx, k2, FromCluster, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ks, _ = b.List(ctx)
	if len(ks) != 2 || ks[0].ID != KeyID(k1) || ks[0].Status() != Retired || ks[1].Status() != Current {
		t.Fatalf("after rotation: %+v", ks)
	}
	if err := b.Revoke(ctx, KeyID(k1), "ann", "leaked", now); err != nil {
		t.Fatal(err)
	}
	ks, _ = b.List(ctx)
	if ks[0].Status() != Revoked || ks[0].RevokedBy != "ann" || ks[0].Reason != "leaked" {
		t.Errorf("revoked: %+v", ks[0])
	}
	if err := b.Revoke(ctx, "abcdefabcdef", "ann", "", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown key: %v", err)
	}
	if err := b.Revoke(ctx, KeyID(k2), "ann", "bad\x01", now); err == nil {
		t.Error("a reason with control characters was kept")
	}
	got := Lookup(ks)
	if k, ok := got(KeyID(k1)); !ok || k.Status() != Revoked {
		t.Errorf("Lookup: %+v %v", k, ok)
	}
	if _, ok := got("000000000000"); ok {
		t.Error("Lookup found a key the list does not have")
	}
}

func TestSharedReadOnly(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	ro := errors.New("read only")
	s, _ := c.server("siem-a", func() error { return ro })
	if err := s.Use(ctx, newKey(t), FromCluster, time.Now()); !errors.Is(err, ro) {
		t.Errorf("Use: %v", err)
	}
	if err := s.Revoke(ctx, "abcdefabcdef", "ann", "", time.Now()); !errors.Is(err, ro) {
		t.Errorf("Revoke: %v", err)
	}
	if ks, _ := s.List(ctx); len(ks) != 0 {
		t.Errorf("a read-only server wrote %+v", ks)
	}
}

// TestSharedSaveMergesConcurrentChanges: a server whose copy is older than
// the cluster's still adds what it changed without losing the other's.
func TestSharedSaveMergesConcurrentChanges(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	a, _ := c.server("siem-a", nil)
	k1, k2 := newKey(t), newKey(t)
	now := time.Now()
	if err := a.Use(ctx, k1, FromCluster, now); err != nil {
		t.Fatal(err)
	}
	coll, err := a.coll()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := a.List(ctx)
	// k1 added again (as if by another server) is kept, and k1's
	// retirement is written onto the stored copy.
	next, _ := Apply(before, k2, FromCluster, now.Add(time.Hour))
	if err := a.save(ctx, coll, nil, before); err != nil {
		t.Fatalf("re-adding a stored key: %v", err)
	}
	if err := a.save(ctx, coll, before, next); err != nil {
		t.Fatal(err)
	}
	revoked, err := RevokeIn(next, KeyID(k1), "ann", "x", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.save(ctx, coll, next, revoked); err != nil {
		t.Fatal(err)
	}
	ks, _ := a.List(ctx)
	if len(ks) != 2 || ks[0].Status() != Revoked || ks[0].Retired == nil || ks[1].Status() != Current {
		t.Errorf("after merge: %+v", ks)
	}
	if !sameKey(ks[1], ks[1]) || sameKey(ks[0], ks[1]) {
		t.Error("sameKey")
	}
}

func TestValidate(t *testing.T) {
	pub := newKey(t)
	good := Key{ID: KeyID(pub), Public: base64.StdEncoding.EncodeToString(pub), Source: FromMaster}
	tests := []struct {
		name string
		edit func(k *Key)
		ok   bool
	}{
		{"good", func(*Key) {}, true},
		{"bad id", func(k *Key) { k.ID = "XYZ" }, false},
		{"bad source", func(k *Key) { k.Source = "elsewhere" }, false},
		{"not base64", func(k *Key) { k.Public = "!!" }, false},
		{"short key", func(k *Key) { k.Public = base64.StdEncoding.EncodeToString([]byte("short")) }, false},
		{"bad reason", func(k *Key) { k.Reason = strings.Repeat("x", MaxReason+1) }, false},
	}
	for _, tc := range tests {
		k := good
		tc.edit(&k)
		if err := validate(&KeyBody{Key: k}); (err == nil) != tc.ok {
			t.Errorf("%s: validate = %v", tc.name, err)
		}
	}
	if err := validateItem(good.ID, &KeyBody{Key: good}); err != nil {
		t.Errorf("validateItem: %v", err)
	}
	if err := validateItem("000000000000", &KeyBody{Key: good}); err == nil {
		t.Error("validateItem took a key under another ID")
	}
}

func TestImporterAndExporter(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	s, _ := c.server("siem-a", nil)
	dir := t.TempDir()
	own := filepath.Join(dir, FileName)
	f := &File{Path: own}
	k1, k2 := newKey(t), newKey(t)
	now := time.Now()
	imp := Importer(s, func() string { return own })

	// No file yet: nothing to import.
	if src, err := imp.Source(); err != nil || src != "" {
		t.Errorf("source without a file: %q %v", src, err)
	}
	if err := f.Use(ctx, k1, FromMaster, now); err != nil {
		t.Fatal(err)
	}
	if err := f.Use(ctx, k2, FromMaster, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A key that does not validate is skipped, not imported.
	ks, _ := Read(own)
	ks = append(ks, Key{ID: "badbadbadbad", Public: "x", Source: FromMaster, FirstUsed: now})
	if err := write(own, ks); err != nil {
		t.Fatal(err)
	}
	src, err := imp.Source()
	if err != nil || src != "keys:3:badbadbadbad" {
		t.Errorf("source: %q %v", src, err)
	}
	if imp.Name != ImportName {
		t.Errorf("importer name %q", imp.Name)
	}
	for range 2 { // a second run finds the keys there
		if err := imp.Run(ctx, "ann"); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.List(ctx)
	if len(got) != 2 {
		t.Fatalf("imported %+v", got)
	}
	for _, k := range got {
		if k.Status() != Retired {
			t.Errorf("imported key %s is %s, want retired", k.ID, k.Status())
		}
	}

	// A file that is not JSON fails the import.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	badImp := Importer(s, func() string { return bad })
	if _, err := badImp.Source(); err == nil {
		t.Error("source of a bad file")
	}
	if err := badImp.Run(ctx, "ann"); err == nil {
		t.Error("import of a bad file")
	}

	out := t.TempDir()
	target := shared.ExportTarget{Under: func(p string) string { return filepath.Join(out, "x", filepath.Base(p)) }}
	exp := Exporter(s, func() string { return own })
	files, err := exp.Run(ctx, target)
	if err != nil || len(files) != 1 || files[0].Dest != own {
		t.Fatalf("export: %+v %v", files, err)
	}
	back, err := Read(files[0].Path)
	if err != nil || len(back) != 2 {
		t.Errorf("exported %+v %v", back, err)
	}
	if files, err := Exporter(s, func() string { return "" }).Run(ctx, target); err != nil || files != nil {
		t.Errorf("export with no path: %v %v", files, err)
	}
	if files, err := Exporter(NewShared(nil), func() string { return own }).Run(ctx, target); !errors.Is(err, errClosed) || files != nil {
		t.Errorf("export when closed: %v %v", files, err)
	}
}

func TestSwitch(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	s, _ := c.server("siem-a", nil)
	f := &File{Path: filepath.Join(t.TempDir(), FileName)}
	clustered := false
	sw := &Switch{Clustered: func() bool { return clustered }, Shared: s, File: f}
	k1, k2 := newKey(t), newKey(t)
	now := time.Now()

	if err := sw.Use(ctx, k1, FromMaster, now); err != nil {
		t.Fatal(err)
	}
	if ks, _ := f.List(ctx); len(ks) != 1 {
		t.Errorf("on its own the file has %+v", ks)
	}
	clustered = true
	if err := sw.Use(ctx, k2, FromCluster, now); err != nil {
		t.Fatal(err)
	}
	if ks, _ := sw.List(ctx); len(ks) != 1 || ks[0].ID != KeyID(k2) {
		t.Errorf("clustered lists %+v", ks)
	}
	if err := sw.Revoke(ctx, KeyID(k2), "ann", "", now); err != nil {
		t.Fatal(err)
	}
	clustered = false
	if ks, _ := sw.List(ctx); len(ks) != 1 || ks[0].ID != KeyID(k1) || ks[0].Status() != Current {
		t.Errorf("on its own lists %+v", ks)
	}
	// No shared list: always the file.
	only := &Switch{Clustered: func() bool { return true }, File: f}
	if ks, _ := only.List(ctx); len(ks) != 1 {
		t.Errorf("without shared: %+v", ks)
	}
}

func TestMemory(t *testing.T) {
	ctx := context.Background()
	m := &Memory{}
	k1, k2 := newKey(t), newKey(t)
	now := time.Now()
	if err := m.Use(ctx, k1, FromMaster, now); err != nil {
		t.Fatal(err)
	}
	if err := m.Use(ctx, k2, FromMaster, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(ctx, KeyID(k1), "ann", "r", now); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(ctx, "abcdefabcdef", "ann", "", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	ks, _ := m.List(ctx)
	if len(ks) != 2 || ks[0].Status() != Revoked || ks[1].Status() != Current {
		t.Errorf("memory %+v", ks)
	}
}

func TestFileErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &File{Path: path}
	if _, err := f.List(ctx); err == nil {
		t.Error("List of a bad file")
	}
	if err := f.Use(ctx, newKey(t), FromMaster, time.Now()); err == nil {
		t.Error("Use on a bad file")
	}
	if err := f.Revoke(ctx, "abcdefabcdef", "ann", "", time.Now()); err == nil {
		t.Error("Revoke on a bad file")
	}
	// A folder where the file should be cannot be read.
	if _, err := Read(dir); err == nil {
		t.Error("Read of a folder")
	}
	// A folder that does not exist cannot be locked.
	missing := &File{Path: filepath.Join(dir, "missing", FileName)}
	if err := missing.Use(ctx, newKey(t), FromMaster, time.Now()); err == nil {
		t.Error("Use in a missing folder")
	}
	if err := missing.Revoke(ctx, "abcdefabcdef", "ann", "", time.Now()); err == nil {
		t.Error("Revoke in a missing folder")
	}
}
