// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeBackend is a cluster's shared copy of the lists.
type fakeBackend struct {
	puts []string
	err  error
}

func (f *fakeBackend) ETag(kind string) string { return "etag-" + kind }

func (f *fakeBackend) Put(_ context.Context, by, kind string, data []byte, etag string) error {
	f.puts = append(f.puts, by+" "+kind+" "+etag)
	return f.err
}

func TestSharedLists(t *testing.T) {
	ctx := context.Background()
	s, _ := NewStore(t.TempDir())
	if s.Shared() || s.ETag(KindAssets) != "" {
		t.Error("a store on its own is shared")
	}
	if _, err := s.SetIf(ctx, "admin", "groups", nil, ""); err == nil || !strings.Contains(err.Error(), `unknown list "groups"`) {
		t.Errorf("unknown kind = %v", err)
	}
	if _, err := s.SetIf(ctx, "admin", KindAssets, []byte("host,priority\nx,urgent\n"), ""); err == nil {
		t.Error("a bad list was taken")
	}

	// Kept in Dir, under the hold.
	held, released := 0, 0
	s.Hold = func() (func(), error) { held++; return func() { released++ }, nil }
	if n, err := s.SetIf(ctx, "admin", KindAssets, []byte(assetCSV), ""); err != nil || n != 4 || held != 1 || released != 1 {
		t.Errorf("held set = %d %v (held %d released %d)", n, err, held, released)
	}
	s.Hold = func() (func(), error) { return nil, errors.New("the lists are moving") }
	if _, err := s.SetIf(ctx, "admin", KindIdentities, []byte(identityCSV), ""); err == nil || !strings.Contains(err.Error(), "moving") {
		t.Errorf("refused hold = %v", err)
	}
	s.Hold = nil

	// Kept in the cluster's settings, with a copy in Dir.
	b := &fakeBackend{}
	s.UseBackend(b)
	if !s.Shared() || s.ETag(KindIdentities) != "etag-identities" {
		t.Error("the backend is not used")
	}
	if n, err := s.SetIf(ctx, "admin", KindIdentities, []byte(identityCSV), "v1"); err != nil || n != 2 || len(s.Identities()) != 2 {
		t.Errorf("shared set = %d %v", n, err)
	}
	if len(b.puts) != 1 || b.puts[0] != "admin identities v1" {
		t.Errorf("puts = %v", b.puts)
	}
	b.err = errors.New("changed by kim")
	if _, err := s.SetIf(ctx, "admin", KindAssets, []byte(assetCSV), "old"); err == nil || !strings.Contains(err.Error(), "kim") {
		t.Errorf("refused put = %v", err)
	}

	// Another server's change, written back.
	if err := s.Write(KindAssets, []byte("host\nweb9\n")); err != nil || len(s.Assets()) != 1 {
		t.Errorf("write assets = %v %d", err, len(s.Assets()))
	}
	if err := s.Write(KindIdentities, []byte("identity\nzed\n")); err != nil || len(s.Identities()) != 1 {
		t.Errorf("write identities = %v %d", err, len(s.Identities()))
	}
	if err := s.Write("groups", nil); err == nil {
		t.Error("an unknown list was written")
	}
}

func TestAssetEdges(t *testing.T) {
	_, err := ParseAssets([]byte("cidr\n10.0.0.0/33\n"))
	if err == nil || !strings.Contains(err.Error(), "is not a network") {
		t.Errorf("bad cidr = %v", err)
	}
	_, err = ParseIdentities([]byte("identity,priority\nbob,urgent\n|,low\n"))
	if err == nil || !strings.Contains(err.Error(), "identity is empty") || !strings.Contains(err.Error(), "urgent") {
		t.Errorf("bad identities = %v", err)
	}
	if Multiplier("high") != 1.5 {
		t.Error("high multiplier")
	}

	var none *Store
	if none.Own() != nil {
		t.Error("nil Own")
	}
	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Reload(); changed || err != nil {
		t.Errorf("reload without a folder = %v %v", changed, err)
	}
	if _, ok := s.Asset(""); ok {
		t.Error("an empty asset was found")
	}
	if _, ok := s.Identity(" "); ok {
		t.Error("an empty identity was found")
	}
	if _, ok := s.Lookup("user", "nobody"); ok {
		t.Error("an unknown user was found")
	}
	if _, ok := s.Lookup("dest", "nowhere"); ok {
		t.Error("an unknown host was found")
	}

	// The folder is a file: nothing can be saved.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	blocked := &Store{Dir: file, own: newLookup(nil, nil), overlay: newLookup(nil, nil)}
	if _, err := blocked.SetAssets([]byte(assetCSV)); err == nil {
		t.Error("saved assets in a file")
	}
	if _, err := blocked.SetIdentities([]byte(identityCSV)); err == nil {
		t.Error("saved identities in a file")
	}
	if err := blocked.SetOverlay([]Asset{{Host: []string{"x"}}}, nil); err == nil {
		t.Error("saved the overlay in a file")
	}
	// Windows reports a path under a file as missing, which is no error.
	if err := blocked.SetOverlay(nil, nil); err == nil && runtime.GOOS != "windows" {
		t.Error("removed the overlay from a file")
	}
}
