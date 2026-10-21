// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package keytrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// useRoot makes a root key the only one this build trusts.
func useRoot(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := newKey(t)
	old, oldRevoked := Roots, Revoked
	Roots, Revoked = []ed25519.PublicKey{pub}, nil
	t.Cleanup(func() { Roots, Revoked = old, oldRevoked })
	return pub, priv
}

func signedList(t *testing.T, priv ed25519.PrivateKey, issued time.Time, ids ...string) ([]byte, []byte) {
	t.Helper()
	l := List{Format: Format, Issued: issued}
	for _, id := range ids {
		l.Revoked = append(l.Revoked, RevokedKey{ID: id, Note: "test"})
	}
	data, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return data, Sign(priv, data)
}

func TestBuiltinFilesParse(t *testing.T) {
	if _, err := ParseKeys(rootKeys); err != nil {
		t.Fatal(err)
	}
	mustIDs(revokedKeys)
}

func TestVerify(t *testing.T) {
	_, rootPriv := useRoot(t)
	_, other := newKey(t)
	online, _ := newKey(t)
	now := time.Now()
	data, sig := signedList(t, rootPriv, now, KeyID(online))
	if l, err := Verify(Roots, data, sig); err != nil || len(l.Revoked) != 1 || l.Revoked[0].ID != KeyID(online) {
		t.Fatalf("good list: %+v %v", l, err)
	}
	if _, err := Verify(nil, data, sig); err != ErrNoRoot {
		t.Errorf("no root: %v", err)
	}
	for name, tc := range map[string]struct {
		data, sig []byte
		want      string
	}{
		"signed by another key": {data: data, sig: Sign(other, data), want: "does not match"},
		"changed":               {data: bytes.Replace(data, []byte(KeyID(online)), []byte("000000000000"), 1), sig: sig, want: "does not match"},
		"not a signature":       {data: data, sig: []byte("x"), want: "not a Signalith signature"},
		"too large":             {data: make([]byte, MaxList+1), sig: sig, want: "larger"},
	} {
		if _, err := Verify(Roots, tc.data, tc.sig); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	for name, l := range map[string]string{
		"format":    `{"format":2,"issued":"2026-10-20T00:00:00Z"}`,
		"no issued": `{"format":1}`,
		"bad ID":    `{"format":1,"issued":"2026-10-20T00:00:00Z","revoked":[{"id":"../../etc"}]}`,
	} {
		if _, err := Verify(Roots, []byte(l), Sign(rootPriv, []byte(l))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStoreKeepsNewestList(t *testing.T) {
	_, rootPriv := useRoot(t)
	a, _ := newKey(t)
	b, _ := newKey(t)
	s := &Store{Dir: filepath.Join(t.TempDir(), "keytrust")}
	if l, _, _, err := s.Load(); l != nil || err != nil {
		t.Fatalf("empty store: %+v %v", l, err)
	}
	now := time.Now().UTC()
	d1, s1 := signedList(t, rootPriv, now, KeyID(a))
	if kept, err := s.Offer(d1, s1); !kept || err != nil {
		t.Fatalf("first list: %v %v", kept, err)
	}
	// The same list again, or an older one, changes nothing: a server
	// cannot take a revocation back by handing out an old list.
	d0, s0 := signedList(t, rootPriv, now.Add(-time.Hour))
	for _, l := range [][2][]byte{{d1, s1}, {d0, s0}} {
		if kept, err := s.Offer(l[0], l[1]); kept || err != nil {
			t.Fatalf("not newer: %v %v", kept, err)
		}
	}
	if l, _, _, _ := s.Load(); !RevokedIDs(l)[KeyID(a)] {
		t.Fatal("the revocation was lost")
	}
	d2, s2 := signedList(t, rootPriv, now.Add(time.Hour), KeyID(a), KeyID(b))
	if kept, err := s.Offer(d2, s2); !kept || err != nil {
		t.Fatalf("newer list: %v %v", kept, err)
	}
	l, data, sig, err := s.Load()
	if err != nil || !bytes.Equal(data, d2) || !bytes.Equal(sig, s2) || len(RevokedIDs(l)) != 2 {
		t.Fatalf("load = %+v %v", l, err)
	}
	// A bad list is refused and the kept one stays.
	if _, err := s.Offer(d2, s1); err == nil {
		t.Fatal("bad signature accepted")
	}
	// A kept list changed on disk is not used.
	if err := os.WriteFile(filepath.Join(s.Dir, keptFile), slices.Concat(s2, d1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := (&Store{Dir: s.Dir}).Load(); err == nil {
		t.Fatal("changed kept list used")
	}
}

// A kept list that cannot be read is an error, never no list, unless this
// Store has read a good one before, which it keeps using.
func TestKeptListUnreadableFailsClosed(t *testing.T) {
	_, rootPriv := useRoot(t)
	a, _ := newKey(t)
	dir := filepath.Join(t.TempDir(), "keytrust")
	s := &Store{Dir: dir}
	d1, s1 := signedList(t, rootPriv, time.Now().UTC(), KeyID(a))
	if kept, err := s.Offer(d1, s1); !kept || err != nil {
		t.Fatalf("offer: %v %v", kept, err)
	}
	path := filepath.Join(dir, keptFile)
	for name, b := range map[string][]byte{
		"truncated":   slices.Concat(s1, d1)[:len(s1)+10],
		"no newline":  []byte("garbage"),
		"empty":       nil,
		"other's sig": slices.Concat(Sign(rootPriv, []byte("x")), d1),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if l, _, _, err := (&Store{Dir: dir}).Load(); err == nil || l != nil || !strings.Contains(err.Error(), "belong to the user") {
			t.Errorf("%s, new store: %+v %v, want an error", name, l, err)
		}
		if l, _, _, err := s.Load(); err != nil || !RevokedIDs(l)[KeyID(a)] {
			t.Errorf("%s, store that read it: %+v %v, want the list read before", name, l, err)
		}
	}
	// A list no newer than the one read before does not replace the bad
	// file; a newer one does.
	d0, s0 := signedList(t, rootPriv, time.Now().Add(-time.Hour))
	if kept, err := s.Offer(d0, s0); kept || err != nil {
		t.Fatalf("older list: %v %v", kept, err)
	}
	// With nothing read before, any good list replaces a bad file.
	if kept, err := (&Store{Dir: dir}).Offer(d0, s0); !kept || err != nil {
		t.Fatalf("new store, older list: %v %v", kept, err)
	}
	// The store that saw the newer list keeps it, whatever the file says.
	if l, _, _, err := s.Load(); err != nil || !RevokedIDs(l)[KeyID(a)] {
		t.Fatalf("after an older list was written: %+v %v", l, err)
	}
	// A build with no root key takes no list, so a bad file does not stop
	// it.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	Roots = nil
	if l, _, _, err := (&Store{Dir: dir}).Load(); l != nil || err != nil {
		t.Errorf("no root key: %+v %v", l, err)
	}
	Roots = []ed25519.PublicKey{rootPriv.Public().(ed25519.PublicKey)}
	// A file that cannot be opened is an error too.
	if os.Geteuid() != 0 {
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := (&Store{Dir: dir}).Load(); err == nil {
			t.Error("unreadable file: no error")
		}
	}
}

func TestTrusted(t *testing.T) {
	root, _ := useRoot(t)
	online, _ := newKey(t)
	other, _ := newKey(t)
	// A list (or the built-in revoked.keys) cannot revoke a root key.
	Revoked = []string{KeyID(other), KeyID(root)}
	l := &List{Format: Format, Issued: time.Now(), Revoked: []RevokedKey{{ID: KeyID(online)}, {ID: KeyID(root)}}}
	ids := RevokedIDs(l)
	if ids[KeyID(root)] || !ids[KeyID(online)] || !ids[KeyID(other)] {
		t.Fatalf("revoked = %v", ids)
	}
	got := Trusted([]ed25519.PublicKey{online, other, root}, ids)
	if len(got) != 1 || !got[0].Equal(root) {
		t.Fatalf("trusted = %d keys, want only the root", len(got))
	}
	if got := Trusted([]ed25519.PublicKey{online}, RevokedIDs()); len(got) != 2 {
		t.Fatalf("trusted with no list = %d keys, want the online key and the root", len(got))
	}
}

// A keytrust folder that is a link is not written through: whoever owns
// the folder above could point it anywhere.
func TestStoreDoesNotFollowLinkedFolder(t *testing.T) {
	_, rootPriv := useRoot(t)
	state, target := t.TempDir(), t.TempDir()
	dir := filepath.Join(state, "keytrust")
	if err := os.Symlink(target, dir); err != nil {
		t.Skip("cannot make a link:", err)
	}
	data, sig := signedList(t, rootPriv, time.Now())
	if kept, err := (&Store{Dir: dir}).Offer(data, sig); kept || err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("offer through a link: %v %v", kept, err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("written through the link: %v", entries)
	}
}

// A list kept from a root key a later build dropped no longer checks, so
// the server refuses updates until a list signed with a current root key
// replaces it.
func TestListFromRemovedRootIsReplaced(t *testing.T) {
	_, oldPriv := useRoot(t)
	a, _ := newKey(t)
	dir := filepath.Join(t.TempDir(), "keytrust")
	now := time.Now().UTC()
	d1, s1 := signedList(t, oldPriv, now, KeyID(a))
	if kept, err := (&Store{Dir: dir}).Offer(d1, s1); !kept || err != nil {
		t.Fatalf("offer: %v %v", kept, err)
	}
	newPub, newPriv := newKey(t)
	Roots = []ed25519.PublicKey{newPub}
	s := &Store{Dir: dir}
	if _, _, _, err := s.Load(); err == nil {
		t.Fatal("a list signed with a dropped root key was used")
	}
	// The same list signed again with the new root key, even with the
	// same issue time, is taken.
	if kept, err := s.Offer(d1, Sign(newPriv, d1)); !kept || err != nil {
		t.Fatalf("re-signed list: %v %v", kept, err)
	}
	if l, _, _, err := (&Store{Dir: dir}).Load(); err != nil || !RevokedIDs(l)[KeyID(a)] {
		t.Fatalf("after: %+v %v", l, err)
	}
}
