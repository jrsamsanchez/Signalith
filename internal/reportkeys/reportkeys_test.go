// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package reportkeys

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileKeepsKeysAcrossRotationAndRevocation(t *testing.T) {
	ctx := context.Background()
	f := &File{Path: filepath.Join(t.TempDir(), FileName)}
	if ks, err := f.List(ctx); err != nil || len(ks) != 0 {
		t.Fatalf("empty: %v %v", ks, err)
	}
	a, _, _ := ed25519.GenerateKey(nil)
	b, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	for range 2 {
		if err := f.Use(ctx, a, FromMaster, now); err != nil {
			t.Fatal(err)
		}
	}
	ks, _ := f.List(ctx)
	if len(ks) != 1 || ks[0].Status() != Current || ks[0].ID != KeyID(a) || !ValidID(ks[0].ID) {
		t.Fatalf("one key: %+v", ks)
	}
	if pub, err := ks[0].PublicKey(); err != nil || !pub.Equal(a) {
		t.Errorf("public key: %v", err)
	}
	// A new master key: the old report key is retired, not forgotten.
	f.Use(ctx, b, FromMaster, now.Add(time.Hour))
	ks, _ = f.List(ctx)
	if len(ks) != 2 || ks[0].Status() != Retired || ks[1].Status() != Current {
		t.Fatalf("after rotation: %+v", ks)
	}
	if err := f.Revoke(ctx, ks[0].ID, "admin", "leaked backup", now); err != nil {
		t.Fatal(err)
	}
	ks, _ = f.List(ctx)
	if ks[0].Status() != Revoked || ks[0].RevokedBy != "admin" || ks[0].Reason != "leaked backup" {
		t.Errorf("revoked: %+v", ks[0])
	}
	if err := f.Revoke(ctx, "abcdefabcdef", "admin", "", now); err != ErrNotFound {
		t.Errorf("unknown key: %v", err)
	}
	if err := f.Revoke(ctx, ks[1].ID, "admin", strings.Repeat("x", MaxReason+1), now); err == nil {
		t.Error("an overlong reason was kept")
	}
}

func TestKeyRejectsAMismatchedID(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(nil)
	b, _, _ := ed25519.GenerateKey(nil)
	ks, _ := Apply(nil, a, FromCluster, time.Now())
	k := ks[0]
	k.ID = KeyID(b)
	if _, err := k.PublicKey(); err == nil {
		t.Error("a key filed under another key's ID was used")
	}
	if validate(&KeyBody{Key: k}) == nil {
		t.Error("the shared settings would take it")
	}
}
