// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"errors"
	"testing"
)

// TestMAC checks that a MAC matches only its record, its field and its
// key, that the keyring checks MACs of the previous key after a rotation,
// and that MAC never makes a master key.
func TestMAC(t *testing.T) {
	dir := t.TempDir()
	k := keyring(dir, nil)
	if _, err := k.MAC("f", []byte("x")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("MAC without a master key: %v", err)
	}
	if _, err := k.Seal("f", "make a key"); err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"id":"a","encryption":"aes"}`)
	tag, err := k.MAC("retention.archive_manifest", msg)
	if err != nil {
		t.Fatal(err)
	}
	if MACKeyID(tag) != k.KeyID() {
		t.Errorf("MAC %q does not name key %s", tag, k.KeyID())
	}
	if err := k.CheckMAC("retention.archive_manifest", msg, tag); err != nil {
		t.Errorf("CheckMAC: %v", err)
	}
	changed := bytes.Replace(msg, []byte("aes"), []byte(""), 1)
	if err := k.CheckMAC("retention.archive_manifest", changed, tag); !errors.Is(err, ErrMACMismatch) {
		t.Errorf("a changed record: %v", err)
	}
	if err := k.CheckMAC("other.field", msg, tag); !errors.Is(err, ErrMACMismatch) {
		t.Errorf("another field: %v", err)
	}

	raw := bytes.Repeat([]byte{7}, 32)
	ck, err := NewKey(raw, "cluster key")
	if err != nil {
		t.Fatal(err)
	}
	if err := ck.CheckMAC("retention.archive_manifest", msg, tag); !errors.Is(err, ErrMACKey) {
		t.Errorf("the cluster key checking the master key's MAC: %v", err)
	}
	ctag := ck.MAC("retention.archive_manifest", msg)
	if err := ck.CheckMAC("retention.archive_manifest", msg, ctag); err != nil {
		t.Errorf("cluster key CheckMAC: %v", err)
	}
	if err := k.CheckMAC("retention.archive_manifest", msg, ctag); !errors.Is(err, ErrMACKey) {
		t.Errorf("the master key checking the cluster key's MAC: %v", err)
	}
	// The MAC key is derived from the key, not the key itself.
	if bytes.Equal(ck.m.mac, raw) {
		t.Error("the MAC key is the raw key")
	}

	// After a rotation the previous key's MACs still check.
	r, err := k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Done()
	if err := k.CheckMAC("retention.archive_manifest", msg, tag); err != nil {
		t.Errorf("CheckMAC with the previous key: %v", err)
	}
	if err := k.CheckMAC("retention.archive_manifest", msg, "mac:v1:zzzz"); !errors.Is(err, ErrMACKey) {
		t.Errorf("a damaged MAC: %v", err)
	}
}
