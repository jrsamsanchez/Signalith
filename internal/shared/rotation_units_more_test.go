// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestKeyringRotationField(t *testing.T) {
	kr := &KeyringBody{}
	if n, err := kr.Rotation(); n != nil || err != nil {
		t.Errorf("no rotation = %v %v", n, err)
	}
	kr.Next = json.RawMessage(`{"kid": ""}`)
	if n, err := kr.Rotation(); n != nil || err != nil {
		t.Errorf("a rotation without a key = %v %v", n, err)
	}
	kr.Next = json.RawMessage(`[`)
	if _, err := kr.Rotation(); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("a damaged rotation = %v", err)
	}
	if err := kr.setRotation(&RotationNext{KID: "k2", From: "k1"}); err != nil {
		t.Fatal(err)
	}
	if n, err := kr.Rotation(); err != nil || n.KID != "k2" || n.From != "k1" {
		t.Errorf("a rotation set = %+v %v", n, err)
	}
	if err := kr.setRotation(nil); err != nil || kr.Next != nil {
		t.Errorf("ending a rotation = %s %v", kr.Next, err)
	}

	now := time.Now()
	for _, c := range []struct {
		until string
		live  bool
	}{
		{now.Add(time.Hour).Format(time.RFC3339Nano), true},
		{now.Add(-time.Hour).Format(time.RFC3339Nano), false},
		{"not a time", false},
	} {
		kr.CatchUp = &CatchUp{KID: "k2", Until: c.until}
		if got := kr.catchUpLive(now); (got != nil) != c.live {
			t.Errorf("catch-up until %q live = %v", c.until, got != nil)
		}
	}
	kr.CatchUp = nil
	if kr.catchUpLive(now) != nil {
		t.Error("no catch-up is live")
	}
}

// A copy of a new key opens only for its server, with the proof of the
// old key, and holds the key it says.
func TestKeyCopies(t *testing.T) {
	old, _ := NewClusterKey()
	next, _ := NewClusterKey()
	nk, _ := NewNodeKey()
	m := KeyringMember{Name: "siem-b", NodePub: nk.PublicText()}
	cp, err := sealCopy(next, old, "n_b", m)
	if err != nil {
		t.Fatal(err)
	}
	k, err := openCopy(nk, "n_b", next.ID(), cp, old)
	if err != nil || k.ID() != next.ID() {
		t.Fatalf("openCopy = %v %v", k, err)
	}
	if _, err := openCopy(nk, "n_b", next.ID(), cp, nil); err != nil {
		t.Errorf("openCopy without a proof check = %v", err)
	}
	other, _ := NewClusterKey()
	if _, err := openCopy(nk, "n_b", next.ID(), cp, other); err == nil || !strings.Contains(err.Error(), "proof") {
		t.Errorf("a copy proved with another key = %v", err)
	}
	if _, err := openCopy(nk, "n_b", other.ID(), cp, nil); err == nil {
		t.Error("a copy opened for another key id")
	}
	// A copy sealed for another key id than it holds.
	sealed, err := SealToNode(nk.Public(), "n_b", other.ID(), next.raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openCopy(nk, "n_b", other.ID(), KeyCopy{Sealed: sealed}, nil); err == nil || !strings.Contains(err.Error(), "its copy holds cluster key") {
		t.Errorf("a copy of another key = %v", err)
	}
	if _, err := sealCopy(next, old, "n_c", KeyringMember{Name: "siem-c", NodePub: "!!"}); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("a member whose node key is not base64 = %v", err)
	}
	if _, err := sealCopy(next, old, "n_c", KeyringMember{NodePub: "AAAA"}); err == nil || !strings.Contains(err.Error(), "the node key of n_c") {
		t.Errorf("a member whose node key is too short = %v", err)
	}
}

// A rotation does not start from a keyring whose rotation cannot be read,
// or with a member whose node key cannot be sealed to.
func TestKeyRotationFromADamagedKeyring(t *testing.T) {
	rc := newRotationCluster(t)
	ctx := context.Background()
	kdoc := rc.a.rt.Keyring()
	if _, err := kdoc.Mutate(ctx, "test", func(b *KeyringBody) error {
		b.Next = json.RawMessage(`"not a rotation"`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.a.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("a rotation from a damaged keyring = %v", err)
	}
	if _, err := kdoc.Mutate(ctx, "test", func(b *KeyringBody) error {
		b.Next = nil
		m := b.Members["n_siem-c"]
		m.NodePub = "!!"
		b.Members["n_siem-c"] = m
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.a.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "the node key of siem-c") {
		t.Errorf("a rotation to a member whose node key is damaged = %v", err)
	}
	kr, _ := kdoc.Get()
	if n, _ := kr.Rotation(); n != nil {
		t.Errorf("a refused rotation was recorded: %+v", n)
	}
}
