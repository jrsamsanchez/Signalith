// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Passwords past the 72 bytes bcrypt reads are accepted whole: 64
// characters of a non-Latin script, and passwords that differ only after
// the 72nd byte are told apart. Up to 72 bytes the hash is plain bcrypt,
// so hashes made before, and by other bcrypt tools, still match.
func TestLongPasswords(t *testing.T) {
	greek := strings.Repeat("αβγδεζηθ", 8) // 64 characters, 128 bytes
	if err := CheckNewPassword("alice", greek); err != nil {
		t.Fatalf("64 Greek characters refused: %v", err)
	}
	h, err := HashPassword(greek)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(h, greek) {
		t.Error("the long password does not match its hash")
	}
	if ComparePassword(h, greek[:72]) || ComparePassword(h, greek+"x") {
		t.Error("a password sharing the first 72 bytes matches")
	}
	a, b := strings.Repeat("k", 80)+"one", strings.Repeat("k", 80)+"two"
	ha, err := HashPassword(a)
	if err != nil {
		t.Fatal(err)
	}
	if ComparePassword(ha, b) {
		t.Error("passwords differing after byte 72 match")
	}

	short := strings.Repeat("q7", 36) // exactly 72 bytes
	plain, err := bcrypt.GenerateFromPassword([]byte(short), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(string(plain), short) {
		t.Error("a plain bcrypt hash of a 72-byte password no longer matches")
	}
	hs, _ := HashPassword(short)
	if bcrypt.CompareHashAndPassword([]byte(hs), []byte(short)) != nil {
		t.Error("a 72-byte password is not hashed as plain bcrypt")
	}

	if _, err := HashPassword(strings.Repeat("ж", 257)); err == nil {
		t.Error("257 characters accepted")
	}
	if ComparePassword("", greek) {
		t.Error("an empty hash matches")
	}
}

// Password hashes are made at HashCost (AUTHRT-12). This package's tests
// never call UseFastHashesInTests, so this checks the production cost.
func TestHashPasswordCost(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := bcrypt.Cost([]byte(h)); err != nil || c != HashCost || HashCost < 12 {
		t.Fatalf("cost %d (%v), want %d", c, err, HashCost)
	}
	if c, err := bcrypt.Cost(dummyHash()); err != nil || c != HashCost {
		t.Fatalf("dummy hash cost %d (%v), want %d", c, err, HashCost)
	}
}

// AUTHRT-12: a local user's hash from an older version, of a lower cost,
// is made again at HashCost once the right password is checked; a wrong
// one changes nothing.
func TestCheckPasswordRehashes(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	if _, err := st.Create(ctx, NewUser{Username: "olga", Role: Viewer, Password: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	old, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.b.Change(ctx, "test", "olga", "", func(r *Record) error { r.Hash = string(old); return nil }); err != nil {
		t.Fatal(err)
	}
	if v := st.PasswordVersion("olga"); v != string(old) {
		t.Fatalf("the old hash is not in use: %q", v)
	}
	if st.CheckPassword("olga", "wrong horse battery") || st.PasswordVersion("olga") != string(old) {
		t.Fatal("a wrong password was accepted, or changed the hash")
	}
	if !st.CheckPassword("olga", "correct horse battery") {
		t.Fatal("the right password was refused")
	}
	now := st.PasswordVersion("olga")
	if c, err := bcrypt.Cost([]byte(now)); err != nil || c != HashCost {
		t.Fatalf("hash after the sign-in has cost %d (%v), want %d", c, err, HashCost)
	}
	if !st.CheckPassword("olga", "correct horse battery") || st.PasswordVersion("olga") != now {
		t.Error("the new hash does not check, or was made again")
	}
	if u, _ := st.Get("olga"); u.SessionEpoch != 0 && u.SessionEpoch != 1 {
		t.Errorf("session epoch %d moved on", u.SessionEpoch)
	}
}

// AUTHRT-12: a name that is no user is checked at a cost the stored
// hashes have, in their proportions, so users whose hashes are of an
// older, lower cost are not told apart from unknown names by how quickly
// they are refused. Each name always gets the same cost.
func TestWasteTimeMatchesStoredCosts(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	if _, ok := st.dummyCost("nobody"); ok {
		t.Error("a dummy cost with no stored hashes")
	}
	for _, u := range []struct {
		name string
		cost int
	}{{"old1", bcrypt.MinCost}, {"old2", bcrypt.MinCost}, {"new1", bcrypt.MinCost + 1}} {
		h, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), u.cost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Create(ctx, NewUser{Username: u.name, Role: Viewer, Password: "correct horse battery"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.b.Change(ctx, "test", u.name, "", func(r *Record) error { r.Hash = string(h); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int]int{}
	for i := range 300 {
		name := fmt.Sprintf("nobody%d", i)
		c, ok := st.dummyCost(name)
		if !ok || c != bcrypt.MinCost && c != bcrypt.MinCost+1 {
			t.Fatalf("%s: dummy cost %d %v", name, c, ok)
		}
		if again, _ := st.dummyCost(name); again != c {
			t.Fatalf("%s: dummy cost %d then %d", name, c, again)
		}
		seen[c]++
	}
	if seen[bcrypt.MinCost] < 150 || seen[bcrypt.MinCost+1] < 50 {
		t.Errorf("dummy costs %v, want about two in three at the lower cost", seen)
	}
	st.WasteTime("nobody", "a password")
	if st.CheckPassword("nobody", "correct horse battery") {
		t.Error("an unknown name signed in")
	}
}

// A rehash makes its hash before taking the hold, and replaces only the
// hash it checked: a password changed while it waited for the hold stays.
func TestRehashKeepsAPasswordChangedMeanwhile(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	if _, err := st.Create(ctx, NewUser{Username: "olga", Role: Viewer, Password: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	old, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.b.Change(ctx, "test", "olga", "", func(r *Record) error { r.Hash = string(old); return nil }); err != nil {
		t.Fatal(err)
	}
	changed := ""
	st.Hold = func() (func(), error) {
		if changed == "" {
			// Another change wins the race for the hold.
			changed = "set"
			st.Hold = nil
			if _, err := st.SetPassword(ctx, "olga", "a new staple battery", false); err != nil {
				t.Error(err)
			}
			changed = st.PasswordVersion("olga")
		}
		return func() {}, nil
	}
	if !st.CheckPassword("olga", "correct horse battery") {
		t.Fatal("the right password was refused")
	}
	if changed == "" || changed == "set" || st.PasswordVersion("olga") != changed {
		t.Error("the rehash replaced a password changed while it waited")
	}
}
