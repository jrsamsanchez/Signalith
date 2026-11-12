// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
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
