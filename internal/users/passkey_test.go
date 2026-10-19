// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPasskeyName(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "Passkey",
		"  Work laptop  ":       "Work laptop",
		"Ann's\x00 phone‮":      "Ann's phone",
		strings.Repeat("é", 80): strings.Repeat("é", passkeyNameMax),
	} {
		if got := PasskeyName(in); got != want {
			t.Errorf("PasskeyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPasskeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	clock := &mfaClock{time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)}
	s.Now = clock.now
	u, err := s.Create(ctx, newUser("jdoe", Analyst))
	if err != nil {
		t.Fatal(err)
	}
	handle := s.PasskeyHandle("jdoe")
	if len(handle) != handleSize {
		t.Fatalf("handle %x", handle)
	}
	key := Passkey{ID: []byte("key-1"), PublicKey: []byte("pub"), RPID: "siem.example.com", Name: "Laptop"}
	codes, err := s.AddPasskey(ctx, "jdoe", handle, key)
	if err != nil || len(codes) != RecoveryCodes {
		t.Fatalf("first passkey: %d codes, %v", len(codes), err)
	}
	m, _ := s.MFA("jdoe")
	if !m.On() || m.AppOn() || !m.NoApp || len(m.Passkeys) != 1 || !m.Passkeys[0].Created.Equal(clock.t) {
		t.Fatalf("after the first passkey: %+v", m)
	}
	if after, _ := s.Get("jdoe"); after.SessionEpoch != u.SessionEpoch+1 {
		t.Error("the first passkey did not end the other sessions")
	}
	if !s.MFAOn("jdoe") {
		t.Error("MFAOn is false with a passkey")
	}
	// App codes do not work without an app; recovery codes do.
	if _, err := s.UseMFACode(ctx, "jdoe", code(t, m.Secret, clock.t)); !errors.Is(err, ErrWrongCode) {
		t.Errorf("app code without an app: %v", err)
	}
	if res, err := s.UseMFACode(ctx, "jdoe", codes[0]); err != nil || res.Kind != CodeRecovery {
		t.Errorf("recovery code: %+v %v", res, err)
	}
	if owner, ok := s.PasskeyOwner(handle); !ok || owner != "jdoe" {
		t.Errorf("owner = %q %v", owner, ok)
	}
	if _, ok := s.PasskeyOwner([]byte("nobody")); ok {
		t.Error("unknown handle has an owner")
	}
	if got := s.PasskeyHandle("jdoe"); string(got) != string(handle) {
		t.Error("handle changed")
	}

	// The same key twice, another handle, too many.
	if _, err := s.AddPasskey(ctx, "jdoe", handle, key); !errors.Is(err, ErrPasskeyExists) {
		t.Errorf("twice: %v", err)
	}
	if _, err := s.AddPasskey(ctx, "jdoe", NewPasskeyHandle(), Passkey{ID: []byte("key-x")}); !errors.Is(err, ErrPasskeyRace) {
		t.Errorf("other handle: %v", err)
	}
	for i := 2; i <= MaxPasskeys; i++ {
		if c, err := s.AddPasskey(ctx, "jdoe", handle, Passkey{ID: []byte{'k', byte(i)}}); err != nil || c != nil {
			t.Fatalf("passkey %d: %v %v", i, c, err)
		}
	}
	if _, err := s.AddPasskey(ctx, "jdoe", handle, Passkey{ID: []byte("one-more")}); !errors.Is(err, ErrTooManyPasskeys) {
		t.Errorf("too many: %v", err)
	}

	// Counters move on, never back; zero means none is kept.
	n := 0
	use := func(count uint32) PasskeyUse {
		n++
		return PasskeyUse{SignCount: count, Challenge: []byte{'c', byte(n)}, ChallengeUntil: clock.t.Add(6 * time.Minute)}
	}
	first := use(5)
	first.BackupState = true
	if k, err := s.UsePasskey(ctx, "jdoe", key.ID, first); err != nil || k.SignCount != 5 || !k.BackupState || !k.LastUsed.Equal(clock.t) {
		t.Errorf("use: %+v %v", k, err)
	}
	for _, c := range []uint32{5, 4, 0} {
		if _, err := s.UsePasskey(ctx, "jdoe", key.ID, use(c)); !errors.Is(err, ErrPasskeyCloned) {
			t.Errorf("counter %d: %v", c, err)
		}
	}
	// A passkey that keeps no counter (a synced one) still answers each
	// challenge once, whichever server checks it.
	synced := use(0)
	if _, err := s.UsePasskey(ctx, "jdoe", []byte{'k', 2}, synced); err != nil {
		t.Errorf("no counter: %v", err)
	}
	if _, err := s.UsePasskey(ctx, "jdoe", []byte{'k', 2}, synced); !errors.Is(err, ErrPasskeyReplayed) {
		t.Errorf("same challenge again: %v", err)
	}
	if _, err := s.UsePasskey(ctx, "jdoe", []byte{'k', 2}, use(0)); err != nil {
		t.Errorf("next challenge: %v", err)
	}
	if _, err := s.UsePasskey(ctx, "jdoe", []byte{'k', 2}, PasskeyUse{}); !errors.Is(err, ErrPasskeyReplayed) {
		t.Errorf("no challenge: %v", err)
	}
	if _, err := s.UsePasskey(ctx, "jdoe", []byte("gone"), use(9)); !errors.Is(err, ErrPasskeyUnknown) {
		t.Errorf("unknown: %v", err)
	}
	// Spent challenges are forgotten once they expire.
	clock.t = clock.t.Add(7 * time.Minute)
	if _, err := s.UsePasskey(ctx, "jdoe", []byte{'k', 2}, use(0)); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.MFA("jdoe"); len(m.Spent) != 1 {
		t.Errorf("%d spent challenges kept", len(m.Spent))
	}
	// Another account cannot register the same credential.
	if _, err := s.Create(ctx, newUser("mroe", Analyst)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(ctx, "mroe", s.PasskeyHandle("mroe"), Passkey{ID: key.ID}); !errors.Is(err, ErrPasskeyExists) {
		t.Errorf("another account's credential: %v", err)
	}

	// An app set up alongside keeps the recovery codes and the passkeys.
	secret, err := s.BeginMFA(ctx, "jdoe")
	if err != nil || secret != m.Secret {
		t.Fatalf("app: %v, same secret %v", err, secret == m.Secret)
	}
	clock.t = clock.t.Add(time.Minute)
	if _, err := s.ConfirmMFA(ctx, "jdoe", code(t, secret, clock.t)); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.MFA("jdoe"); !m.AppOn() || len(m.Passkeys) != MaxPasskeys {
		t.Errorf("with the app: %+v", m)
	}
	// Turning the app off keeps the passkeys.
	if had, err := s.RemoveApp(ctx, "jdoe"); !had || err != nil {
		t.Fatalf("remove app: %v %v", had, err)
	}
	if m, _ := s.MFA("jdoe"); !m.On() || m.AppOn() || len(m.Passkeys) != MaxPasskeys {
		t.Errorf("app off: %+v", m)
	}
	if had, err := s.RemoveApp(ctx, "jdoe"); had || err != nil {
		t.Errorf("remove app twice: %v %v", had, err)
	}

	// Kept, sealed, in the users file.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := reopened.MFA("jdoe"); !ok || !m.NoApp || len(m.Passkeys) != MaxPasskeys || string(m.Handle) != string(handle) || m.Passkeys[0].SignCount != 5 {
		t.Errorf("reopened: %+v", m)
	}
	// The app key is sealed; a passkey's public key is no secret.
	if data, _ := os.ReadFile(path); strings.Contains(string(data), m.Secret) || !strings.Contains(string(data), `"passkeys"`) {
		t.Errorf("users file:\n%s", data)
	}

	// A password reset removes them all, keeping the app.
	if _, err := s.BeginMFA(ctx, "jdoe"); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(time.Minute)
	if _, err := s.ConfirmMFA(ctx, "jdoe", code(t, m.Secret, clock.t)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RemovePasskeys(ctx, "jdoe"); n != MaxPasskeys || err != nil {
		t.Fatalf("remove all: %d %v", n, err)
	}
	if m, _ := s.MFA("jdoe"); !m.AppOn() || len(m.Passkeys) != 0 {
		t.Errorf("after removing all: %+v", m)
	}
	if n, err := s.RemovePasskeys(ctx, "jdoe"); n != 0 || err != nil {
		t.Errorf("remove all again: %d %v", n, err)
	}
	if _, err := s.RemoveApp(ctx, "jdoe"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := s.AddPasskey(ctx, "jdoe", handle, Passkey{ID: []byte{'r', byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	// Removing the last one turns two-step sign-in off.
	m, _ = s.MFA("jdoe")
	for _, k := range m.Passkeys {
		if _, err := s.RemovePasskey(ctx, "jdoe", k.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.MFA("jdoe"); ok || s.MFAOn("jdoe") {
		t.Error("still on with no passkeys and no app")
	}
	if _, err := s.RemovePasskey(ctx, "jdoe", []byte{'r', 1}); !errors.Is(err, ErrPasskeyUnknown) {
		t.Errorf("remove again: %v", err)
	}

	// The built-in admin can have them too.
	ah := s.PasskeyHandle("admin")
	if _, err := s.AddPasskey(ctx, "Admin", ah, Passkey{ID: []byte("admin-key")}); err != nil {
		t.Fatal(err)
	}
	if owner, ok := s.PasskeyOwner(ah); !ok || owner != "admin" {
		t.Errorf("admin owner = %q %v", owner, ok)
	}
}
