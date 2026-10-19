// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCheckNewPassword(t *testing.T) {
	for _, c := range []struct {
		user, pw string
		want     error
	}{
		// Common passwords, whatever the case.
		{"alice", "password", ErrCommonPassword},
		{"alice", "PassWord1", ErrCommonPassword},
		{"alice", "iloveyou", ErrCommonPassword},
		{"alice", "changeme", ErrCommonPassword},
		{"alice", "QWERTYUIOP", ErrCommonPassword},
		// Repeated and sequential runs.
		{"alice", "qqqqqqqqq", ErrSequencePassword},
		{"alice", "zzzzzzzzzzzz", ErrSequencePassword},
		{"alice", "abcabcabc", ErrSequencePassword},
		{"alice", "xy12xy12xy12", ErrSequencePassword},
		{"alice", "23456789", ErrSequencePassword},
		{"alice", "abcdefghij", ErrSequencePassword},
		{"alice", "ZYXWVUTS", ErrSequencePassword},
		{"alice", "76543210", ErrSequencePassword},
		// The username, in any case and anywhere in the password.
		{"jlee", "jlee-at-work", ErrUsernamePassword},
		{"Jlee", "my JLEE pass 7", ErrUsernamePassword},
		{"admin", "superadmin-77", ErrUsernamePassword},
		// A short username is not looked for.
		{"al", "al-paints-boats", nil},
		{"", "a long enough pass", nil},
		// The product's name with only digits or symbols around it.
		{"alice", "Signalith1", ErrProductPassword},
		{"alice", "signalith2026!", ErrProductPassword},
		{"alice", "!!SIGNALITH!!", ErrProductPassword},
		{"alice", "signalith rocks", nil},
		// Good passwords.
		{"alice", "correct horse battery", nil},
		{"alice", "kq7m-3xhp-9tvd-w2fa", nil},
		{"alice", "s3cret-pass", nil},
	} {
		if err := CheckNewPassword(c.user, c.pw); !errors.Is(err, c.want) {
			t.Errorf("%s %q: %v, want %v", c.user, c.pw, err, c.want)
		}
	}
	// The length rules come first.
	if err := CheckNewPassword("alice", "abc"); err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Errorf("short: %v", err)
	}
	if err := CheckNewPassword("alice", strings.Repeat("xyz", 86)); err == nil || !strings.Contains(err.Error(), "at most 256") {
		t.Errorf("long: %v", err)
	}
	if !strings.Contains(ErrCommonPassword.Error(), "on a list of commonly used passwords; choose another") {
		t.Errorf("message %q", ErrCommonPassword)
	}
}

// Every entry of the list is refused, and nothing on it is shorter than
// the shortest password allowed anyway.
func TestCommonPasswordList(t *testing.T) {
	set := commonPasswords()
	if len(set) < 1000 {
		t.Fatalf("%d common passwords", len(set))
	}
	for pw := range set {
		if len([]rune(pw)) < MinPasswordLength || pw != strings.ToLower(pw) {
			t.Errorf("list entry %q", pw)
		}
		if err := CheckNewPassword("", pw); err == nil {
			t.Errorf("%q accepted", pw)
		}
	}
}

// The temporary passwords Signalith makes up always pass.
func TestGeneratedPasswordsPass(t *testing.T) {
	for range 2000 {
		if pw := GeneratePassword(); CheckNewPassword("someone", pw) != nil {
			t.Fatalf("%q: %v", pw, CheckNewPassword("someone", pw))
		}
	}
}

// Adding a user and setting a password check the new password against the
// username; a password stored before is not checked again at sign-in.
func TestStoreChecksNewPasswords(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	in := newUser("mallory", Viewer)
	in.Password = "Password1"
	_, err := s.Create(ctx, in)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "password" || !errors.Is(err, ErrCommonPassword) {
		t.Fatalf("common password: %v", err)
	}
	in.Password = "mallory-2026"
	if _, err := s.Create(ctx, in); !errors.Is(err, ErrUsernamePassword) {
		t.Fatalf("username in password: %v", err)
	}
	in.Password = "temporary-pass"
	if _, err := s.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPassword(ctx, "mallory", "23456789", false); !errors.Is(err, ErrSequencePassword) {
		t.Errorf("sequence: %v", err)
	}
	if _, err := s.SetPassword(ctx, "mallory", GeneratePassword(), true); err != nil {
		t.Errorf("generated: %v", err)
	}
	// A weak password already stored still signs in.
	s.mu.Lock()
	h, _ := HashPassword("password")
	s.hashes["mallory"] = h
	s.mu.Unlock()
	if !s.CheckPassword("mallory", "password") {
		t.Error("a stored password was checked against the new password rules")
	}
}
