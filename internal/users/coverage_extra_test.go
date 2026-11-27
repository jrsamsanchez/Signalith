// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// signalith passwd asks for the built-in admin to be turned on at the
// next start; the next server to start does so, once.
func TestBuiltinOnAtStart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	// On already: nothing to do.
	if was, err := SetFileBuiltinOnAtStart(path); err != nil || was {
		t.Fatalf("SetFileBuiltinOnAtStart while on = %v, %v", was, err)
	}
	if _, err := s.Create(ctx, newUser("kim", Admin)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetBuiltinDisabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if was, err := SetFileBuiltinOnAtStart(path); err != nil || !was {
			t.Fatalf("SetFileBuiltinOnAtStart = %v, %v", was, err)
		}
	}
	// It stays off until a server starts.
	if off, err := ReadFileBuiltinDisabled(path); err != nil || !off {
		t.Errorf("before the start: off %v, %v", off, err)
	}
	next, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	next.BuiltinAdmin = "admin"
	on, err := next.StartBuiltin(ctx)
	if err != nil || !on {
		t.Fatalf("StartBuiltin = %v, %v", on, err)
	}
	if next.BuiltinDisabled() {
		t.Error("still off after the start")
	}
	// A second start has nothing to turn on.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.BuiltinAdmin = "admin"
	if on, err := again.StartBuiltin(ctx); err != nil || on {
		t.Errorf("second StartBuiltin = %v, %v", on, err)
	}
}

func TestStartBuiltinWithoutFile(t *testing.T) {
	s := NewMemory()
	if on, err := s.StartBuiltin(context.Background()); err != nil || on {
		t.Errorf("StartBuiltin on memory = %v, %v", on, err)
	}
	// A built-in admin named by a function that has none.
	s.Builtin = func() (string, string, bool) { return "", "", false }
	if s.builtinName() != "" {
		t.Errorf("builtinName = %q", s.builtinName())
	}
	s.Builtin = func() (string, string, bool) { return "root", "hash", true }
	if s.builtinName() != "root" {
		t.Errorf("builtinName = %q", s.builtinName())
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range []Role{Viewer, Analyst, Admin} {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("ParseRole(%s) = %s, %v", r, got, err)
		}
	}
	for _, s := range []string{"", "root", "Admin"} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q) accepted", s)
		}
	}
	if Role("other").Label() != "other" {
		t.Error("Label of an unknown role")
	}
}

func TestSSOIssuer(t *testing.T) {
	sub := SSOSubject("https://idp.example.com", "abc 123")
	if got := SSOIssuer(sub); got != "https://idp.example.com" {
		t.Errorf("SSOIssuer = %q", got)
	}
	if got := SSOIssuer("no-space"); got != "no-space" {
		t.Errorf("SSOIssuer without a subject = %q", got)
	}
}

func TestCheckAppCode(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &mfaClock{time.Now().UTC().Truncate(30 * time.Second)}
	s.Now = clock.now
	if _, err := s.Create(ctx, newUser("jdoe", Analyst)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckAppCode("jdoe", "123456", 0); !errors.Is(err, ErrMFAOff) {
		t.Errorf("without two-step sign-in: %v", err)
	}
	secret, err := s.BeginMFA(ctx, "jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmMFA(ctx, "jdoe", code(t, secret, clock.t)); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(2 * time.Minute)
	c := code(t, secret, clock.t)
	step, err := s.CheckAppCode("jdoe", c, 0)
	if err != nil || step != clock.t.Unix()/30 {
		t.Fatalf("CheckAppCode = %d, %v", step, err)
	}
	// Nothing was written: the same code is still good, but not after
	// the step the caller already took.
	if _, err := s.CheckAppCode("jdoe", c, 0); err != nil {
		t.Errorf("checked again: %v", err)
	}
	if _, err := s.CheckAppCode("jdoe", c, step); !errors.Is(err, ErrWrongCode) {
		t.Errorf("a step already taken: %v", err)
	}
	if _, err := s.CheckAppCode("jdoe", "abc", 0); !errors.Is(err, ErrWrongCode) {
		t.Errorf("not a code: %v", err)
	}
	wrong := fmt.Sprintf("%06d", (mustAtoi(t, c)+1)%1000000)
	if _, err := s.CheckAppCode("jdoe", wrong, 0); !errors.Is(err, ErrWrongCode) {
		t.Errorf("wrong code: %v", err)
	}
	if _, err := s.CheckAppCode("nobody", c, 0); !errors.Is(err, ErrMFAOff) {
		t.Errorf("unknown user: %v", err)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestExplainLDAPErrors(t *testing.T) {
	settings := &LDAPSettings{UserBaseDN: "OU=People,DC=corp,DC=example,DC=com"}
	le := func(code uint16, msg string) error { return ldap.NewError(code, errors.New(msg)) }
	tests := []struct {
		name, step string
		err        error
		bindDN     string
		code       string
		msg        string
	}{
		{"network", "search", errors.New("reset"), "", "connect", "failed while talking"},
		{"ldap network", "search", le(ldap.ErrorNetwork, "eof"), "", "connect", "failed while talking"},
		{"strong auth", "search", le(ldap.LDAPResultStrongAuthRequired, "x"), "", "encryption_required", "encrypted"},
		{"bad bind", "bind", le(ldap.LDAPResultInvalidCredentials, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"), "", "bind_refused", "Active Directory says"},
		{"bad bind no ad", "bind", le(ldap.LDAPResultInvalidCredentials, "invalid"), "", "bind_refused", "refused the service account"},
		{"unwilling", "userbind", le(ldap.LDAPResultUnwillingToPerform, "no"), "", "bind_failed", "require an encrypted connection"},
		{"bind other", "bind", le(ldap.LDAPResultBusy, "busy"), "", "bind_failed", "Signing in to the directory failed"},
		{"no base", "search", le(ldap.LDAPResultNoSuchObject, "x"), "", "base_not_found", "user base DN OU=People"},
		{"group base", "groups", le(ldap.LDAPResultNoSuchObject, "x"), "", "base_not_found", "group base DN"},
		{"bad dn", "search", le(ldap.LDAPResultInvalidDNSyntax, "x"), "", "base_not_found", "not a valid DN"},
		{"no access", "search", le(ldap.LDAPResultInsufficientAccessRights, "x"), "", "search_refused", "not allowed to search"},
		{"anonymous", "search", le(ldap.LDAPResultOperationsError, "x"), "", "bind_required", "anonymous"},
		{"operations error with bind", "search", le(ldap.LDAPResultOperationsError, "oops"), "CN=svc", "search_failed", "Searching for the user failed"},
		{"group nesting", "groups", le(ldap.LDAPResultInappropriateMatching, "x"), "", "search_failed", "Nested groups"},
		{"group other", "groups", le(ldap.LDAPResultBusy, "x"), "", "search_failed", "groups failed"},
	}
	for _, tc := range tests {
		s := *settings
		s.BindDN = tc.bindDN
		e := explain(tc.step, "dc1.corp.example.com:636", tc.err, &s)
		if e.Code != tc.code || !strings.Contains(e.Message, tc.msg) || e.Server != "dc1.corp.example.com:636" {
			t.Errorf("%s: %s %q", tc.name, e.Code, e.Message)
		}
	}
	if adReason(errors.New("data 775")) != "account locked out" || adReason(errors.New("nothing")) != "" {
		t.Error("adReason")
	}
}

func TestSignedInRecordsDirectoryUsers(t *testing.T) {
	s := NewMemory()
	var got []string
	s.signedIn(context.Background(), Record{User: User{Username: "ann"}})
	s.SignIns = func(_ context.Context, name string, builtin bool) {
		got = append(got, fmt.Sprintf("%s %v", name, builtin))
	}
	s.signedIn(context.Background(), Record{User: User{Username: "ann"}})
	s.signedIn(context.Background(), Record{User: User{Username: "bob", Disabled: true}})
	if len(got) != 1 || got[0] != "ann false" {
		t.Errorf("sign-ins %v", got)
	}
}
