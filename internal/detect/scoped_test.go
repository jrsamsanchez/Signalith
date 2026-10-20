// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestScopedExceptionInScope(t *testing.T) {
	d := &Detection{ID: "ps-encoded", Tags: []string{"PowerShell", "execution"}, Origin: &Origin{Pack: "sigmahq"}}
	plain := &Detection{ID: "auth-brute-force"}
	for _, tc := range []struct {
		scope    string
		d, plain bool
	}{
		{"all", true, true},
		{"pack:sigmahq", true, false},
		{"pack:SigmaHQ", true, false},
		{"pack:splunk", false, false},
		{"tag:powershell", true, false},
		{"tag:persistence", false, false},
		{"", false, false},
		{"everything", false, false},
	} {
		e := Exception{ID: "ex-1", Scope: tc.scope}
		if got := e.InScope(d); got != tc.d {
			t.Errorf("%q covers the pack rule = %v", tc.scope, got)
		}
		if got := e.InScope(plain); got != tc.plain {
			t.Errorf("%q covers the built-in = %v", tc.scope, got)
		}
	}
	for scope, ok := range map[string]bool{"all": true, "pack:sigmahq": true, "tag:a b": true, "pack:": false, "tag: x": false, "host:web1": false, "All": false} {
		if err := checkScope(scope); (err == nil) != ok {
			t.Errorf("checkScope(%q) = %v", scope, err)
		}
	}
}

func TestScopedExceptionsSuppressFirst(t *testing.T) {
	dir := t.TempDir()
	lib, _, err := NewLibrary(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	run := &fakeRunner{rows: []search.Row{
		{"src": "10.0.0.5", "dest": "sccm01", "count": int64(40)},
		{"src": "198.51.100.1", "dest": "web1", "count": int64(12)},
	}}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	// The detection's own exception would match too: the scoped one is
	// checked first, and the run counts the row once.
	if _, err := lib.UpdateExceptions("auth-brute-force", func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: "ex-own", Match: map[string]string{"dest": "sccm*"}}), nil
	}); err != nil {
		t.Fatal(err)
	}
	es, err := lib.UpdateScopedExceptionsIf(context.Background(), "admin", lib.ScopedETag(), func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: "ex-sccm", Scope: ScopeAll, Match: map[string]string{"dest": "SCCM01"}, By: "admin", Added: now}), nil
	})
	if err != nil || len(es) != 1 {
		t.Fatalf("add = %v, %v", es, err)
	}
	d, _ := lib.Get("auth-brute-force")
	if len(d.Scoped) != 1 || d.Suppressing(map[string]any{"dest": "sccm01"}, now).ID != "ex-sccm" {
		t.Fatalf("scoped = %+v", d.Scoped)
	}
	res, err := s.RunManual(context.Background(), d, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Suppressed != 1 || len(res.Findings) != 1 || res.Findings[0].Entities["dest"] != "web1" {
		t.Fatalf("run = %+v", res)
	}
	// It is kept as state under the reserved name, not as a detection,
	// and survives a restart.
	if data, err := os.ReadFile(filepath.Join(dir, StateDir, ScopedID+".yaml")); err != nil || !strings.Contains(string(data), "scope: all") {
		t.Fatalf("state = %s, %v", data, err)
	}
	lib, problems, _ := NewLibrary(dir)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if _, err := lib.Get(ScopedID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the reserved name is a detection: %v", err)
	}
	for _, d := range lib.List() {
		if len(d.Scoped) != 1 {
			t.Fatalf("%s has %d scoped exceptions", d.ID, len(d.Scoped))
		}
	}
	// A pack scope covers only that pack's rules.
	var packRule *Detection
	for _, d := range lib.List() {
		if d.Origin != nil {
			packRule = d
			break
		}
	}
	if packRule == nil {
		t.Fatal("no pack rules")
	}
	if _, err := lib.UpdateScopedExceptionsIf(context.Background(), "admin", "", func([]Exception) ([]Exception, error) {
		return []Exception{{ID: "ex-pack", Scope: "pack:" + packRule.Origin.Pack, Match: map[string]string{"user": "ansible"}}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if d, _ := lib.Get("auth-brute-force"); len(d.Scoped) != 0 {
		t.Errorf("scoped = %+v", d.Scoped)
	}
	if d, _ := lib.Get(packRule.ID); len(d.Scoped) != 1 || d.Suppressing(map[string]any{"user": "Ansible"}, now) == nil {
		t.Errorf("pack rule scoped = %+v", d.Scoped)
	}
	// Removing the last one removes the file.
	if _, err := lib.UpdateScopedExceptionsIf(context.Background(), "admin", "", func([]Exception) ([]Exception, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateDir, ScopedID+".yaml")); !os.IsNotExist(err) {
		t.Errorf("state file left: %v", err)
	}
}

func TestScopedExceptionsLimits(t *testing.T) {
	lib, _, _ := NewLibrary("")
	ctx := context.Background()
	refused := func(name, want string, es ...Exception) {
		t.Helper()
		_, err := lib.UpdateScopedExceptionsIf(ctx, "admin", "", func([]Exception) ([]Exception, error) { return es, nil })
		var ve *ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	until := time.Now().Add(time.Hour)
	refused("no scope", "scope is required", Exception{ID: "ex-1", Match: map[string]string{"host": "x"}})
	refused("bad scope", "must be all", Exception{ID: "ex-1", Scope: "host:x", Match: map[string]string{"host": "x"}})
	refused("every result", "needs an end time", Exception{ID: "ex-1", Scope: ScopeAll})
	refused("bad field", "not a field name", Exception{ID: "ex-1", Scope: ScopeAll, Match: map[string]string{"a b": "x"}})
	many := make([]Exception, MaxExceptions+1)
	for i := range many {
		many[i] = Exception{ID: NewExceptionID(), Scope: ScopeAll, Match: map[string]string{"host": "x"}}
	}
	refused("too many", "at most 500", many...)
	// A maintenance window for every rule is allowed, with an end.
	if _, err := lib.UpdateScopedExceptionsIf(ctx, "admin", "", func([]Exception) ([]Exception, error) {
		return []Exception{{ID: "ex-window", Scope: ScopeAll, Until: &until}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	// A stale version is refused.
	if _, err := lib.UpdateScopedExceptionsIf(ctx, "admin", ETag(nil, nil), func(es []Exception) ([]Exception, error) { return es, nil }); err == nil {
		t.Error("stale etag accepted")
	}
	// A detection's own exceptions have no scope, and the reserved name
	// takes neither a detection nor its exceptions.
	if _, err := lib.UpdateExceptions("auth-brute-force", func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: "ex-own", Scope: ScopeAll, Match: map[string]string{"host": "x"}}), nil
	}); err == nil || !strings.Contains(err.Error(), "has no scope") {
		t.Errorf("own exception with a scope: %v", err)
	}
	if _, err := lib.UpdateExceptions(ScopedID, func(es []Exception) ([]Exception, error) { return es, nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("reserved name: %v", err)
	}
	d, _ := lib.Get("auth-brute-force")
	c := *d
	c.ID = ScopedID
	if err := lib.Put(&c); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("put reserved = %v", err)
	}
}
