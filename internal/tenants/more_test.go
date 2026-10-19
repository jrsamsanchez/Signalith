// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tenants

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDir(t *testing.T) {
	if got, want := Dir("state", "acme"), filepath.Join("state", "tenants", "acme"); got != want {
		t.Errorf("Dir = %s, want %s", got, want)
	}
}

func TestNamesAndLimits(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	r, err := Open(File(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", strings.Repeat("n", 101), "admin", now); err == nil || !strings.Contains(err.Error(), "at most 100") {
		t.Errorf("long name = %v", err)
	}
	if _, err := r.Add("acme", "bad\xffname", "admin", now); err == nil {
		t.Error("a name that is not UTF-8 was taken")
	}
	if _, err := r.Add("acme", strings.Repeat("é", 100), "admin", now); err != nil {
		t.Errorf("100 characters = %v", err)
	}
	bad := " "
	if _, err := r.Change("acme", &bad, nil, "admin"); err == nil {
		t.Error("an empty new name was taken")
	}
	off := true
	got, err := r.Change("acme", nil, &off, "admin")
	if err != nil || !got.Disabled || got.Name != strings.Repeat("é", 100) {
		t.Errorf("turn off = %+v %v", got, err)
	}

	// A cluster's list already full.
	full := &fakeShared{on: true}
	for i := range MaxTenants {
		full.list = append(full.list, Tenant{ID: fmt.Sprintf("t%d", i), Name: "x"})
	}
	r.UseShared(full)
	if _, err := r.Add("another", "Another", "admin", now); !errors.Is(err, ErrTooMany) {
		t.Errorf("full = %v", err)
	}
}

func TestCheckList(t *testing.T) {
	many := make([]Tenant, MaxTenants+1)
	for i := range many {
		many[i].ID = fmt.Sprintf("t%d", i)
	}
	if err := CheckList(many); !errors.Is(err, ErrTooMany) {
		t.Errorf("too many = %v", err)
	}
	if err := CheckList([]Tenant{{ID: "Bad"}}); err == nil || !strings.Contains(err.Error(), "lower-case") {
		t.Errorf("bad ID = %v", err)
	}
	if err := CheckList([]Tenant{{ID: "ab"}, {ID: "ab"}}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("twice = %v", err)
	}
	if err := CheckList(many[:3]); err != nil {
		t.Errorf("good = %v", err)
	}
}

func TestFileProblems(t *testing.T) {
	dir := t.TempDir()
	// The registry's path is a folder, so it cannot be read.
	if _, err := Open(dir); err == nil {
		t.Error("a folder opened as the registry")
	}
	path := File(dir)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.List(); err == nil {
		t.Error("listing a folder worked")
	}
	if _, err := r.Add("acme", "Acme", "admin", time.Now()); err == nil {
		t.Error("adding to a folder worked")
	}

	// The folder to keep the file in is a file.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(blocker, "tenants.json"), nil); err == nil {
		t.Error("written under a file")
	}
}
