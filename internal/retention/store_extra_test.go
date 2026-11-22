// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"os"
	"path/filepath"
	"testing"
)

// A store without a file keeps its settings in memory.
func TestStoreWithoutFile(t *testing.T) {
	s := NewStore("")
	if saved, err := s.Get(); err != nil || len(saved.Policies) != 0 {
		t.Fatalf("empty: %+v %v", saved, err)
	}
	if err := s.Update(func(sv *Saved) { sv.Policies = map[string]Policy{"endpoint": {KeepDays: 30}} }); err != nil {
		t.Fatal(err)
	}
	if saved, err := s.Get(); err != nil || saved.Policies["endpoint"].KeepDays != 30 {
		t.Errorf("kept %+v %v", saved, err)
	}
	// A setting with problems is refused.
	if err := s.Update(func(sv *Saved) { sv.Policies = map[string]Policy{"endpoint": {KeepDays: -1}} }); err == nil {
		t.Error("a negative keep_days was saved")
	}
	// Removing every policy leaves none, not an empty map.
	if err := s.Update(func(sv *Saved) { sv.Policies = map[string]Policy{} }); err != nil {
		t.Fatal(err)
	}
	if saved, _ := s.Get(); saved.Policies != nil {
		t.Errorf("policies %v", saved.Policies)
	}
}

// A settings path that is a folder cannot be read: that is an error,
// and nothing is written over it.
func TestStorePathIsAFolder(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if _, err := s.Get(); err == nil {
		t.Error("read a folder as the settings file")
	}
	if err := s.Update(func(*Saved) {}); err == nil {
		t.Error("updated a folder")
	}
}

// A settings file whose folder cannot be made is not saved.
func TestStoreCannotWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(filepath.Join(file, "retention.yaml"))
	if err := s.Update(func(sv *Saved) { sv.Policies = map[string]Policy{"endpoint": {KeepDays: 30}} }); err == nil {
		t.Error("saved under a file")
	}
}
