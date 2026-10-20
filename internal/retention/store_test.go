// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups", "retention.yaml")
	s := NewStore(path)
	if saved, err := s.Get(); err != nil || saved.Default != nil || len(saved.Policies) != 0 {
		t.Fatalf("empty store = %+v %v", saved, err)
	}
	err := s.Update(func(sv *Saved) {
		sv.Default = &Policy{KeepDays: 60}
		sv.Policies = map[string]Policy{"endpoint": {KeepDays: 30, MaxSizeGB: 2.5, CompactAfterDays: 7, Archive: true}, Findings: {KeepDays: 365}}
		off := false
		sv.Guard = &Guard{Enabled: &off, MaxDiskPercent: 80, MinDays: 3}
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v", st.Mode().Perm())
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# Data retention settings") || !strings.Contains(string(data), "compact_after_days: 7") {
		t.Errorf("file:\n%s", data)
	}
	saved, err := NewStore(path).Get()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Default.KeepDays != 60 || saved.Policies["endpoint"].MaxSizeGB != 2.5 || !saved.Policies["endpoint"].Archive ||
		saved.Policies[Findings].KeepDays != 365 || saved.Guard.IsEnabled() || saved.Guard.MinDays != 3 {
		t.Errorf("reloaded = %+v", saved)
	}
	// Get returns a copy.
	saved.Policies["endpoint"] = Policy{}
	if again, _ := s.Get(); again.Policies["endpoint"].KeepDays != 30 {
		t.Error("Get shares its map")
	}
	// Invalid changes are refused and nothing is written.
	if err := s.Update(func(sv *Saved) { sv.Policies["endpoint"] = Policy{KeepDays: -1} }); err == nil {
		t.Error("invalid policy saved")
	}
	if again, _ := NewStore(path).Get(); again.Policies["endpoint"].KeepDays != 30 {
		t.Error("an invalid change reached the file")
	}
	// Removing the last policy drops the key.
	if err := s.Update(func(sv *Saved) { sv.Policies = nil }); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "policies") {
		t.Errorf("file:\n%s", data)
	}
}

func TestStoreReloadsAndReportsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.yaml")
	s := NewStore(path)
	if err := os.WriteFile(path, []byte("policies:\n  endpoint:\n    keep_days: 14\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := s.Get()
	if err != nil || saved.Policies["endpoint"].KeepDays != 14 {
		t.Fatalf("edited by hand: %+v %v", saved, err)
	}
	// A typo is an error, not a silently ignored setting, and the store
	// refuses to overwrite the file until it is fixed.
	later := time.Now().Add(time.Second)
	os.WriteFile(path, []byte("policies:\n  endpoint:\n    keepdays: 14\n"), 0o600)
	os.Chtimes(path, later, later)
	if _, err := s.Get(); err == nil || !strings.Contains(err.Error(), "keepdays") {
		t.Errorf("typo: %v", err)
	}
	if err := s.Update(func(sv *Saved) {}); err == nil {
		t.Error("update over a broken file")
	}
	later = later.Add(time.Second)
	os.WriteFile(path, []byte("policies:\n  intel:\n    keep_days: 14\n"), 0o600)
	os.Chtimes(path, later, later)
	if _, err := s.Get(); err == nil || !strings.Contains(err.Error(), "policies.intel") {
		t.Errorf("intel policy: %v", err)
	}
	os.Remove(path)
	if saved, err := s.Get(); err != nil || len(saved.Policies) != 0 {
		t.Errorf("deleted file: %+v %v", saved, err)
	}
}
