// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

const updateRule = "proc_access_win_hktl_generic_access.yml"

// updateFS is a content update of one Sigma pack: a rule this build
// converts, and one whose file is missing.
func updateFS(t *testing.T) fstest.MapFS {
	t.Helper()
	src, err := os.ReadFile("packs/sigmahq/rules/" + updateRule)
	if err != nil {
		t.Fatal(err)
	}
	manifest := `name: update
title: An update
rules:
  - id: update-generic-access
    rule_id: d0d2f720-d14f-448d-8242-51ff396a334e
    file: ` + updateRule + `
    path: rules/windows/process_access/` + updateRule + `
  - id: update-missing
    rule_id: 00000000-0000-0000-0000-000000000000
    file: missing.yml
    path: rules/windows/missing.yml
`
	return fstest.MapFS{
		"packs/update/pack.yaml":           {Data: []byte(manifest)},
		"packs/update/rules/" + updateRule: {Data: src},
	}
}

// A content update's packs replace the built-in ones until it is removed,
// and a library takes them on ReloadPacks.
func TestContentUpdate(t *testing.T) {
	ps, ds, skipped, err := LoadPacks(updateFS(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || len(ds) != 1 || ds[0].ID != "update-generic-access" {
		t.Fatalf("packs %d, detections %+v", len(ps), ds)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Error(), "missing.yml") {
		t.Errorf("skipped = %v", skipped)
	}
	if _, _, _, err := LoadPacks(fstest.MapFS{}); err == nil {
		t.Error("content without packs loaded")
	}
	if _, _, _, err := LoadPacks(fstest.MapFS{"packs/x/pack.yaml": {Data: []byte("rules: [")}}); err == nil {
		t.Error("a broken manifest loaded")
	}

	lib, _, err := NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	builtin := BuiltinContentVersion()
	if v, updated := ContentVersion(); updated || v != builtin {
		t.Fatalf("version = %s %v", v, updated)
	}
	UsePacks(ps, ds, "update-1")
	defer func() {
		UsePacks(nil, nil, "")
		if err := lib.ReloadPacks(); err != nil {
			t.Error(err)
		}
	}()
	if v, updated := ContentVersion(); !updated || v != "update-1" {
		t.Errorf("version = %s %v", v, updated)
	}
	if err := lib.ReloadPacks(); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Get("update-generic-access"); err != nil {
		t.Errorf("update's detection: %v", err)
	}
	if _, err := lib.Get("sigma-access-hktl-generic-access"); !errors.Is(err, ErrNotFound) {
		t.Errorf("built-in pack detection still there: %v", err)
	}
	UsePacks(nil, nil, "")
	if err := lib.ReloadPacks(); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Get("sigma-access-hktl-generic-access"); err != nil {
		t.Errorf("built-in pack detection not back: %v", err)
	}
	if v, updated := ContentVersion(); updated || v != builtin {
		t.Errorf("version after removing = %s %v", v, updated)
	}
}

// The scheduler's settings read back as set, and Preview runs a
// detection's query over its lookback without raising findings.
func TestSchedulerSettingsAndPreview(t *testing.T) {
	lib, _, _ := NewLibrary("")
	run := &fakeRunner{rows: []search.Row{{"user": "bob"}}}
	now := time.Now()
	s := &Scheduler{Library: lib, Engine: run, Now: func() time.Time { return now }}
	s.SetSpread(true)
	s.SetSearchBudget(7)
	s.SetMaxFindingsPerRun(3)
	if !s.SpreadOn() || s.SearchBudgetSetting() != 7 || s.MaxFindingsPerRun != 3 {
		t.Errorf("settings = %v %d %d", s.SpreadOn(), s.SearchBudgetSetting(), s.MaxFindingsPerRun)
	}
	res, err := s.Preview(context.Background(), &Detection{ID: "p", Query: "user=bob", Lookback: "1h"})
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("preview = %+v %v", res, err)
	}
	if !run.last.EventsOnly || run.last.Earliest != now.Add(-time.Hour).UTC().Format(time.RFC3339) {
		t.Errorf("preview query = %+v", run.last)
	}
	if _, err := s.Preview(context.Background(), &Detection{ID: "p", Query: "user=(", Lookback: "1h"}); err == nil {
		t.Error("previewed a query that does not parse")
	}
	if _, err := s.Preview(context.Background(), &Detection{ID: "p", Query: "user=bob", Lookback: "soon"}); err == nil {
		t.Error("previewed a bad lookback")
	}
	e := &RuleError{Err: errors.New("bad query")}
	if e.Error() != "bad query" || !errors.Is(e, e.Err) {
		t.Errorf("rule error = %v", e)
	}
}
