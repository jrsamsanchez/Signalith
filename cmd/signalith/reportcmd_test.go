// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/cases"
)

func TestReportVerifyCommand(t *testing.T) {
	now := time.Now()
	c := &cases.Case{ID: "CASE-1", Title: "x", Severity: "low", Status: "new", Created: now, Updated: now}
	r, err := casereport.New(c, nil, nil, "ana", "", now)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := r.HTML()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.html")
	bad := filepath.Join(dir, "bad.html")
	os.WriteFile(good, page, 0o600)
	os.WriteFile(bad, []byte(strings.Replace(string(page), "<dd>Low</dd>", "<dd>High</dd>", 1)), 0o600)
	if err := cmdReport([]string{"verify", good}); err != nil {
		t.Errorf("good: %v", err)
	}
	if err := cmdReport([]string{"verify", bad}); !errors.Is(err, errReportChanged) {
		t.Errorf("bad: %v", err)
	}
	if err := cmdReport([]string{"verify", filepath.Join(dir, "none")}); err == nil || errors.Is(err, errReportChanged) {
		t.Errorf("missing: %v", err)
	}
}
