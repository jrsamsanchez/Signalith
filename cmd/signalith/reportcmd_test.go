// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

func TestReportVerifyCommand(t *testing.T) {
	now := time.Now()
	c := &cases.Case{ID: "CASE-1", Title: "x", Severity: "low", Status: "new", Created: now, Updated: now}
	r, err := casereport.New(c, nil, nil, "ana", "", "signalith", now)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := r.Sign(nil)
	page, _ := s.HTML()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.html")
	bad := filepath.Join(dir, "bad.html")
	os.WriteFile(good, page, 0o600)
	os.WriteFile(bad, []byte(strings.Replace(string(page), "<dd>Low</dd>", "<dd>High</dd>", 1)), 0o600)
	// Unsigned and intact: exit 4, or 0 when that is allowed.
	if err := cmdReport([]string{"verify", good}); !errors.Is(err, errReportUnchecked) || reportExitCode(err) != 4 {
		t.Errorf("good: %v", err)
	}
	if err := cmdReport([]string{"verify", "-allow-unsigned", good}); err != nil {
		t.Errorf("good, unsigned allowed: %v", err)
	}
	if err := cmdReport([]string{"verify", "-allow-unsigned", "-tenant", "other", good}); !errors.Is(err, errReportChanged) {
		t.Errorf("another tenant: %v", err)
	}
	if err := cmdReport([]string{"verify", bad}); !errors.Is(err, errReportChanged) {
		t.Errorf("bad: %v", err)
	}
	if err := cmdReport([]string{"verify", filepath.Join(dir, "none")}); err == nil || errors.Is(err, errReportChanged) {
		t.Errorf("missing: %v", err)
	}
}

func TestReportVerifyChecksSignatures(t *testing.T) {
	now := time.Now()
	c := &cases.Case{ID: "CASE-2", Title: "y", Severity: "low", Status: "new", Created: now, Updated: now}
	r, _ := casereport.New(c, nil, nil, "ana", "", "signalith", now)
	_, priv, _ := ed25519.GenerateKey(nil)
	s, _ := r.Sign(priv)
	js, _ := s.JSON()
	dir := t.TempDir()
	report := filepath.Join(dir, "r.json")
	os.WriteFile(report, js, 0o600)
	keysFile := filepath.Join(dir, "keys.json")
	ks, _ := reportkeys.Apply(nil, priv.Public().(ed25519.PublicKey), reportkeys.FromMaster, now)
	b, _ := json.Marshal(map[string]any{"keys": ks})
	os.WriteFile(keysFile, b, 0o600)
	cfg := filepath.Join(dir, "none.yaml")

	var out bytes.Buffer
	if err := reportVerify([]string{"-c", cfg, "-keys", keysFile, report}, &out); err != nil || !strings.Contains(out.String(), "Verified") {
		t.Errorf("with keys: %v %s", err, out.String())
	}
	if !strings.Contains(out.String(), "tenant signalith") {
		t.Errorf("the tenant is not shown: %s", out.String())
	}
	out.Reset()
	if err := reportVerify([]string{"-c", cfg, report}, &out); !errors.Is(err, errReportUnchecked) || !strings.Contains(out.String(), "claiming report key") || strings.Contains(out.String(), "Verified") {
		t.Errorf("without keys: %v %s", err, out.String())
	}
	// With a key list, a report without its signature does not verify.
	out.Reset()
	if err := reportVerify([]string{"-c", cfg, "-keys", keysFile, filepath.Join(dir, "unsigned.json")}, &out); err == nil {
		t.Error("a missing file verified")
	}
	unsigned, _ := r.Sign(nil)
	uj, _ := unsigned.JSON()
	os.WriteFile(filepath.Join(dir, "unsigned.json"), uj, 0o600)
	if err := reportVerify([]string{"-c", cfg, "-keys", keysFile, filepath.Join(dir, "unsigned.json")}, &out); !errors.Is(err, errReportChanged) {
		t.Errorf("unsigned with a key list: %v", err)
	}
	// A revoked key: exit 3.
	rk, _ := reportkeys.RevokeIn(ks, ks[0].ID, "admin", "leaked", now)
	b, _ = json.Marshal(map[string]any{"keys": rk})
	os.WriteFile(keysFile, b, 0o600)
	out.Reset()
	if err := reportVerify([]string{"-c", cfg, "-keys", keysFile, report}, &out); !errors.Is(err, errReportRevoked) || reportExitCode(err) != 3 || !strings.Contains(out.String(), "REVOKED") {
		t.Errorf("revoked: %v %s", err, out.String())
	}
	// Another key's list refuses it.
	other, _, _ := ed25519.GenerateKey(nil)
	ks2, _ := reportkeys.Apply(nil, other, reportkeys.FromMaster, now)
	b, _ = json.Marshal(map[string]any{"keys": ks2})
	os.WriteFile(keysFile, b, 0o600)
	if err := reportVerify([]string{"-c", cfg, "-keys", keysFile, report}, &out); !errors.Is(err, errReportChanged) {
		t.Errorf("unknown key: %v", err)
	}
}

// Text from a report cannot drive the terminal or turn itself around.
func TestReportTextHidesControls(t *testing.T) {
	if got := reportText("CASE-1\x1b[2K\rVerified‮"); got != "CASE-1?[2K?Verified?" {
		t.Errorf("got %q", got)
	}
}
