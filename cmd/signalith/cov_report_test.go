// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

// report keys and report revoke-key list and revoke the keys of a server
// on its own.
func TestReportKeysAndRevoke(t *testing.T) {
	path := sampleConfig(t, "http://127.0.0.1:1")
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)

	var out bytes.Buffer
	if err := reportKeys([]string{"-c", path}, &out); err != nil || !strings.Contains(out.String(), "No case report was signed") {
		t.Errorf("no keys: %v %s", err, out.String())
	}
	out.Reset()
	if err := reportKeys([]string{"-c", path, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var empty struct{ Keys []reportkeys.Key }
	if err := json.Unmarshal(out.Bytes(), &empty); err != nil || empty.Keys == nil || len(empty.Keys) != 0 {
		t.Errorf("empty JSON: %v %s", err, out.String())
	}
	// Revoking needs a valid key ID and a key to revoke.
	if err := reportRevoke([]string{"-c", path}, &out); err == nil || !strings.Contains(err.Error(), "Usage") {
		t.Errorf("no ID: %v", err)
	}
	if err := reportRevoke([]string{"-c", path, "not an id"}, &out); err == nil {
		t.Error("a bad ID was taken")
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	id := reportkeys.KeyID(pub)
	if err := reportRevoke([]string{"-c", path, id}, &out); err == nil || !strings.Contains(err.Error(), "keeps no report keys") {
		t.Errorf("no keys to revoke: %v", err)
	}
	f := &reportkeys.File{Path: filepath.Join(state, reportkeys.FileName)}
	if err := f.Use(context.Background(), pub, reportkeys.FromMaster, time.Now()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := reportKeys([]string{"-c", path}, &out); err != nil || !strings.Contains(out.String(), "KEY ID") || !strings.Contains(out.String(), id) {
		t.Errorf("table: %v %s", err, out.String())
	}
	out.Reset()
	if err := reportKeys([]string{"-c", path, "-json"}, &out); err != nil || !strings.Contains(out.String(), id) {
		t.Errorf("JSON: %v %s", err, out.String())
	}
	out.Reset()
	if err := reportRevoke([]string{"-c", path, "-reason", "leaked backup", id}, &out); err != nil || !strings.Contains(out.String(), "is revoked") {
		t.Errorf("revoke: %v %s", err, out.String())
	}
	ks, _ := reportkeys.Read(f.Path)
	if len(ks) != 1 || ks[0].Status() == "active" {
		t.Errorf("after revoking: %+v", ks)
	}
	// A key ID that is not in the list is refused.
	other, _, _ := ed25519.GenerateKey(nil)
	if err := reportRevoke([]string{"-c", path, reportkeys.KeyID(other)}, &out); err == nil {
		t.Error("an unknown key was revoked")
	}
	// A config file that cannot be read stops both.
	missing := filepath.Join(t.TempDir(), "none.yaml")
	if err := reportKeys([]string{"-c", missing}, &out); err == nil {
		t.Error("keys with no config")
	}
	if err := reportRevoke([]string{"-c", missing, id}, &out); err == nil {
		t.Error("revoke with no config")
	}
	// A key file that is not JSON is an error.
	os.WriteFile(f.Path, []byte("{"), 0o600)
	if err := reportKeys([]string{"-c", path}, &out); err == nil {
		t.Error("a broken key file was read")
	}
	if err := cmdReport([]string{"nope"}); err == nil {
		t.Error("unknown report command")
	}
	if err := cmdReport(nil); err == nil {
		t.Error("no report command")
	}
}
