// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/snapshots"
)

type fakeBackups struct{ st snapshots.Status }

func (f *fakeBackups) Status(context.Context, bool) *snapshots.Status {
	st := f.st
	return &st
}

// The Health page's Backups card is for admins: the scheduled snapshots,
// with a red item when they are late, and the last signalith backup of
// this server's files.
func TestHealthBackups(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	last := time.Now().Add(-72 * time.Hour).UTC()
	fake := &fakeBackups{st: snapshots.Status{On: true, State: snapshots.StateLate, Policy: "signalith-daily", LastSuccess: &last,
		Problem: "The last successful snapshot was taken more than two scheduled periods ago."}}
	ts, srv := newRoleServer(t)
	srv.Snapshots = fake

	_, body := do(t, ts, "GET", "/api/health", "", true)
	b, _ := body["backup"].(map[string]any)
	if b == nil || !strings.Contains(b["alert"].(string), "more than two scheduled periods") || b["files"] != nil {
		t.Fatalf("admin backup = %v", body["backup"])
	}
	if sn, _ := b["snapshots"].(map[string]any); sn["state"] != "late" || sn["policy"] != "signalith-daily" {
		t.Errorf("snapshots = %v", b["snapshots"])
	}
	_, body = doAs(t, ts, "vera", "role-password", "GET", "/api/health", "")
	if _, ok := body["backup"]; ok {
		t.Error("a viewer sees the backups")
	}

	// Snapshots going well, and a backup of the files recorded: no alert.
	fake.st = snapshots.Status{On: true, State: snapshots.StateOK}
	if err := snapshots.WriteFilesBackup(state, snapshots.FilesBackup{At: time.Now().UTC(), File: "/root/signalith-backup.zip", Files: 9}); err != nil {
		t.Fatal(err)
	}
	_, body = do(t, ts, "GET", "/api/health", "", true)
	b, _ = body["backup"].(map[string]any)
	if b == nil || b["alert"] != nil {
		t.Fatalf("backup = %v", body["backup"])
	}
	if f, _ := b["files"].(map[string]any); f["file"] != "/root/signalith-backup.zip" || f["files"] != float64(9) {
		t.Errorf("files = %v", b["files"])
	}
}
