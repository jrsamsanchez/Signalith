// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package integration

// A single server wiped and brought back with the product's own backup
// (docs/backup.md): `signalith backup` of its files while it runs, a
// snapshot of its OpenSearch indices, then the state folder and the
// indices deleted, and `signalith restore` with the master key, the
// snapshot restored and `signalith cluster accept-restore`. The events,
// the user added, the setting changed and the HTTPS certificate authority
// all come back, and the user signs in.
//
// Against a real OpenSearch the snapshot is taken and restored with the
// Docker quick start's deploy/docker/opensearch/snapshot.sh, run through
// $COMPOSE as the integration CI job sets it (Signalith's own OpenSearch
// certificate may not take snapshots). Against the in-memory fake,
// ostest's TakeSnapshot and RestoreSnapshot stand in for it.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
)

const backupToken = "backup-test-ingest-token-0123456789"

// osSnapshot snapshots the harness's indices and restores them.
type osSnapshot interface {
	take(t *testing.T)
	restore(t *testing.T)
}

// fakeSnapshot is a snapshot of the in-memory fake.
type fakeSnapshot struct {
	h    *clusterHarness
	snap *ostest.Snapshot
}

func (f *fakeSnapshot) take(t *testing.T) {
	f.snap = f.h.fake.TakeSnapshot(f.h.prefix + "*")
}

func (f *fakeSnapshot) restore(t *testing.T) {
	f.h.fake.RestoreSnapshot(f.snap)
}

// composeSnapshot runs the Docker quick start's snapshot.sh in its
// OpenSearch container, limited to the harness's indices.
type composeSnapshot struct {
	h       *clusterHarness
	compose string
	name    string
}

func (c *composeSnapshot) run(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// The prefix and the arguments go in as sh's own arguments, not into
	// the command text.
	script := c.compose + ` exec -T -e SIGNALITH_INDEX_PREFIX="$1" opensearch sh snapshot.sh "$2" ${3:+"$3"}`
	cmd := exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh", c.h.prefix}, args...)...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("snapshot.sh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (c *composeSnapshot) take(t *testing.T) {
	t.Helper()
	c.run(t, "create", c.name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		script := c.compose + ` exec -T -e SIGNALITH_INDEX_PREFIX="$1" opensearch sh snapshot.sh delete "$2"`
		cmd := exec.CommandContext(ctx, "sh", "-c", script, "sh", c.h.prefix, c.name)
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("could not delete snapshot %s: %v\n%s", c.name, err, out)
		}
	})
}

func (c *composeSnapshot) restore(t *testing.T) {
	t.Helper()
	if out := c.run(t, "restore", c.name); !strings.Contains(out, "Done.") {
		t.Fatalf("snapshot.sh restore did not finish:\n%s", out)
	}
}

// snapshotter is how this run snapshots OpenSearch; it skips the test
// when there is no way to, except in CI.
func (h *clusterHarness) snapshotter(t *testing.T) osSnapshot {
	t.Helper()
	if h.fake != nil {
		return &fakeSnapshot{h: h}
	}
	compose := os.Getenv("COMPOSE")
	if compose == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("COMPOSE is not set: in CI this test snapshots OpenSearch with the Docker quick start's snapshot.sh")
		}
		t.Skip("a real OpenSearch needs COMPOSE (the docker compose command of the quick start that runs it) to take a snapshot")
	}
	return &composeSnapshot{h: h, compose: compose, name: h.prefix + "-backup"}
}

// eventCount refreshes the harness's event indices and counts their
// documents.
func (h *clusterHarness) eventCount(t *testing.T) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := h.prefix + "-*"
	if err := h.os.Do(ctx, http.MethodPost, "/"+events+"/_refresh?allow_no_indices=true", nil, nil); err != nil {
		t.Fatal(err)
	}
	var count struct {
		Count int `json:"count"`
	}
	if err := h.os.Do(ctx, http.MethodGet, "/"+events+"/_count?allow_no_indices=true", nil, &count); err != nil {
		t.Fatal(err)
	}
	return count.Count
}

// wipeIndices deletes every index of the harness's prefix, as a lost
// OpenSearch has none.
func (h *clusterHarness) wipeIndices(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names, err := h.os.ListIndices(ctx, h.prefix+"-*,"+h.prefix+"_*")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("the server made no indices to wipe")
	}
	for _, n := range names {
		if err := h.os.DeleteIndex(ctx, n); err != nil {
			t.Fatalf("deleting %s: %v", n, err)
		}
	}
	if left, _ := h.os.ListIndices(ctx, h.prefix+"-*,"+h.prefix+"_*"); len(left) != 0 {
		t.Fatalf("indices left after the wipe: %v", left)
	}
}

// ingest sends n events to the server's /api/ingest, dated a minute ago.
func (s *testServer) ingest(t *testing.T, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"log":%q}`, syslogTime(time.Now().Add(-time.Minute))+
			fmt.Sprintf(" web1 sshd[%d]: Failed password for backuptest from 192.0.2.88 port %d ssh2", 100+i, 4000+i))
	}
	b.WriteString("]")
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/api/ingest", s.port), strings.NewReader(b.String()))
	req.Header.Set("Authorization", "Bearer "+backupToken)
	req.Header.Set("X-Signalith-Tag", "linux.auth")
	resp, err := s.api.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ingest: %d %s", resp.StatusCode, out)
	}
}

func TestBackupWipeAndRestore(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	snap := h.snapshotter(t)
	// One server on its own, as installed: no cluster key handed to it,
	// so the keys it makes live in its state folder.
	opts := serverOptions{noKey: true, yaml: "ingest:\n  tokens: [" + backupToken + "]\n"}
	a := h.add("siem-a", opts)
	freshConfig, err := os.ReadFile(filepath.Join(a.dir, "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The ingest token encrypted with a master key, which the restore
	// must bring back for the token to work again.
	if out, err := a.cli("", "secrets", "encrypt"); err != nil {
		t.Fatalf("signalith secrets encrypt: %v\n%s", err, out)
	}
	a.start()
	waitUntil(t, 90*time.Second, "siem-a founds its cluster", func() bool { return a.mode() == "member" })

	const sent = 5
	a.ingest(t, sent)
	waitUntil(t, 60*time.Second, "the events are stored", func() bool { return h.eventCount(t) >= sent })

	userPass := "restored-" + config.RandomToken(12)
	a.addUser("backupuser", "analyst", userPass)
	if c, code := a.signIn("backupuser", userPass); c == nil {
		t.Fatalf("backupuser cannot sign in before the backup: %d", code)
	}
	a.saveSettings("", map[string]any{"auth.session_timeout": "45m"})
	waitUntil(t, 30*time.Second, "the setting is saved", func() bool {
		v, ok := a.settings()
		val, _, found := v.field("auth.session_timeout")
		return ok && found && val == "45m"
	})
	caBefore, err := os.ReadFile(filepath.Join(a.dir, "tls", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}

	// Signalith's files while it runs, the master key in a file of its own.
	backups := filepath.Join(h.root, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(backups, "signalith-backup.zip")
	keyPath := filepath.Join(backups, "signalith-backup.master-key.zip")
	if out, err := a.cli("", "backup", "-o", zipPath); err != nil {
		t.Fatalf("signalith backup: %v\n%s", err, out)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("no master key file next to the backup: %v", err)
	}

	// Stopped, so nothing changes between the snapshot and the wipe.
	stopGraceful(a)
	stored := h.eventCount(t)
	snap.take(t)

	// The install is lost: its state folder and its indices.
	if b, err := os.ReadFile(a.logPath()); err == nil {
		_ = os.WriteFile(filepath.Join(h.root, "siem-a-before-wipe.log"), b, 0o600)
	}
	if err := os.RemoveAll(a.dir); err != nil {
		t.Fatal(err)
	}
	h.wipeIndices(t)

	// A new install in the same place: its config file and nothing else.
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, "signalith.yaml"), freshConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	snap.restore(t)
	if got := h.eventCount(t); got != stored {
		t.Fatalf("%d events after the snapshot was restored, %d before", got, stored)
	}
	out, err := a.cli("", "restore", "-yes", "-master-key", keyPath, zipPath)
	if err != nil {
		t.Fatalf("signalith restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Restored ") {
		t.Fatalf("signalith restore said:\n%s", out)
	}

	a.start()
	if out, err := a.cli("", "cluster", "accept-restore", "-yes"); err != nil {
		t.Fatalf("signalith cluster accept-restore: %v\n%s", err, out)
	}

	caAfter, err := os.ReadFile(filepath.Join(a.dir, "tls", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(caBefore, caAfter) {
		t.Error("the HTTPS certificate authority is not the one backed up")
	}
	if got := h.eventCount(t); got < stored {
		t.Errorf("%d events after the restore, %d before", got, stored)
	}
	// The encrypted ingest token works again: the master key is back.
	a.ingest(t, 1)
	waitUntil(t, 60*time.Second, "an event sent after the restore is stored", func() bool { return h.eventCount(t) >= stored+1 })
	if m := a.mode(); m != "member" {
		t.Errorf("siem-a is %q after the restore, want member", m)
	}
	if !a.hasUser("backupuser") {
		t.Error("the Users page does not list backupuser after the restore")
	}
	waitUntil(t, 30*time.Second, "backupuser signs in after the restore", func() bool {
		c, _ := a.signIn("backupuser", userPass)
		return c != nil && a.me(c) == http.StatusOK
	})
	if c, code := a.signIn("backupuser", "not-"+userPass); c != nil || code == http.StatusOK {
		t.Errorf("a wrong password signs in after the restore: %d", code)
	}
	if code := a.call(http.MethodGet, "/api/me", nil, nil); code != http.StatusOK {
		t.Errorf("the built-in admin after the restore: %d", code)
	}
	v, ok := a.settings()
	val, _, found := v.field("auth.session_timeout")
	if !ok || !found || val != "45m" {
		t.Errorf("auth.session_timeout after the restore: %v (found %v, answered %v), want 45m", val, found, ok)
	}
}
