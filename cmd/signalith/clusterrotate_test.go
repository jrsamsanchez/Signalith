// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// After the running server rotated the cluster key, signalith cluster
// remove on it works with the new key it keeps in the state folder, even
// while its copy of the shared settings (cache.enc) is still one signed
// with the old key.
func TestClusterRemoveAfterRotateKey(t *testing.T) {
	ctx := context.Background()
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: cc\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := cliWatch
	cliWatch = 10 * time.Millisecond
	t.Cleanup(func() { cliWatch = old })
	run := func(args ...string) (string, error) {
		t.Helper()
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		w.Close()
		var out, errOut bytes.Buffer
		err = runCluster(append(args, "-c", path), in, &out, &errOut)
		return out.String() + errOut.String(), err
	}

	stateA := filepath.Join(dir, "state-a")
	a := clusterServerDir(t, stateA, "siem-a")
	if out, err := run("found", "-name", "Plant"); err != nil {
		t.Fatalf("found: %v\n%s", err, out)
	}
	// Before the rotation, the CLI writes cache.enc as a server would.
	if out, err := run("status"); err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}

	// The running server, with the same state folder and master key,
	// rotates the cluster key.
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cl := store.New(store.Config{URL: fake.URL})
	srv := shared.NewRuntime(shared.RuntimeOptions{StateDir: stateA, Self: shared.Self{NodeID: a.NodeID, Name: a.Name}})
	srv.Use(cl, "cc", c.Keyring())
	sctx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	srv.Start(sctx)
	if err := srv.FlushCache(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(shared.CachePath(stateA)); err != nil {
		t.Fatalf("no cache.enc: %v", err)
	}
	if m, why := srv.Mode(); m != shared.ModeMember {
		t.Fatalf("server mode %v (%s)", m, why)
	}
	from := srv.Hub().Keys().Active().ID()
	res, err := srv.RotateKey(ctx, shared.RotateOptions{By: "admin", Reason: "rotate-key", Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.KID == from {
		t.Fatalf("rotated to the same key %s", res.KID)
	}
	if _, err := os.Stat(shared.ClusterKeyPath(stateA, res.KID)); err != nil {
		t.Fatalf("the new key is not in the state folder: %v", err)
	}

	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_gone", Name: "siem-gone", State: cluster.StateStopped, HeartbeatAt: time.Now().Add(-time.Hour).UTC()}
	fake.Put("cc_runtime", "node:n_gone", asMap(t, hb))
	out, err := run("remove", "-yes", "-no-rotate", "siem-gone")
	if err != nil || !strings.Contains(out, "Removed siem-gone") {
		t.Fatalf("remove after rotate-key: %v\n%s", err, out)
	}
	// The command signed its changes with the new key: the server takes
	// them.
	eventually(t, "the server sees the removal", func() bool {
		srv.Kick()
		m, _ := srv.Mode()
		rm := srv.Removed()
		return m == shared.ModeMember && len(rm) == 1 && rm[0].NodeID == "n_gone"
	})
}
