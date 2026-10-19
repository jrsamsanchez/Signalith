// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

func TestClusterUpgradeCheck(t *testing.T) {
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: uc\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	exited := -1
	old := exitFunc
	exitFunc = func(code int) { exited = code }
	t.Cleanup(func() { exitFunc = old })
	run := func() (upgradeVerdict, error) {
		t.Helper()
		exited = -1
		var out, errOut bytes.Buffer
		err := runCluster([]string{"upgrade-check", "-c", path, "-json"}, os.Stdin, &out, &errOut)
		var v upgradeVerdict
		if jerr := json.Unmarshal(out.Bytes(), &v); jerr != nil {
			t.Fatalf("upgrade-check -json: %v, %v\n%s%s", err, jerr, out.String(), errOut.String())
		}
		return v, err
	}

	a := clusterServerDir(t, filepath.Join(dir, "state-a"), "siem-a")
	now := time.Now().UTC()
	hbA := cluster.Heartbeat{Kind: "node", NodeID: a.NodeID, Name: "siem-a", State: cluster.StateReady, Version: "0.2.0",
		LeaderEligible: true, Leader: true, HeartbeatAt: now}
	fake.Put("uc_runtime", "node:"+a.NodeID, asMap(t, hbA))
	v, err := run()
	if err != nil || exited != -1 || !v.Single || !v.Safe {
		t.Fatalf("single server: %v, exit %d, %+v", err, exited, v)
	}

	hbB := cluster.Heartbeat{Kind: "node", NodeID: "n_b", Name: "siem-b", State: cluster.StateReady, Version: "0.2.0", LeaderEligible: true, HeartbeatAt: now}
	fake.Put("uc_runtime", "node:n_b", asMap(t, hbB))
	fake.Put("uc_runtime", "lease:jobs", asMap(t, cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: a.NodeID, HolderName: "siem-a", HolderVersion: "0.2.0"}))
	v, err = run()
	if err != nil || exited != -1 || !v.Safe || v.Single || len(v.Servers) != 2 || v.Current != "0.2.0" || !strings.Contains(v.Next, "start with siem-b") {
		t.Fatalf("two servers: %v, exit %d, %+v", err, exited, v)
	}

	hbB.Restart = &cluster.RestartStatus{Busy: true}
	fake.Put("uc_runtime", "node:n_b", asMap(t, hbB))
	v, err = run()
	if !errors.Is(err, errNotSafe) || exited != 3 || v.Safe || len(v.Blockers) != 1 || v.Blockers[0].Code != "restart_running" || v.Blockers[0].Server != "siem-b" {
		t.Fatalf("restart running: %v, exit %d, %+v", err, exited, v)
	}
}
