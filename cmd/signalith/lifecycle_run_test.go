package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// signalith cluster rotate-key asks the server that runs the background
// jobs to rotate the cluster key and follows the request; draining and
// resuming that server from the Servers page runs on it.
func TestClusterKeyRotationAndDrainOnARunningServer(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	node := rs.r.node
	eventually(t, "this server runs the jobs", node.RunsJobs)
	rs.usersShared()
	eventually(t, "the server takes the shared settings", func() bool {
		srv := rs.r.srv.Load()
		return srv != nil && rs.r.shared.SharedSettings() && rs.r.shared.KeyRotation() && !rs.r.RestartStatus().InProgress
	})
	before := rs.r.shared.Hub().Keys().Active().ID()

	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out, errOut bytes.Buffer
	if err := runCluster([]string{"rotate-key", "-yes", "-c", filepath.Join(rs.dir, "signalith.yaml")}, in, &out, &errOut); err != nil {
		t.Fatalf("rotate-key: %v\n%s%s\n%s", err, out.String(), errOut.String(), rs.logs.String())
	}
	if !strings.Contains(out.String(), "Done: the key rotation finished.") || !strings.Contains(errOut.String(), "Waiting for the server that runs the background jobs") {
		t.Errorf("rotate-key:\n%s%s", out.String(), errOut.String())
	}
	eventually(t, "the server signs with the new key", func() bool {
		k := rs.r.shared.Hub().Keys().Active()
		return k != nil && k.ID() != before
	})

	// Removing a stopped server on the Servers page rotates the key once
	// more, noting it on the removed server.
	second := rs.r.shared.Hub().Keys().Active().ID()
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_gone", Name: "siem-gone", State: cluster.StateStopped, HeartbeatAt: time.Now().UTC()}
	rs.os.Put("signalith_runtime", "node:n_gone", asMap(t, hb))
	rs.usersShared()
	var removed map[string]any
	eventually(t, "siem-gone is removed", func() bool {
		code, body, err := rs.call("", "DELETE", "/api/cluster/servers/n_gone", "")
		removed = body
		return err == nil && code == http.StatusOK
	})
	if removed["rotate_skipped"] != nil {
		t.Errorf("remove: %v", removed)
	}
	eventually(t, "the key is rotated after the removal", func() bool {
		k := rs.r.shared.Hub().Keys().Active()
		return k != nil && k.ID() != second
	})
	if rm := rs.r.shared.Removed(); len(rm) != 1 || rm[0].NodeID != "n_gone" {
		t.Errorf("removed servers: %+v", rm)
	}

	// Drain this server, then resume it.
	rs.usersShared()
	code, body, err := rs.call("", "POST", "/api/cluster/servers/"+node.ID()+"/drain", "")
	if err != nil || code != http.StatusAccepted {
		t.Fatalf("drain: %d %v %v", code, body, err)
	}
	eventually(t, "the server is drained", func() bool { return node.Drained() && !node.Lease().Holding() })
	eventually(t, "its own settings keep the drain", func() bool {
		nc, ok := rs.r.shared.NodeCfg().Get()
		return ok && nc.Drained != nil
	})
	code, body, err = rs.call("", "POST", "/api/cluster/servers/"+node.ID()+"/resume", "")
	if err != nil || code != http.StatusAccepted {
		t.Fatalf("resume: %d %v %v", code, body, err)
	}
	eventually(t, "the server is resumed", func() bool {
		nc, ok := rs.r.shared.NodeCfg().Get()
		return !node.Drained() && ok && nc.Drained == nil
	})
	// The resume is logged once the request that made it ends.
	for _, want := range []string{"this server was drained", "this server was resumed"} {
		eventually(t, "the log says "+want, func() bool { return strings.Contains(rs.logs.String(), want) })
	}
}
