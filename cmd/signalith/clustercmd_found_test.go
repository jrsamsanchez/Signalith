package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestClusterCommandsOnAFoundedCluster(t *testing.T) {
	fc := newFoundedCluster(t, nil)
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_other", Name: "siem-z", State: cluster.StateStopped, HeartbeatAt: time.Now().UTC()}
	fc.fake.Put("cc_runtime", "node:n_other", asMap(t, hb))

	out, err := fc.run("", "tls")
	if err != nil || !strings.Contains(out, "Certificate authority:  none chosen yet") || !strings.Contains(out, "siem-z") {
		t.Errorf("tls: %v\n%s", err, out)
	}
	out, err = fc.run("", "tls", "-json")
	if err != nil || !strings.Contains(out, `"name": "siem-z"`) || !strings.Contains(out, `"published": false`) {
		t.Errorf("tls -json: %v\n%s", err, out)
	}
	if _, err := fc.run("", "tls", "bogus"); err == nil || !strings.Contains(err.Error(), "usage: signalith cluster tls") {
		t.Errorf("tls bogus: %v", err)
	}
	out, err = fc.run("", "upgrade-check")
	if err != nil || !strings.Contains(out, "Safe to upgrade the next server.") || !strings.Contains(out, "siem-z is offline") {
		t.Errorf("upgrade-check: %v\n%s", err, out)
	}
	out, err = fc.run("", "upgrade-check", "-json")
	if err != nil || !strings.Contains(out, `"safe": true`) || !strings.Contains(out, `"code": "offline"`) {
		t.Errorf("upgrade-check -json: %v\n%s", err, out)
	}
	// The fake OpenSearch has no sign-in, so no server can be added.
	if _, err := fc.run("", "token", "-url", "https://siem.example.test:9000"); err == nil || !strings.Contains(err.Error(), "security turned on") {
		t.Errorf("token: %v", err)
	}
	if _, err := fc.run("", "token", "-revoke", "jt_nothing"); err == nil || !strings.Contains(err.Error(), "there is no join token jt_nothing") {
		t.Errorf("token -revoke: %v", err)
	}
	if out, err := fc.run("", "approve"); err != nil || !strings.Contains(out, "No server waits for approval.") {
		t.Errorf("approve: %v\n%s", err, out)
	}
	if _, err := fc.run("", "import", "-from-cache"); err == nil || !strings.Contains(err.Error(), "keeps no copy of the shared settings") {
		t.Errorf("import -from-cache: %v", err)
	}
	if out, err := fc.run("", "export", "-settings"); err != nil || !strings.Contains(out, "# Settings shared by the servers of this cluster, exported from siem-a") ||
		!strings.Contains(out, "name: Plant") {
		t.Errorf("export -settings: %v\n%s", err, out)
	}

	// Removing servers.
	if _, err := fc.run("", "remove", "siem-nobody"); err == nil || !strings.Contains(err.Error(), `no server is named "siem-nobody"`) {
		t.Errorf("remove an unknown server: %v", err)
	}
	if _, err := fc.run("", "remove", "siem-a"); err == nil || !strings.Contains(err.Error(), "run signalith cluster leave on it") {
		t.Errorf("remove this server: %v", err)
	}
	if _, err := fc.run("", "remove", "siem-z"); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("remove without -yes: %v", err)
	}
	live := hb
	live.Name, live.NodeID, live.State = "siem-live", "n_live", cluster.StateReady
	fc.fake.Put("cc_runtime", "node:n_live", asMap(t, live))
	if _, err := fc.run("", "remove", "-yes", "siem-live"); err == nil || !strings.Contains(err.Error(), "drain it on the Servers page") {
		t.Errorf("remove a running server: %v", err)
	}
	out, err = fc.run("", "remove", "-yes", "-no-rotate", "siem-z")
	if err != nil || !strings.Contains(out, "Removed siem-z from the cluster.") || !strings.Contains(out, "The cluster key was not rotated, so siem-z's copy") {
		t.Errorf("remove: %v\n%s", err, out)
	}
	if fc.fake.Source("cc_runtime", "node:n_other") != nil {
		t.Error("the removed server's heartbeat is still there")
	}

	if _, err := fc.run("", "rotate-key"); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("rotate-key without -yes: %v", err)
	}
	if _, err := fc.run("", "leave"); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("leave without -yes: %v", err)
	}
	if _, err := fc.run("", "leave", "-yes", "-no-rotate"); err == nil || !strings.Contains(err.Error(), "last server") {
		t.Errorf("leave of the last server: %v", err)
	}
}

// A second server gets the cluster key, then leaves the cluster again.
func TestClusterLeave(t *testing.T) {
	fc := newFoundedCluster(t, nil)
	keyFile := filepath.Join(fc.dir, "cluster-key.txt")
	if out, err := fc.run("correct horse battery\n", "export-key", "-o", keyFile); err != nil {
		t.Fatalf("export-key: %v\n%s", err, out)
	}
	stateB := filepath.Join(fc.dir, "state-b")
	b := clusterServerDir(t, stateB, "siem-b")
	allowUnsecured(t)
	if out, err := fc.run("correct horse battery\n", "import-key", keyFile); err != nil {
		t.Fatalf("import-key: %v\n%s", err, out)
	}
	keys := shared.ClusterKeyFiles(stateB)
	if len(keys) == 0 {
		t.Fatal("siem-b keeps no cluster key")
	}
	out, err := fc.run("", "leave", "-yes")
	if err != nil || !strings.Contains(out, "siem-b left the cluster and deleted its copy of the cluster key.") ||
		!strings.Contains(out, "rotates the cluster key now (request ") {
		t.Fatalf("leave: %v\n%s", err, out)
	}
	for _, k := range keys {
		if _, err := os.Stat(k); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", k, err)
		}
	}
	// siem-a no longer lists siem-b in the keyring.
	t.Setenv("SIGNALITH_STATE_DIR", fc.state)
	out, err = fc.run("", "status")
	if err != nil || !strings.Contains(out, "siem-a  ") || strings.Contains(out, "siem-b  "+b.NodeID) {
		t.Errorf("status after siem-b left: %v\n%s", err, out)
	}
}
