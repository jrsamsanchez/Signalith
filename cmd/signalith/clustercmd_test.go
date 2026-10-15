package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// clusterServerDir gives a state folder an identity, as a server's first
// start does, and makes it the one the commands use.
func clusterServerDir(t *testing.T, dir, name string) cluster.Identity {
	t.Helper()
	t.Setenv("SIGNALITH_STATE_DIR", dir)
	local, err := cluster.OpenLocal(dir, cluster.LocalOptions{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	local.Close()
	return local.Identity
}

func TestClusterCommands(t *testing.T) {
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
	run := func(input string, args ...string) (string, error) {
		t.Helper()
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		w.WriteString(input)
		w.Close()
		var out, errOut bytes.Buffer
		err = runCluster(append(args, "-c", path), in, &out, &errOut)
		return out.String() + errOut.String(), err
	}

	stateA := filepath.Join(dir, "state-a")
	a := clusterServerDir(t, stateA, "siem-a")
	out, err := run("", "status")
	if err != nil || !strings.Contains(out, "legacy_c") || !strings.Contains(out, "siem-a") {
		t.Fatalf("status before founding: %v\n%s", err, out)
	}
	// A server that may run the background jobs and is up founds by
	// itself.
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_other", Name: "siem-z", State: cluster.StateReady, LeaderEligible: true, HeartbeatAt: time.Now().UTC()}
	fake.Put("cc_runtime", "node:n_other", asMap(t, hb))
	beating := make(chan struct{})
	beat := make(chan struct{})
	go func() {
		defer close(beat)
		for {
			select {
			case <-beating:
				return
			case <-time.After(2 * time.Millisecond):
			}
			hb.HeartbeatAt = time.Now().UTC()
			fake.Put("cc_runtime", "node:n_other", asMap(t, hb))
		}
	}()
	out, err = run("", "found")
	close(beating)
	<-beat
	if err == nil || !strings.Contains(err.Error(), "siem-z is up") {
		t.Fatalf("found with a live scheduler server: %v\n%s", err, out)
	}
	hb.State = cluster.StateStopped
	fake.Put("cc_runtime", "node:n_other", asMap(t, hb))
	out, err = run("", "found", "-name", "Plant")
	if err != nil || !strings.Contains(out, `Founded cluster "Plant"`) {
		t.Fatalf("found: %v\n%s", err, out)
	}
	if _, err := run("", "found"); err == nil || !strings.Contains(err.Error(), "a cluster already") {
		t.Errorf("found again: %v", err)
	}
	out, err = run("", "status", "-json")
	var st clusterStatus
	if err != nil || json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &st) != nil {
		t.Fatalf("status -json: %v\n%s", err, out)
	}
	if st.Status.Mode != shared.ModeMember || st.Keyring[a.NodeID].AddedBy != shared.AddedByFounder || st.Status.ClusterName != "Plant" {
		t.Fatalf("status -json: %+v", st)
	}
	kid := st.Status.ClusterKID
	out, err = run("", "export")
	if err != nil || !strings.Contains(out, "id: cluster") || !strings.Contains(out, "verified: \"yes\"") || !strings.Contains(out, "name: Plant") {
		t.Fatalf("export: %v\n%s", err, out)
	}

	keyFile := filepath.Join(dir, "cluster-key.txt")
	if _, err := run("short\n", "export-key", "-o", keyFile); err == nil {
		t.Error("a short passphrase was taken")
	}
	if out, err := run("correct horse battery\n", "export-key", "-o", keyFile); err != nil {
		t.Fatalf("export-key: %v\n%s", err, out)
	}

	// Another server gets the key.
	stateB := filepath.Join(dir, "state-b")
	clusterServerDir(t, stateB, "siem-b")
	out, _ = run("", "status")
	if !strings.Contains(out, "legacy_b") {
		t.Errorf("status of a server without the key:\n%s", out)
	}
	if _, err := run("wrong passphrase\n", "import-key", keyFile); err == nil {
		t.Error("a wrong passphrase opened the key")
	}
	out, err = run("correct horse battery\n", "import-key", keyFile)
	if err != nil || !strings.Contains(out, "check out") {
		t.Fatalf("import-key: %v\n%s", err, out)
	}
	if _, err := os.Stat(shared.ClusterKeyPath(stateB, kid)); err != nil {
		t.Errorf("the key is not kept: %v", err)
	}
	if out, err := run("", "accept-restore", "-yes"); err != nil || !strings.Contains(out, "accepts") {
		t.Errorf("accept-restore: %v\n%s", err, out)
	}

	// Every copy of the key lost: a new one, and the documents signed again.
	// While this server still has the key, it is not lost.
	t.Setenv("SIGNALITH_STATE_DIR", stateA)
	if _, err := run("", "reset-key", "-yes"); err == nil || !strings.Contains(err.Error(), "still has the cluster key") {
		t.Errorf("reset-key with the key: %v", err)
	}
	for _, f := range shared.ClusterKeyFiles(stateA) {
		os.Remove(f)
	}
	if _, err := run("", "reset-key"); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Errorf("reset-key without -yes: %v", err)
	}
	out, err = run("", "reset-key", "-yes")
	if err != nil || !strings.Contains(out, "Signed") || !strings.Contains(out, "no key here") {
		t.Fatalf("reset-key: %v\n%s", err, out)
	}
	out, err = run("", "status", "-json")
	st = clusterStatus{}
	if err != nil || json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &st) != nil {
		t.Fatalf("status -json: %v\n%s", err, out)
	}
	if st.Status.Mode != shared.ModeMember || st.Status.ClusterKID == kid || len(st.Keyring) != 1 {
		t.Errorf("after reset-key: %+v", st)
	}
	if out, _ := run("", "export"); strings.Contains(out, "verified: no") {
		t.Errorf("export after reset-key:\n%s", out)
	}
	// The other server's key is the old one now. It keeps that key, so it
	// does not fall back to its own files (legacy b), even with no copy of
	// the shared settings: it is told to import the current key.
	t.Setenv("SIGNALITH_STATE_DIR", stateB)
	if out, _ := run("", "status"); !strings.Contains(out, "key_missing") || !strings.Contains(out, "import-key") {
		t.Errorf("status of a server with the old key:\n%s", out)
	}
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
