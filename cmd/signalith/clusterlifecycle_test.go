package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestMergeHandlersRefusesTwoForOneType(t *testing.T) {
	r := &runner{}
	hs := mergeHandlers(map[string]shared.Handler{clustercfg.RequestRestart: nil}, r.lifecycleServerHandlers())
	for _, k := range []string{clustercfg.RequestRestart, clustercfg.RequestDrain, clustercfg.RequestResume} {
		if _, ok := hs[k]; !ok {
			t.Errorf("no handler for %s", k)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("two handlers for one request type were merged")
		}
	}()
	mergeHandlers(r.lifecycleServerHandlers(), r.lifecycleServerHandlers())
}

// signalith cluster new-identity moves node.id aside and forgets the
// node key and the cluster key, on a stopped server only.
func TestNewIdentity(t *testing.T) {
	dir := t.TempDir()
	l, err := cluster.OpenLocal(dir, cluster.LocalOptions{
		Hostname:  func() (string, error) { return "siem-a", nil },
		MachineID: func() string { return "machine-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	yes := func(string) error { return nil }
	var out, errOut bytes.Buffer
	if err := newIdentity(dir, &out, &errOut, yes); !errors.Is(err, cluster.ErrRunning) {
		t.Fatalf("while running: %v", err)
	}
	l.Close()
	k, _ := shared.NewClusterKey()
	for _, p := range []string{shared.NodeKeyPath(dir), shared.ClusterKeyPath(dir, k.ID()), shared.CachePath(dir)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := newIdentity(dir, &out, &errOut, func(string) error { return errors.New("not confirmed") }); err == nil {
		t.Fatal("went on without the confirmation")
	}
	if err := newIdentity(dir, &out, &errOut, yes); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "node.id"), shared.NodeKeyPath(dir), shared.ClusterKeyPath(dir, k.ID()), shared.CachePath(dir)} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there", filepath.Base(p))
		}
	}
	if !strings.Contains(out.String(), "node.id.replaced-") {
		t.Errorf("output %q", out.String())
	}
}
