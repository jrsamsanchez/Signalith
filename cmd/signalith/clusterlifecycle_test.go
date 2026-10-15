package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
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

// Removing a server revokes its own OpenSearch certificates; without an
// OpenSearch certificate authority kept, there is nothing to revoke.
func TestRemoveRevokesOpenSearchCertificates(t *testing.T) {
	ctx := context.Background()
	cl := store.New(store.Config{URL: ostest.New(t).URL})
	if err := shared.EnsureConfig(ctx, cl, "s"); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h := shared.NewHub(shared.Options{NodeName: "a"})
	h.SetKeys(shared.NewKeySet(key))
	h.Use(cl, "s")
	osca := clusterpki.New()
	osca.Track(h)
	if err := h.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if hooks := removeHooks(nil, nil); len(hooks) != 0 {
		t.Fatalf("%d hooks without an osca", len(hooks))
	}
	hooks := removeHooks(nil, osca)
	for _, fn := range hooks {
		if err := fn(ctx, "admin", "n2"); err != nil {
			t.Fatalf("without a CA: %v", err)
		}
	}
	ca, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := osca.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	_, req, err := ospki.NewClientRequest("x")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := osca.Issue(ctx, "siem-b", "n2", req, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, fn := range hooks {
		if err := fn(ctx, "admin", "n2"); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := osca.Get(); len(b.RevokedSerials(time.Now())) != 1 {
		t.Errorf("revoked %v", b.Revoked)
	}
}

// A step after the removal that fails does not stop the others: the
// server is out of the cluster, so removeServer goes on and returns the
// failure as a warning for the caller to show after auditing the removal
// and rotating the key.
func TestRemoveServerGoesOnAfterAFailedStep(t *testing.T) {
	ctx := context.Background()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	dir := t.TempDir()
	rt := shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_a", Name: "siem-a"}})
	rt.Use(cl, "s", secrets.NewKeyring(dir))
	if err := rt.Found(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_gone", Name: "siem-gone", State: cluster.StateStopped, HeartbeatAt: time.Now().UTC()}
	if _, err := cl.Create(ctx, cluster.RuntimeIndex("s"), cluster.NodeDocID("n_gone"), hb, true); err != nil {
		t.Fatal(err)
	}
	var ran []string
	hooks := []removeHook{
		func(context.Context, string, string) error {
			ran = append(ran, "revoke")
			return errors.New("its OpenSearch certificates could not be revoked: no route")
		},
		func(context.Context, string, string) error { ran = append(ran, "next"); return nil },
	}
	rec, warnings, err := removeServer(ctx, rt, hooks, "n_gone", "siem-gone", "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if rec.NodeID != "n_gone" || len(ran) != 2 {
		t.Errorf("removed %+v, hooks ran %v", rec, ran)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "siem-gone was removed, but its OpenSearch certificates could not be revoked") {
		t.Errorf("warnings %q", warnings)
	}
	if _, _, found, _ := cl.Get(ctx, cluster.RuntimeIndex("s"), cluster.NodeDocID("n_gone")); found {
		t.Error("the heartbeat was kept")
	}
	if rm := rt.Removed(); len(rm) != 1 || rm[0].NodeID != "n_gone" {
		t.Errorf("removed list %+v", rm)
	}
	if err := removeWarnings(warnings); err == nil || !strings.Contains(err.Error(), "could not be revoked") {
		t.Errorf("the command's error: %v", err)
	}
}
