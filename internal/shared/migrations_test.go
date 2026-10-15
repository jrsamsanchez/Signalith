package shared

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"
	"testing"
)

func TestPruneMigrations(t *testing.T) {
	m := map[string]string{
		"intel-fields@1.4.0":  "2026-09-01T10:00:00Z",
		"intel-fields@1.5.0":  "2026-10-01T10:00:00.5Z",
		"intel-fields@1.6.0":  "2026-10-01T10:00:00.25Z", // older, though a newer version
		"cases-fields@1.5.0":  "2026-10-01T10:00:00Z",
		"cases-fields@broken": "not a time",
		"level-9-move":        "2026-01-01T00:00:00Z",
	}
	got := pruneMigrations(m)
	want := map[string]string{
		"intel-fields@1.5.0": "2026-10-01T10:00:00.5Z",
		"cases-fields@1.5.0": "2026-10-01T10:00:00Z",
		"level-9-move":       "2026-01-01T00:00:00Z",
	}
	if !maps.Equal(got, want) {
		t.Errorf("kept %v, want %v", got, want)
	}
	if len(pruneMigrations(nil)) != 0 {
		t.Error("nil")
	}
}

func TestPruneMigrationsAtHousekeeping(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	ctx := context.Background()
	if _, err := a.rt.Cluster().Mutate(ctx, "test", func(b *ClusterBody) error {
		b.Migrations = map[string]string{"intel-fields@1.5.0": "2026-10-01T10:00:00Z", "intel-fields@1.6.0": "2026-10-02T10:00:00Z", "plain": "2026-10-01T10:00:00Z"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Only the server running the background jobs prunes.
	a.holds.Store(false)
	a.rt.Housekeep(ctx)
	if _, body := clusterBody(t, e); len(body.Migrations) != 3 {
		t.Fatalf("pruned without the lease: %v", body.Migrations)
	}
	a.holds.Store(true)
	a.rt.Housekeep(ctx)
	_, body := clusterBody(t, e)
	if !maps.Equal(body.Migrations, map[string]string{"intel-fields@1.6.0": "2026-10-02T10:00:00Z", "plain": "2026-10-01T10:00:00Z"}) {
		t.Errorf("after housekeeping: %v", body.Migrations)
	}
}

func TestLevelMigrations(t *testing.T) {
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}
	old := Peer{NodeID: "n_siem-old", Name: "siem-old", Live: true}
	var moved, flaky atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	migrations := []LevelMigration{
		{Name: "level-2-move", Level: 2, Run: func(context.Context) error { moved.Add(1); return nil }},
		{Name: "level-2-flaky", Level: 2, Run: func(context.Context) error {
			flaky.Add(1)
			if fail.Load() {
				return errors.New("OpenSearch said no")
			}
			return nil
		}},
	}
	e := newEnv(t)
	var peers peerList
	peers.set(self, old)
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.Peers = peers.get
		o.Migrations = migrations
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	wantLevel(t, e, 1)
	ctx := context.Background()
	a.rt.Housekeep(ctx)
	if moved.Load() != 0 || flaky.Load() != 0 {
		t.Fatal("a migration ran below its level")
	}

	b := e.server("siem-b", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, a.key())
		o.Peers = peers.get
		o.Migrations = migrations
	})
	b.wantMode(ModeMember)

	upgraded := old
	upgraded.LevelMax = LevelMax
	peers.set(self, upgraded)
	a.step()
	wantLevel(t, e, 2)
	if moved.Load() != 1 || flaky.Load() != 1 {
		t.Fatalf("after the raise: moved %d, flaky %d", moved.Load(), flaky.Load())
	}
	_, body := clusterBody(t, e)
	if body.Migrations["level-2-move"] == "" || body.Migrations["level-2-flaky"] != "" {
		t.Fatalf("recorded %v", body.Migrations)
	}

	// The other member does not run them: it does not hold the lease.
	b.step()
	b.rt.Housekeep(ctx)
	if moved.Load() != 1 || flaky.Load() != 1 {
		t.Fatalf("a server without the lease ran them: moved %d, flaky %d", moved.Load(), flaky.Load())
	}

	// The failed one runs again at housekeeping; the done one does not.
	fail.Store(false)
	a.rt.Housekeep(ctx)
	if moved.Load() != 1 || flaky.Load() != 2 {
		t.Fatalf("at housekeeping: moved %d, flaky %d", moved.Load(), flaky.Load())
	}
	// Once each across the cluster: the other server, now holding the
	// lease, finds them recorded.
	a.holds.Store(false)
	b.holds.Store(true)
	b.step()
	b.rt.Housekeep(ctx)
	if moved.Load() != 1 || flaky.Load() != 2 {
		t.Fatalf("ran twice: moved %d, flaky %d", moved.Load(), flaky.Load())
	}
	_, body = clusterBody(t, e)
	if body.Migrations["level-2-move"] == "" || body.Migrations["level-2-flaky"] == "" {
		t.Errorf("recorded %v", body.Migrations)
	}
}
