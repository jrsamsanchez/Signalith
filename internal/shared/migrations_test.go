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
	got := pruneMigrations(m, nil)
	want := map[string]string{
		"intel-fields@1.5.0": "2026-10-01T10:00:00.5Z",
		"cases-fields@1.5.0": "2026-10-01T10:00:00Z",
		"level-9-move":       "2026-01-01T00:00:00Z",
	}
	if !maps.Equal(got, want) {
		t.Errorf("kept %v, want %v", got, want)
	}
	if len(pruneMigrations(nil, nil)) != 0 {
		t.Error("nil")
	}
	// A version still running keeps its record, though an older one was
	// written after it (the lease went back to an older server).
	got = pruneMigrations(m, func(v string) bool { return v == "1.6.0" })
	want["intel-fields@1.6.0"] = m["intel-fields@1.6.0"]
	if !maps.Equal(got, want) {
		t.Errorf("keeping 1.6.0: kept %v, want %v", got, want)
	}
}

func TestPruneMigrationsKeepsRunningVersions(t *testing.T) {
	e := newEnv(t)
	var peers peerList
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax, Version: "1.6.0"}
	old := Peer{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: LevelMax, Version: "1.5.0"}
	peers.set(self, old)
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.Peers = peers.get
		o.Version = "1.6.0"
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	ctx := context.Background()
	recs := map[string]string{
		"intel-fields@1.4.0": "2026-09-01T10:00:00Z",
		"intel-fields@1.6.0": "2026-10-01T10:00:00Z",
		"intel-fields@1.5.0": "2026-10-02T10:00:00Z",
	}
	if _, err := a.rt.Cluster().Mutate(ctx, "test", func(b *ClusterBody) error {
		b.Migrations = maps.Clone(recs)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.rt.Housekeep(ctx)
	delete(recs, "intel-fields@1.4.0")
	if _, body := clusterBody(t, e); !maps.Equal(body.Migrations, recs) {
		t.Fatalf("with 1.5.0 and 1.6.0 running: %v", body.Migrations)
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

func TestLevelMigrationsOneAtATime(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var runs atomic.Int32
	migrations := []LevelMigration{{Name: "slow", Level: 1, Run: func(context.Context) error {
		if runs.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}}}
	e := newEnv(t)
	a := e.server("siem-a", func(o *RuntimeOptions) { o.Migrations = migrations })
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		a.rt.runLevelMigrations(ctx)
		close(done)
	}()
	<-started
	if got := a.rt.MigrationBusy(); got != "level migration" {
		t.Errorf("busy while one runs: %q", got)
	}
	// A second call while one runs returns at once and does not run it
	// beside the first; the first goes round again and finds it recorded.
	a.rt.runLevelMigrations(ctx)
	close(release)
	<-done
	if runs.Load() != 1 {
		t.Errorf("ran %d times", runs.Load())
	}
	if got := a.rt.MigrationBusy(); got != "" {
		t.Errorf("busy after: %q", got)
	}
}

func TestLevelMigrationStopsWithTheLease(t *testing.T) {
	stopped, started := make(chan error, 1), make(chan struct{})
	migrations := []LevelMigration{{Name: "long", Level: 1, Run: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}}}
	e := newEnv(t)
	a := e.server("siem-a", func(o *RuntimeOptions) { o.Migrations = migrations })
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	go a.rt.runLevelMigrations(context.Background())
	<-started
	a.holds.Store(false)
	if err := <-stopped; err == nil {
		t.Error("not cancelled")
	}
	if _, body := clusterBody(t, e); body.Migrations["long"] != "" {
		t.Error("recorded a migration that was cut short")
	}
}
