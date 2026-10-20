// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

// TestRetentionColdStorage moves a day to cold storage and back out of
// it against a real OpenSearch. It needs a node that mounts searchable
// snapshots (the warm role on OpenSearch 3) and a folder OpenSearch may
// keep snapshots in (path.repo), named by SIGNALITH_TEST_COLD_PATH.
func TestRetentionColdStorage(t *testing.T) {
	repoPath := os.Getenv("SIGNALITH_TEST_COLD_PATH")
	if repoPath == "" {
		t.Skip("SIGNALITH_TEST_COLD_PATH not set")
	}
	cl, _, prefix := setup(t)
	ctx := context.Background()
	repo := retention.ColdRepository(prefix)
	if err := cl.Do(ctx, http.MethodPut, "/_snapshot/"+repo, map[string]any{
		"type": "fs", "settings": map[string]any{"location": filepath.Join(repoPath, prefix)},
	}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Do(ctx, http.MethodDelete, "/_snapshot/"+repo, nil, nil) })
	ros := retention.NewOpenSearch(cl)
	ros.Poll = 200 * time.Millisecond
	st, err := ros.ColdState(ctx, repo, prefix)
	if err != nil || !st.Registered || st.Type != "fs" {
		t.Fatalf("cold state = %+v, %v", st, err)
	}
	if !st.Mountable {
		t.Skip("no OpenSearch node mounts searchable snapshots")
	}

	now := time.Now().UTC()
	day := retention.IndexName(prefix, "endpoint", now.AddDate(0, 0, -40))
	addDay(t, cl, day, 321)
	off := false
	mgr := &retention.Manager{
		Cluster: ros, Prefix: prefix,
		Config: retention.Config{Days: 90, Guard: &retention.Guard{Enabled: &off},
			Policies: map[string]retention.Policy{"endpoint": {KeepDays: 60, ColdAfterDays: 30, Archive: true}}},
		Store:       retention.NewStore(filepath.Join(t.TempDir(), "retention.yaml")),
		Archive:     &retention.Archive{Dir: filepath.Join(t.TempDir(), "archive")},
		HistoryFile: filepath.Join(t.TempDir(), "history.json"),
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	run, err := mgr.Run(ctx, retention.TriggerManual, "test")
	if err != nil || run.Cold != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	ix := infoOf(t, ros, day)
	name := retention.ColdSnapshotName(day, ix.UUID)
	if ix.Cold == nil || ix.Cold.Repository != repo || ix.Docs != 321 || !ix.WriteBlocked {
		t.Fatalf("after the move: %+v (snapshot %s)", ix, name)
	}
	var cnt struct {
		Count int64 `json:"count"`
	}
	if err := cl.Do(ctx, http.MethodGet, "/"+prefix+"-*/_count?q=user:user3", nil, &cnt); err != nil || cnt.Count != 46 {
		t.Errorf("search across the cold day: %d, %v", cnt.Count, err)
	}
	st, _ = ros.ColdState(ctx, repo, prefix)
	if len(st.Snapshots) != 1 || st.Snapshots[0].Index != day || st.Snapshots[0].Name != ix.Cold.Snapshot {
		t.Errorf("snapshots = %+v", st.Snapshots)
	}

	// Past keep_days: archived from the mounted index, then the index and
	// its snapshot are deleted.
	mgr.Now = func() time.Time { return now.AddDate(0, 0, 25) }
	run, err = mgr.Run(ctx, retention.TriggerManual, "test")
	if err != nil || run.Archived != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	if ixs, _ := ros.Indices(ctx, day); len(ixs) != 0 {
		t.Errorf("index left: %+v", ixs)
	}
	if st, _ := ros.ColdState(ctx, repo, prefix); len(st.Snapshots) != 0 {
		t.Errorf("snapshots left: %+v", st.Snapshots)
	}
	if man, err := mgr.Archive.Get(day); err != nil || man.Docs != 321 {
		t.Errorf("archive = %+v, %v", man, err)
	}
}
