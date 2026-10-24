// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/snapshots"
)

// TestScheduledSnapshots writes, reads and deletes Signalith's snapshot
// management policy against a real OpenSearch, as the server that runs
// the background jobs does, and checks the Health page's status. It needs
// a snapshot repository Signalith may use, registered beforehand, named
// by SIGNALITH_TEST_SNAPSHOT_REPO: the policy runs only in the small
// hours, so it takes no snapshot during the test.
func TestScheduledSnapshots(t *testing.T) {
	repo := os.Getenv("SIGNALITH_TEST_SNAPSHOT_REPO")
	if repo == "" {
		t.Skip("SIGNALITH_TEST_SNAPSHOT_REPO not set")
	}
	cl, _, prefix := setup(t)
	ctx := context.Background()
	name := snapshots.PolicyName(prefix)
	t.Cleanup(func() { _ = cl.Do(ctx, http.MethodDelete, "/_plugins/_sm/policies/"+name, nil, nil) })
	set := snapshots.Settings{On: true, Repository: "no-such-repository", TimeZone: "Europe/Berlin", Keep: 3}
	fenced := 0
	m := &snapshots.Manager{Client: cl, Prefix: prefix, Settings: func() snapshots.Settings { return set },
		Fence: func(context.Context) error { fenced++; return nil }}

	res, err := m.Sync(ctx)
	if err != nil || !strings.Contains(res.Problem, "no snapshot repository named no-such-repository") || fenced != 0 {
		t.Fatalf("missing repository: %+v, %v", res, err)
	}
	set.Repository = repo
	if res, err = m.Sync(ctx); err != nil || res.Action != "created" || res.Problem != "" {
		t.Fatalf("create: %+v, %v", res, err)
	}
	if res, err = m.Sync(ctx); err != nil || res.Action != "" {
		t.Fatalf("unchanged: %+v, %v", res, err)
	}
	set.Every, set.Keep = "12h", 5
	if res, err = m.Sync(ctx); err != nil || res.Action != "updated" {
		t.Fatalf("update: %+v, %v", res, err)
	}
	var got struct {
		Policy struct {
			Creation struct {
				Schedule struct {
					Cron struct {
						Expression string `json:"expression"`
						TimeZone   string `json:"timezone"`
					} `json:"cron"`
				} `json:"schedule"`
			} `json:"creation"`
			SnapshotConfig map[string]any `json:"snapshot_config"`
		} `json:"sm_policy"`
	}
	if err := cl.Do(ctx, http.MethodGet, "/_plugins/_sm/policies/"+name, nil, &got); err != nil {
		t.Fatal(err)
	}
	if c := got.Policy.Creation.Schedule.Cron; c.Expression != "30 2,14 * * *" || c.TimeZone != "Europe/Berlin" ||
		got.Policy.SnapshotConfig["indices"] != snapshots.Indices(prefix) || got.Policy.SnapshotConfig["include_global_state"] != "false" {
		t.Errorf("policy: %+v", got.Policy)
	}
	st := m.Status(ctx, true)
	if st.State != snapshots.StateWaiting || st.Pending || st.Next == nil || st.Next.Before(time.Now()) || st.Kept != 0 {
		t.Errorf("status: %+v", st)
	}

	set.On = false
	if res, err = m.Sync(ctx); err != nil || res.Action != "deleted" {
		t.Fatalf("off: %+v, %v", res, err)
	}
	if st := m.Status(ctx, true); st.State != snapshots.StateOff {
		t.Errorf("off: %+v", st)
	}
}
