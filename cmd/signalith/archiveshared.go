package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterarchive"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Restores with the CLI on servers that share their archives: the server
// that runs retention restores, as it would for the page, so that the
// archive list and retention agree on what was restored. -offline
// restores from the files here instead, for when no server runs.

// archiveCluster is what the CLI needs to know of the cluster to restore.
type archiveCluster struct {
	rt *shared.Runtime
	// leader names the server that runs the background jobs, "" when no
	// server that may run them sent a heartbeat lately.
	leader string
}

// openArchiveCluster returns the cluster when it shares its archives,
// nil when this server keeps them in its own files.
func openArchiveCluster(ctx context.Context, c *config.Config, cl *store.Client, errOut io.Writer) (*archiveCluster, error) {
	self, err := cluster.ReadIdentity(c.StateDir())
	if err != nil {
		// A server that never started has no cluster to ask.
		return nil, nil
	}
	x := &clusterCLI{c: c, cl: cl, log: newLogger(io.Discard), self: self, out: errOut, errOut: errOut, by: cliUser()}
	rt := x.runtime(true, "")
	b, ok := rt.Cluster().Get()
	if !ok || b.Level < shared.LevelSharedAudit {
		return nil, nil
	}
	peers, err := x.peers(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("the servers' heartbeats cannot be read: %w", err)
	}
	ac := &archiveCluster{rt: rt}
	for _, p := range peers {
		if p.Leader && p.Live {
			ac.leader = p.Name
		}
	}
	return ac, nil
}

// restore asks the server that runs retention to restore ids and follows
// the request until it is over.
func (ac *archiveCluster) restore(ctx context.Context, ids []string, keepDays int, confirm bool, out io.Writer) error {
	for _, id := range ids {
		if strings.ContainsAny(id, `/\`) || strings.HasSuffix(id, ".ndjson.gz") || strings.HasSuffix(id, ".json") {
			return fmt.Errorf("%s: name archives by ID; the server that runs retention restores them from its archive folder (or add -offline to restore this file here)", id)
		}
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	req, err := ac.rt.Requests().Submit(sctx, clusterarchive.RequestArchiveRestore, shared.TargetLeader,
		clusterarchive.ArchiveRestoreArgs{IDs: ids, KeepDays: keepDays, Confirm: confirm}, cliUser())
	cancel()
	if err != nil {
		return fmt.Errorf("could not ask the server that runs retention to restore: %w", err)
	}
	fmt.Fprintf(out, "Asked %s to restore %d archived day(s) (request %s).\n", orSomeServer(ac.leader), len(ids), req.ID)
	var last shared.Progress
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(out, "Stopped following the restore; it goes on. Follow it on the Data retention page, or with GET /api/requests/%s.\n", req.ID)
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		gctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		cur, found, err := ac.rt.Requests().Get(gctx, req.ID)
		cancel()
		if err != nil || !found {
			continue
		}
		if cur.Progress != last && cur.Progress.Total > 0 {
			last = cur.Progress
			fmt.Fprintf(out, "  %d of %d events\n", last.Done, last.Total)
		}
		if !cur.Over() {
			continue
		}
		var res clusterarchive.ArchiveRestoreResult
		_ = json.Unmarshal(cur.Result, &res)
		if cur.State == shared.RequestFailed {
			if res.Check != nil && res.Check.NeedsConfirm {
				return fmt.Errorf("%s\nRun it again with -confirm to restore anyway", res.Check.Message)
			}
			return errors.New(cur.Error)
		}
		for _, r := range res.Restores {
			fmt.Fprintf(out, "Restored %s: %d events into %s; it stays searchable until %s.\n", r.ID, r.Restored, r.Index, r.KeepUntil)
		}
		return nil
	}
}

func orSomeServer(name string) string {
	if name == "" {
		return "the server that runs retention, once one does,"
	}
	return name
}

// offlineAllowed refuses a restore from the files here while a server
// that runs retention is up, unless forced.
func (ac *archiveCluster) offlineAllowed(force bool) error {
	if ac == nil || ac.leader == "" || force {
		return nil
	}
	return fmt.Errorf("%s runs retention now, so restore through it (leave out -offline); add -force to restore from the files here anyway", ac.leader)
}
