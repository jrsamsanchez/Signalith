package shared

import (
	"context"
	"errors"
	"strings"
	"time"
)

// LevelMigration is work tied to a cluster level that runs once for the
// whole cluster, on the server running the background jobs, once the
// cluster reaches Level (design 4.9: "then runs that level's migrations
// once each"). It is recorded in cluster.migrations under Name, so it is
// fenced by the job lease and never runs twice; one that fails is not
// recorded and runs again later. Run must be idempotent.
type LevelMigration struct {
	Name  string
	Level int
	Run   func(ctx context.Context) error
}

// runLevelMigrations runs, on the server holding the job lease, each
// level migration whose level the cluster has reached and that is not
// recorded yet. It is called after the level is raised and at
// housekeeping. One run goes at a time in this process: a call made while
// one runs asks it to go round once more (the level may have risen since
// it looked) and returns. A run is cut short once this server no longer
// holds the lease, so it never goes on beside the next holder's.
func (rt *Runtime) runLevelMigrations(ctx context.Context) {
	if len(rt.opts.Migrations) == 0 {
		return
	}
	rt.migAgain.Store(true)
	for rt.migAgain.Load() {
		if !rt.migMu.TryLock() {
			return
		}
		for rt.migAgain.Swap(false) {
			rt.levelMigrationsOnce(ctx)
		}
		rt.migMu.Unlock()
	}
}

// levelMigrationsOnce is one round of runLevelMigrations.
func (rt *Runtime) levelMigrationsOnce(ctx context.Context) {
	if rt.opts.ReadOnly || !rt.holdsLease() {
		return
	}
	if m, _ := rt.Mode(); m != ModeMember {
		return
	}
	ctx, stop := rt.leaseBound(ctx)
	defer stop()
	for _, lm := range rt.opts.Migrations {
		if ctx.Err() != nil {
			return
		}
		body, ok := rt.Cluster().Get()
		if !ok || body == nil || body.Level < lm.Level || body.Migrations[lm.Name] != "" || lm.Run == nil {
			continue
		}
		rt.migRunning.Store(true)
		_, err := rt.Migrate(ctx, lm.Name, lm.Run)
		rt.migRunning.Store(false)
		if err != nil && ctx.Err() == nil {
			rt.log.Warn("could not run a migration of the cluster; trying again later", "migration", lm.Name, "err", err)
		}
	}
}

// leaseCheckEvery is how often a level migration checks that this server
// still holds the job lease.
const leaseCheckEvery = time.Second

// leaseBound is ctx, cancelled as well once this server no longer holds
// the job lease.
func (rt *Runtime) leaseBound(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(leaseCheckEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !rt.holdsLease() {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// MigrationBusy names the level migration step while one runs on this
// server, "" otherwise: a hand-over of the background jobs waits for it.
func (rt *Runtime) MigrationBusy() string {
	if rt != nil && rt.migRunning.Load() {
		return "level migration"
	}
	return ""
}

// pruneMigrations returns the records to keep of m: every record whose
// name has no version (no @), every record of a version keep reports as
// still running somewhere (nil keeps none that way), and of each name
// the newest name@version, by the time recorded (the
// last by name on a tie or a time that cannot be read). The records of an
// index upgrade are written once per version, so they would otherwise
// pile up one per release; a version still running keeps its record so a
// lease that moves between versions during a rolling upgrade does not run
// its upgrade again each time.
func pruneMigrations(m map[string]string, keep func(version string) bool) map[string]string {
	out := map[string]string{}
	newest := map[string]string{}
	for key, at := range m {
		name, version, versioned := strings.Cut(key, "@")
		if !versioned || keep != nil && keep(version) {
			out[key] = at
		}
		if !versioned {
			continue
		}
		cur, ok := newest[name]
		if !ok || newerRecord(key, at, cur, m[cur]) {
			newest[name] = key
		}
	}
	for _, key := range newest {
		out[key] = m[key]
	}
	return out
}

// newerRecord reports whether record a, written at atA, is newer than b,
// written at atB.
func newerRecord(a, atA, b, atB string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, atA)
	tb, errB := time.Parse(time.RFC3339Nano, atB)
	if errA == nil && errB == nil && !ta.Equal(tb) {
		return ta.After(tb)
	}
	if (errA == nil) != (errB == nil) {
		return errA == nil
	}
	return a > b
}

// runningVersions reports whether a version still runs: this server's,
// or that of a server seen within LevelSeen. known is false while the
// servers are not known yet.
func (rt *Runtime) runningVersions() (keep func(string) bool, known bool) {
	versions := map[string]bool{}
	if rt.opts.Version != "" {
		versions[rt.opts.Version] = true
	}
	if rt.opts.Peers != nil {
		peers, seen := rt.peersSeen()
		if !seen {
			return nil, false
		}
		for _, p := range peers {
			if p.Version != "" && (p.Live || p.SeenAgo < LevelSeen) {
				versions[p.Version] = true
			}
		}
	}
	return func(v string) bool { return versions[v] }, true
}

// PruneMigrations removes the records of migrations an older version
// ran that no server seen lately runs (see pruneMigrations), on the server running the background jobs.
// The cluster document is written only when there is something to
// remove. A version that is installed again runs its migration once more,
// which is harmless: they are idempotent.
func (rt *Runtime) PruneMigrations(ctx context.Context) {
	if rt.opts.ReadOnly || !rt.holdsLease() {
		return
	}
	if m, _ := rt.Mode(); m != ModeMember {
		return
	}
	keep, known := rt.runningVersions()
	if !known {
		return
	}
	cdoc := rt.Cluster()
	body, ok := cdoc.Get()
	if !ok || body == nil || len(pruneMigrations(body.Migrations, keep)) == len(body.Migrations) {
		return
	}
	if check := rt.opts.LeaseCheck; check != nil {
		if err := check(ctx); err != nil {
			return
		}
	}
	errNothing := errors.New("nothing to prune")
	var removed int
	_, err := cdoc.Mutate(ctx, "signalith", func(b *ClusterBody) error {
		kept := pruneMigrations(b.Migrations, keep)
		if len(kept) == len(b.Migrations) {
			return errNothing
		}
		removed = len(b.Migrations) - len(kept)
		b.Migrations = kept
		return nil
	})
	switch {
	case err == nil:
		rt.log.Info("removed the records of migrations older versions ran", "records", removed)
	case !errors.Is(err, errNothing):
		rt.log.Debug("could not remove old migration records", "err", err)
	}
}
