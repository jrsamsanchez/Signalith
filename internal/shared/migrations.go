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
// housekeeping.
func (rt *Runtime) runLevelMigrations(ctx context.Context) {
	if len(rt.opts.Migrations) == 0 || rt.opts.ReadOnly || !rt.holdsLease() {
		return
	}
	if m, _ := rt.Mode(); m != ModeMember {
		return
	}
	for _, lm := range rt.opts.Migrations {
		body, ok := rt.Cluster().Get()
		if !ok || body == nil || body.Level < lm.Level || body.Migrations[lm.Name] != "" || lm.Run == nil {
			continue
		}
		if _, err := rt.Migrate(ctx, lm.Name, lm.Run); err != nil && ctx.Err() == nil {
			rt.log.Warn("could not run a migration of the cluster; trying again later", "migration", lm.Name, "err", err)
		}
	}
}

// pruneMigrations returns the records to keep of m: every record whose
// name has no version (no @), and of those named name@version only the
// newest per name, by the time recorded (the last by name on a tie or a
// time that cannot be read). The records of an index upgrade are written
// once per version, so they would otherwise pile up one per release.
func pruneMigrations(m map[string]string) map[string]string {
	out := map[string]string{}
	newest := map[string]string{}
	for key, at := range m {
		name, _, versioned := strings.Cut(key, "@")
		if !versioned {
			out[key] = at
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

// PruneMigrations removes the records of migrations an older version
// ran (see pruneMigrations), on the server running the background jobs.
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
	cdoc := rt.Cluster()
	body, ok := cdoc.Get()
	if !ok || body == nil || len(pruneMigrations(body.Migrations)) == len(body.Migrations) {
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
		kept := pruneMigrations(b.Migrations)
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
