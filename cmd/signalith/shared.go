package main

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The shared configuration: settings every server uses alike, kept in
// OpenSearch (<prefix>_config) and signed with the cluster key. Like the
// node, its runtime belongs to the process, so a restart in place keeps
// its watcher, its copy of the settings and cache.enc, and only points it
// at the new OpenSearch client.
//
// Besides the cluster document, the keyring, the cluster key and the
// requests, a member takes the threat intel feeds and the retention
// policies from it (see sharedcontent.go); other servers keep using their
// own files.

// clusterKeyFileEnv names a file holding the cluster key: a server that
// has it joins the cluster (or founds it with that key) by itself.
const clusterKeyFileEnv = "SIGNALITH_CLUSTER_KEY_FILE"

// openShared returns this server's runtime of the shared configuration,
// which asks the node whether it runs the background jobs (only the one
// that does founds the cluster) and about the other servers, and the
// link of its content to the components.
func openShared(c *config.Config, node *cluster.Node, log *slog.Logger) (*shared.Runtime, *sharedContent) {
	ct := newSharedContent(c, node, log)
	rt := shared.NewRuntime(shared.RuntimeOptions{
		StateDir:   c.StateDir(),
		Self:       shared.Self{NodeID: node.ID(), Name: node.Name()},
		KeyFile:    os.Getenv(clusterKeyFileEnv),
		HoldsLease: node.RunsJobs,
		LeaseCheck: node.Check,
		LeaseEpoch: node.Lease().Epoch,
		Peers:      func() []shared.Peer { return peersOf(node.Status()) },
		Content:    ct.track,
		Importers:  clustercfg.Importers(ct.docs, ct.files()),
		Log:        log,
	})
	ct.rt.Store(rt)
	ct.users.follow(rt)
	return rt, ct
}

// peersOf lists the servers as the node sees them.
func peersOf(st cluster.Status) []shared.Peer {
	out := make([]shared.Peer, 0, len(st.Servers))
	for _, s := range st.Servers {
		p := shared.Peer{NodeID: s.NodeID, Name: s.Name, Leader: s.Jobs == "runs",
			Live: s.State != cluster.StateOffline && s.State != cluster.StateStopped}
		if s.Detail != nil {
			p.Eligible, p.MaxRev = s.Detail.LeaderEligible, s.Detail.MaxRev
			p.LevelMax, p.Users = s.Detail.LevelMax, s.Detail.FilesFingerprint.Users
		}
		if s.SeenAgo != nil {
			p.SeenAgo = *s.SeenAgo
		}
		out = append(out, p)
	}
	return out
}

// sharedStatus is the runtime's status as the heartbeat carries it. A
// server that has just founded or joined the cluster says it is a member
// only once its components take their content from the shared settings:
// until then (the founder still moves its files into OpenSearch, or the
// restart in place that followShared asks for has not switched the
// components yet) its API still answers from its own files, refusing,
// for example, a feed added on a server that does not run the background
// jobs, so it reports itself as starting.
func sharedStatus(rt *shared.Runtime, ct *sharedContent) cluster.SharedStatus {
	st := rt.Status()
	if ct != nil && !st.Mode.Legacy() && st.Mode != shared.ModeImporting && !ct.on.Load() {
		st.Mode = shared.ModeStarting
	}
	return cluster.SharedStatus{Mode: string(st.Mode), ClusterKID: st.ClusterKID, ConfigSeq: max(st.ConfigSeq, 0), MaxRev: st.MaxRev,
		NeedsUpgrade: st.NeedsUpgrade, Tamper: st.Tamper, LevelMin: st.LevelMin, LevelMax: st.LevelMax, NotEligible: st.NotEligible,
		SettingsDrift: ct.settingsDrift(), SettingsRev: ct.settingsRev()}
}

// useShared points the runtime at this start's OpenSearch client, with
// the master key of its config, before the components are built (whether
// they take their content from the shared settings depends on what it
// finds) and before the node, which reads from it whether this server may
// run the background jobs. It reports whether the components take their
// content from the shared settings.
func useShared(rt *shared.Runtime, ct *sharedContent, c *config.Config, cl *store.Client) bool {
	if rt == nil {
		return false
	}
	ct.use(c, cl)
	rt.Use(cl, c.OpenSearch.IndexPrefix, c.Keyring())
	on := ct != nil && rt.SharedContent()
	if ct != nil {
		ct.on.Store(on)
	}
	return on
}

// requestsJob runs the requests for the server that runs the background
// jobs with handlers; requests a later version queues wait for a server
// that knows them.
func requestsJob(rt *shared.Runtime, handlers map[string]shared.Handler) cluster.Job {
	return cluster.Job{Name: "requests", Run: func(ctx context.Context) {
		rt.RunRequests(ctx, handlers)
	}}
}

// clusterUpgrade runs an index upgrade (new fields, filled values) once
// for the whole cluster when this server is a member, recorded in the
// cluster document under name and this version; otherwise, and in a
// build without a version, at each takeover as before. Doing it again is
// harmless, so a lost record only costs time.
func clusterUpgrade(rt *shared.Runtime, name string, fn func(context.Context) error) func(context.Context) error {
	if fn == nil || rt == nil || version == "dev" {
		return fn
	}
	return func(ctx context.Context) error {
		if m, _ := rt.Mode(); m != shared.ModeMember {
			return fn(ctx)
		}
		_, err := rt.Migrate(ctx, name+"@"+version, fn)
		return err
	}
}

// sharedCluster is the node, with what the shared configuration has to
// say among its warnings and banners.
type sharedCluster struct {
	*cluster.Node
	rt *shared.Runtime
}

// Status adds the shared configuration's warnings to the node's.
func (s sharedCluster) Status() cluster.Status {
	st := s.Node.Status()
	for _, w := range s.rt.Warnings() {
		st.Warnings = append(st.Warnings, cluster.Warning{Level: w.Level, Text: w.Text, Banner: w.Banner})
	}
	return st
}

// Banners adds the shared configuration's red banners to the node's.
func (s sharedCluster) Banners() []string {
	out := s.Node.Banners()
	for _, w := range s.rt.Warnings() {
		if w.Level == "red" && w.Banner != "" && !slices.Contains(out, w.Banner) {
			out = append(out, w.Banner)
		}
	}
	return out
}

// sharedReady is the runtime's say in /readyz: a member that cannot use
// the shared settings (OpenSearch down for long, the config index gone, a
// missed key change) gets no traffic.
func sharedReady(rt *shared.Runtime) (bool, string) {
	if rt == nil {
		return true, ""
	}
	return rt.Ready()
}

// flushShared writes cache.enc at shutdown, so the next start has the
// latest copy.
func flushShared(rt *shared.Runtime, log *slog.Logger) {
	if rt == nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- rt.FlushCache() }()
	select {
	case err := <-done:
		if err != nil {
			log.Warn("could not save this server's copy of the shared settings", "err", err)
		}
	case <-time.After(10 * time.Second):
	}
}
