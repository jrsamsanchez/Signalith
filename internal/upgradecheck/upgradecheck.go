// Package upgradecheck says whether one more server of a cluster may be
// upgraded now, and which one next: signalith cluster upgrade-check
// prints it, and the Servers page shows it as a checklist.
package upgradecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// SeenFor is how long ago another server's heartbeat may have been
// written for this OpenSearch to count as shared by several servers.
const SeenFor = 7 * 24 * time.Hour

// LiveAge is how old a heartbeat may be for its server to count as up.
const LiveAge = 30 * time.Second

// Verdict is what the check finds; signalith cluster upgrade-check -json
// prints it.
type Verdict struct {
	Safe bool `json:"safe"`
	// Single is true when no other server used this OpenSearch lately.
	Single       bool     `json:"single,omitempty"`
	Servers      []Server `json:"servers"`
	Versions     []string `json:"versions"`
	ClusterLevel int      `json:"cluster_level,omitempty"`
	Blockers     []Note   `json:"blockers"`
	Warnings     []Note   `json:"warnings"`
	Next         string   `json:"next,omitempty"`
	// Newest is the newest version a live server runs, "" when they all
	// run one.
	Newest string `json:"newest,omitempty"`
	// Migrations are the migrations run once for the cluster, with when
	// they ran, and LevelVersions, per cluster level, the version of the
	// server that raised the cluster to it.
	Migrations    map[string]string `json:"migrations,omitempty"`
	LevelVersions map[string]string `json:"level_versions,omitempty"`
}

// Server is one server as the check sees it.
type Server struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	State   string `json:"state"`
	Live    bool   `json:"live"`
	Jobs    bool   `json:"jobs"`
	// CaughtUp is yes, no or unknown: whether the server applied every
	// shared document.
	CaughtUp string `json:"caught_up"`
	LevelMax int    `json:"level_max,omitempty"`
	// NodeID is the server's node id, Deployment how it runs (systemd,
	// windows-service, docker or ""), OS its operating system, and
	// Drained true while an admin drained it.
	NodeID     string `json:"node_id,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	OS         string `json:"os,omitempty"`
	Drained    bool   `json:"drained,omitempty"`
}

// Note is a blocker or a warning.
type Note struct {
	Code   string `json:"code"`
	Server string `json:"server,omitempty"`
	Text   string `json:"text"`
}

// Inputs are what Judge decides from: the time, this server's node id,
// the servers' heartbeats, the job lease (nil when there is none), the
// shared configuration as this server reads it (whose highest revision is
// Head), and OpenSearch's running tasks (TasksOK is false when they could
// not be read).
type Inputs struct {
	Now        time.Time
	Self       string
	Heartbeats []cluster.Heartbeat
	Lease      *cluster.LeaseDoc
	Status     shared.Status
	Head       int64
	Tasks      []string
	TasksOK    bool
	// Migrations and LevelVersions come from the cluster document.
	Migrations    map[string]string
	LevelVersions map[string]string
}

// Read reads the inputs from OpenSearch through cl and from rt, the
// shared configuration of the server self (a node id).
func Read(ctx context.Context, cl *store.Client, prefix, self string, rt *shared.Runtime) (Inputs, error) {
	in := Inputs{Now: time.Now(), Self: self}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	docs, err := cl.SearchDocs(rctx, cluster.RuntimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	cancel()
	if err != nil {
		return in, fmt.Errorf("could not read the servers' heartbeats: %w", err)
	}
	for _, d := range docs {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" {
			continue
		}
		in.Heartbeats = append(in.Heartbeats, hb)
	}
	slices.SortFunc(in.Heartbeats, func(a, b cluster.Heartbeat) int { return strings.Compare(a.Name, b.Name) })
	rctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	src, _, found, err := cl.Get(rctx, cluster.RuntimeIndex(prefix), cluster.LeaseDocID)
	cancel()
	if err != nil {
		return in, fmt.Errorf("could not read which server runs the jobs: %w", err)
	}
	if found {
		var l cluster.LeaseDoc
		if json.Unmarshal(src, &l) == nil {
			in.Lease = &l
		}
	}
	if rt != nil {
		in.Status, in.Head = rt.Status(), rt.Hub().MaxRev()
		if body, ok := rt.Cluster().Get(); ok && body != nil {
			in.Migrations = maps.Clone(body.Migrations)
		}
	}
	in.Tasks, err = RunningTasks(ctx, cl, prefix)
	in.TasksOK = err == nil
	return in, nil
}

// RunningTasks lists OpenSearch's running deletes, reindexes and
// snapshots that name one of the indices of prefix.
func RunningTasks(ctx context.Context, cl *store.Client, prefix string) ([]string, error) {
	var resp struct {
		Nodes map[string]struct {
			Tasks map[string]struct {
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"tasks"`
		} `json:"nodes"`
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := cl.Do(rctx, http.MethodGet, "/_tasks?actions=*byquery*,*reindex*,cluster:admin/snapshot/*&detailed", nil, &resp); err != nil {
		return nil, err
	}
	out := []string{}
	for _, n := range resp.Nodes {
		for _, t := range n.Tasks {
			if strings.Contains(t.Description, prefix) || strings.HasPrefix(t.Action, "cluster:admin/snapshot/") {
				out = append(out, t.Action+" "+t.Description)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// RetentionBusy reports whether a retention step that deletes data is
// running: the leader holds the jobs in delete-only mode, or OpenSearch runs a delete, reindex or snapshot of the cluster's
// indices.
func RetentionBusy(leader *cluster.Heartbeat, tasks []string) bool {
	return (leader != nil && leader.Frozen) || len(tasks) > 0
}

// Judge says whether one more server may be upgraded now. A field an
// older or newer version does not write counts as unknown, never as a
// reason not to upgrade.
func Judge(in Inputs) Verdict {
	now, self, hbs, lease, st, head := in.Now, in.Self, in.Heartbeats, in.Lease, in.Status, in.Head
	v := Verdict{ClusterLevel: st.Level, Servers: []Server{}, Versions: []string{}, Blockers: []Note{}, Warnings: []Note{},
		Migrations: in.Migrations, LevelVersions: in.LevelVersions}
	block := func(code, server, text string) { v.Blockers = append(v.Blockers, Note{code, server, text}) }
	warn := func(code, server, text string) { v.Warnings = append(v.Warnings, Note{code, server, text}) }
	server := func(hb cluster.Heartbeat) Server {
		return Server{Name: hb.Name, Version: hb.Version, State: hb.State, Live: Live(now, hb), Jobs: hb.Leader, CaughtUp: "unknown",
			LevelMax: hb.LevelMax, NodeID: hb.NodeID, Deployment: hb.Deployment, OS: hb.OS, Drained: hb.State == cluster.StateDraining}
	}

	others := 0
	for _, hb := range hbs {
		if hb.NodeID != self && now.Sub(hb.HeartbeatAt) < SeenFor {
			others++
		}
	}
	if others == 0 {
		v.Safe, v.Single = true, true
		v.Next = "This server is the only one using this OpenSearch: stop it, install the new version and start it."
		for _, hb := range hbs {
			v.Servers = append(v.Servers, server(hb))
			v.Versions = appendVersion(v.Versions, hb.Version)
		}
		return v
	}

	inCluster := st.Mode == shared.ModeMember || st.Mode == shared.ModeImporting || st.Mode == shared.ModeDegraded
	var leader *cluster.Heartbeat
	var live []cluster.Heartbeat
	levels := map[string]int{}
	for i, hb := range hbs {
		if now.Sub(hb.HeartbeatAt) >= SeenFor {
			continue
		}
		s := server(hb)
		jobs := s.Live && hb.Leader
		if lease != nil && lease.Holder != "" && lease.Holder != hb.NodeID {
			jobs = false
		}
		s.Jobs = jobs
		if !s.Live {
			s.State = cluster.StateOffline
			if hb.State == cluster.StateStopped {
				s.State = cluster.StateStopped
			}
			v.Servers = append(v.Servers, s)
			warn("offline", hb.Name, fmt.Sprintf("%s is offline (last heard from %s ago): it catches up when it starts.", hb.Name, Ago(now.Sub(hb.HeartbeatAt))))
			continue
		}
		live = append(live, hb)
		if jobs {
			leader = &hbs[i]
		}
		v.Versions = appendVersion(v.Versions, hb.Version)
		levels[hb.Version] = max(levels[hb.Version], hb.LevelMax)
		switch {
		case !inCluster:
		case hb.Mode == "":
			warn("caught_up_unknown", hb.Name, fmt.Sprintf("%s (version %s) does not say how far it applied the shared settings.", hb.Name, VersionText(hb.Version)))
		case hb.MaxRev < head:
			s.CaughtUp = "no"
			block("config_behind", hb.Name, fmt.Sprintf("%s has not applied every change of the shared settings yet (revision %d of %d): wait until it catches up.", hb.Name, hb.MaxRev, head))
		default:
			s.CaughtUp = "yes"
		}
		switch hb.State {
		case cluster.StateStarting, cluster.StateStopping:
			block("starting", hb.Name, fmt.Sprintf("%s is %s: wait until it is ready.", hb.Name, hb.State))
		case cluster.StateDown, cluster.StateConflict:
			block("not_ready", hb.Name, fmt.Sprintf("%s is %s: fix it before upgrading another server.", hb.Name, hb.State))
		}
		if hb.Restart != nil && hb.Restart.Busy {
			block("restart_running", hb.Name, fmt.Sprintf("%s is restarting to apply new settings: wait until the restart ends.", hb.Name))
		}
		if st.Level > 0 && hb.LevelMax > 0 && st.Level > hb.LevelMax {
			block("level_too_high", hb.Name, fmt.Sprintf("%s (version %s) reads stored data up to level %d, but the cluster is at level %d: upgrade it first.", hb.Name, VersionText(hb.Version), hb.LevelMax, st.Level))
		}
		if len(hb.NeedsUpgrade) > 0 {
			warn("needs_upgrade", hb.Name, fmt.Sprintf("%s cannot read shared settings a newer version wrote (%s): upgrade it.", hb.Name, strings.Join(hb.NeedsUpgrade, ", ")))
		}
		if len(hb.RestartNeeded) > 0 {
			warn("restart_needed", hb.Name, fmt.Sprintf("%s waits for a restart to apply %s: the upgrade's restart applies it.", hb.Name, strings.Join(hb.RestartNeeded, ", ")))
		}
		v.Servers = append(v.Servers, s)
	}
	if len(v.Versions) > 2 {
		block("three_versions", "", fmt.Sprintf("The servers run %d versions (%s): finish the upgrade under way before starting another one.", len(v.Versions), strings.Join(v.Versions, ", ")))
	}
	if RetentionBusy(leader, in.Tasks) {
		name := ""
		text := "OpenSearch is deleting, reindexing or snapshotting the cluster's data: wait until that ends."
		switch {
		case leader != nil && leader.Frozen:
			name = leader.Name
			text = fmt.Sprintf("%s runs the jobs in delete-only mode because OpenSearch refuses writes: wait until OpenSearch takes writes again.", leader.Name)
		}
		block("retention_busy", name, text)
	}
	if !in.TasksOK {
		warn("tasks_unknown", "", "Could not ask OpenSearch whether it is deleting or reindexing data.")
	}
	if leader != nil {
		other := false
		for _, hb := range live {
			if hb.NodeID != leader.NodeID && hb.LeaderEligible {
				other = true
			}
		}
		if !other {
			warn("only_eligible", leader.Name, fmt.Sprintf("%s is the only server that can run the jobs: they pause for about 40 seconds while it is upgraded.", leader.Name))
		}
	}
	v.Next = Next(live, leader, levels)
	if len(levels) > 1 {
		v.Newest = newest(levels)
	}
	v.Safe = len(v.Blockers) == 0
	return v
}

// newest is the newest of the versions in levels.
func newest(levels map[string]int) string {
	n := ""
	for _, ver := range slices.Sorted(maps.Keys(levels)) {
		if n == "" || cluster.NewerVersion(ver, n, levels[ver], levels[n]) {
			n = ver
		}
	}
	return n
}

// Next suggests which server to upgrade next: one still on the older
// version that does not run the jobs, then the one that does, so the jobs
// move once, to the new version.
func Next(live []cluster.Heartbeat, leader *cluster.Heartbeat, levels map[string]int) string {
	if len(live) == 0 {
		return ""
	}
	top := newest(levels)
	var todo []cluster.Heartbeat
	for _, hb := range live {
		if len(levels) < 2 || hb.Version != top {
			todo = append(todo, hb)
		}
	}
	slices.SortStableFunc(todo, func(a, b cluster.Heartbeat) int {
		if a.Leader != b.Leader {
			if a.Leader {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Name, b.Name)
	})
	if len(todo) == 0 {
		return ""
	}
	n := todo[0]
	switch {
	case leader != nil && n.NodeID == leader.NodeID:
		return fmt.Sprintf("Upgrade %s next: it runs the jobs, so they move once, to the new version.", n.Name)
	case leader != nil:
		return fmt.Sprintf("Upgrade %s next: it does not run the jobs. Upgrade %s, which runs them, last.", n.Name, leader.Name)
	}
	return fmt.Sprintf("Upgrade %s next.", n.Name)
}

// Live reports whether a heartbeat's server is up.
func Live(now time.Time, hb cluster.Heartbeat) bool {
	return hb.State != cluster.StateStopped && now.Sub(hb.HeartbeatAt) < LiveAge
}

func appendVersion(vs []string, v string) []string {
	v = VersionText(v)
	if !slices.Contains(vs, v) {
		vs = append(vs, v)
		slices.Sort(vs)
	}
	return vs
}

// VersionText is v, or unknown when a server did not say.
func VersionText(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// Ago writes a duration rounded for people.
func Ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < 2*time.Hour:
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}
