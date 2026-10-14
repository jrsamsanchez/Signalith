package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// errNotSafe is upgrade-check's answer when a server should not be
// upgraded yet; upgradeExit turns it into exit code 3.
var errNotSafe = errors.New("not safe to upgrade the next server yet")

// exitFunc ends the process; tests replace it.
var exitFunc = os.Exit

// upgradeExit exits with 3 when err is errNotSafe, whose reasons were
// printed already, and returns any other error as it is.
func upgradeExit(err error) error {
	if errors.Is(err, errNotSafe) {
		exitFunc(3)
	}
	return err
}

// upgradeSeenFor is how long ago another server's heartbeat may have been
// written for this OpenSearch to count as shared by several servers.
const upgradeSeenFor = 7 * 24 * time.Hour

// upgradeVerdict is what signalith cluster upgrade-check finds, and what
// it prints with -json.
type upgradeVerdict struct {
	Safe bool `json:"safe"`
	// Single is true when no other server used this OpenSearch lately.
	Single       bool            `json:"single,omitempty"`
	Servers      []upgradeServer `json:"servers"`
	Versions     []string        `json:"versions"`
	ClusterLevel int             `json:"cluster_level,omitempty"`
	Blockers     []upgradeNote   `json:"blockers"`
	Warnings     []upgradeNote   `json:"warnings"`
	Next         string          `json:"next,omitempty"`
}

// upgradeServer is one server as upgrade-check sees it.
type upgradeServer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	State   string `json:"state"`
	Live    bool   `json:"live"`
	Jobs    bool   `json:"jobs"`
	// CaughtUp is yes, no or unknown: whether the server applied every
	// shared document.
	CaughtUp string `json:"caught_up"`
	LevelMax int    `json:"level_max,omitempty"`
}

// upgradeNote is a blocker or a warning.
type upgradeNote struct {
	Code   string `json:"code"`
	Server string `json:"server,omitempty"`
	Text   string `json:"text"`
}

func (x *clusterCLI) upgradeCheck(ctx context.Context, asJSON bool) error {
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return fmt.Errorf("could not read the servers' heartbeats: %w", err)
	}
	var lease *cluster.LeaseDoc
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	src, _, found, err := x.cl.Get(rctx, cluster.RuntimeIndex(x.prefix()), "lease:jobs")
	cancel()
	if err != nil {
		return fmt.Errorf("could not read which server runs the jobs: %w", err)
	}
	if found {
		var l cluster.LeaseDoc
		if json.Unmarshal(src, &l) == nil {
			lease = &l
		}
	}
	rt := x.runtime(true, "")
	st, head := rt.Status(), rt.Hub().MaxRev()
	tasks, tasksErr := x.runningTasks(ctx)
	v := judgeUpgrade(time.Now(), x.self.NodeID, hbs, lease, st, head, tasks, tasksErr == nil)
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	} else {
		v.print(x)
	}
	if !v.Safe {
		return errNotSafe
	}
	return nil
}

// runningTasks lists OpenSearch's running deletes, reindexes and
// snapshots that name one of this cluster's indices.
func (x *clusterCLI) runningTasks(ctx context.Context) ([]string, error) {
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
	if err := x.cl.Do(rctx, http.MethodGet, "/_tasks?actions=*byquery*,*reindex*,cluster:admin/snapshot/*&detailed", nil, &resp); err != nil {
		return nil, err
	}
	out := []string{}
	for _, n := range resp.Nodes {
		for _, t := range n.Tasks {
			if strings.Contains(t.Description, x.prefix()) || strings.HasPrefix(t.Action, "cluster:admin/snapshot/") {
				out = append(out, t.Action+" "+t.Description)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// retentionBusy reports whether a retention step that deletes data is
// running: the leader holds the jobs in delete-only mode, or OpenSearch
// runs a delete, reindex or snapshot of the cluster's indices.
func retentionBusy(leader *cluster.Heartbeat, tasks []string) bool {
	return (leader != nil && leader.Frozen) || len(tasks) > 0
}

// judgeUpgrade says whether one more server may be upgraded now, from the
// servers' heartbeats, the job lease, the shared configuration as this
// server reads it (whose highest revision is head) and OpenSearch's
// running tasks (tasksOK is false when they could not be read). A field
// an older or newer version does not write counts as unknown, never as a
// reason not to upgrade.
func judgeUpgrade(now time.Time, self string, hbs []cluster.Heartbeat, lease *cluster.LeaseDoc, st shared.Status, head int64, tasks []string, tasksOK bool) upgradeVerdict {
	v := upgradeVerdict{ClusterLevel: st.Level, Servers: []upgradeServer{}, Versions: []string{}, Blockers: []upgradeNote{}, Warnings: []upgradeNote{}}
	block := func(code, server, text string) { v.Blockers = append(v.Blockers, upgradeNote{code, server, text}) }
	warn := func(code, server, text string) { v.Warnings = append(v.Warnings, upgradeNote{code, server, text}) }

	others := 0
	for _, hb := range hbs {
		if hb.NodeID != self && now.Sub(hb.HeartbeatAt) < upgradeSeenFor {
			others++
		}
	}
	if others == 0 {
		v.Safe, v.Single = true, true
		v.Next = "This server is the only one using this OpenSearch: stop it, install the new version and start it."
		for _, hb := range hbs {
			v.Servers = append(v.Servers, upgradeServer{Name: hb.Name, Version: hb.Version, State: hb.State,
				Live: upgradeLive(now, hb), Jobs: hb.Leader, CaughtUp: "unknown", LevelMax: hb.LevelMax})
			v.Versions = appendVersion(v.Versions, hb.Version)
		}
		return v
	}

	inCluster := st.Mode == shared.ModeMember || st.Mode == shared.ModeImporting || st.Mode == shared.ModeDegraded
	var leader *cluster.Heartbeat
	var live []cluster.Heartbeat
	levels := map[string]int{}
	for i, hb := range hbs {
		if now.Sub(hb.HeartbeatAt) >= upgradeSeenFor {
			continue
		}
		isLive := upgradeLive(now, hb)
		jobs := isLive && hb.Leader
		if lease != nil && lease.Holder != "" && lease.Holder != hb.NodeID {
			jobs = false
		}
		s := upgradeServer{Name: hb.Name, Version: hb.Version, State: hb.State, Live: isLive, Jobs: jobs, CaughtUp: "unknown", LevelMax: hb.LevelMax}
		if !isLive {
			s.State = cluster.StateOffline
			if hb.State == cluster.StateStopped {
				s.State = cluster.StateStopped
			}
			v.Servers = append(v.Servers, s)
			warn("offline", hb.Name, fmt.Sprintf("%s is offline (last heard from %s ago): it catches up when it starts.", hb.Name, upgradeAgo(now.Sub(hb.HeartbeatAt))))
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
			warn("caught_up_unknown", hb.Name, fmt.Sprintf("%s (version %s) does not say how far it applied the shared settings.", hb.Name, upgradeVersion(hb.Version)))
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
			block("level_too_high", hb.Name, fmt.Sprintf("%s (version %s) reads stored data up to level %d, but the cluster is at level %d: upgrade it first.", hb.Name, upgradeVersion(hb.Version), hb.LevelMax, st.Level))
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
	if retentionBusy(leader, tasks) {
		name := ""
		text := "OpenSearch is deleting, reindexing or snapshotting the cluster's data: wait until that ends."
		if leader != nil && leader.Frozen {
			name = leader.Name
			text = fmt.Sprintf("%s runs the jobs in delete-only mode because OpenSearch refuses writes: wait until OpenSearch takes writes again.", leader.Name)
		}
		block("retention_busy", name, text)
	}
	if !tasksOK {
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
	v.Next = upgradeNext(live, leader, levels)
	v.Safe = len(v.Blockers) == 0
	return v
}

// upgradeNext suggests which server to upgrade next: one still on the
// older version that does not run the jobs, then the one that does, so the
// jobs move once, to the new version.
func upgradeNext(live []cluster.Heartbeat, leader *cluster.Heartbeat, levels map[string]int) string {
	if len(live) == 0 {
		return ""
	}
	newest := ""
	for ver := range levels {
		if newest == "" || newerVersion(ver, newest, levels) {
			newest = ver
		}
	}
	var todo []cluster.Heartbeat
	for _, hb := range live {
		if len(levels) < 2 || hb.Version != newest {
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

// newerVersion reports whether version a is newer than b: the one that
// reads higher levels, else the higher release number, else the build
// after a release (with a suffix, or dev).
func newerVersion(a, b string, levels map[string]int) bool {
	if levels[a] != levels[b] {
		return levels[a] > levels[b]
	}
	na, sa := splitVersion(a)
	nb, sb := splitVersion(b)
	if c := slices.Compare(na, nb); c != 0 {
		return c > 0
	}
	return sa != "" && sb == ""
}

// splitVersion splits 0.2.0-next+abc into [0 2 0] and -next+abc; dev has
// no numbers and the suffix dev.
func splitVersion(v string) ([]int, string) {
	v = strings.TrimPrefix(v, "v")
	var nums []int
	for len(v) > 0 {
		i := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
		if i < 0 {
			i = len(v)
		}
		if i == 0 {
			break
		}
		n, _ := strconv.Atoi(v[:i])
		nums = append(nums, n)
		v = v[i:]
		if !strings.HasPrefix(v, ".") {
			break
		}
		v = v[1:]
	}
	return nums, v
}

func upgradeLive(now time.Time, hb cluster.Heartbeat) bool {
	return hb.State != cluster.StateStopped && now.Sub(hb.HeartbeatAt) < cliHeartbeatAge
}

func appendVersion(vs []string, v string) []string {
	v = upgradeVersion(v)
	if !slices.Contains(vs, v) {
		vs = append(vs, v)
		slices.Sort(vs)
	}
	return vs
}

func upgradeVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func upgradeAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < 2*time.Hour:
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}

func (v upgradeVerdict) print(x *clusterCLI) {
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Server\tVersion\tState\tJobs\tCaught up")
	for _, s := range v.Servers {
		jobs := ""
		if s.Jobs {
			jobs = "runs them"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, upgradeVersion(s.Version), s.State, jobs, s.CaughtUp)
	}
	w.Flush()
	fmt.Fprintln(x.out)
	if v.Single {
		fmt.Fprintln(x.out, v.Next)
		return
	}
	if v.Safe {
		fmt.Fprintln(x.out, "Safe to upgrade the next server.")
	} else {
		fmt.Fprintln(x.out, "Not safe yet:")
		for _, b := range v.Blockers {
			fmt.Fprintf(x.out, "  - %s\n", b.Text)
		}
	}
	if len(v.Warnings) > 0 {
		fmt.Fprintln(x.out, "\nWarnings:")
		for _, n := range v.Warnings {
			fmt.Fprintf(x.out, "  - %s\n", n.Text)
		}
	}
	if v.Next != "" {
		fmt.Fprintf(x.out, "\n%s\n", v.Next)
	}
}
