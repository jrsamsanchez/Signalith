package upgradecheck

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// judge is Judge with its inputs as arguments.
func judge(now time.Time, self string, hbs []cluster.Heartbeat, lease *cluster.LeaseDoc, st shared.Status, head int64, tasks []string, tasksOK bool) Verdict {
	return Judge(Inputs{Now: now, Self: self, Heartbeats: hbs, Lease: lease, Status: st, Head: head, Tasks: tasks, TasksOK: tasksOK})
}

func TestJudgeUpgrade(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	member := shared.Status{Mode: shared.ModeMember, Level: 3}
	hb := func(id, version string, mod ...func(*cluster.Heartbeat)) cluster.Heartbeat {
		h := cluster.Heartbeat{Kind: "node", NodeID: "n_" + id, Name: "siem-" + id, State: cluster.StateReady, Version: version,
			HeartbeatAt: now.Add(-2 * time.Second), LeaderEligible: true, Mode: string(shared.ModeMember), MaxRev: 10, LevelMax: 3}
		for _, m := range mod {
			m(&h)
		}
		return h
	}
	leads := func(h *cluster.Heartbeat) { h.Leader = true }
	codes := func(ns []Note) []string {
		var out []string
		for _, n := range ns {
			out = append(out, n.Code)
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		hbs      []cluster.Heartbeat
		st       shared.Status
		tasks    []string
		tasksOK  bool
		blockers []string
		warnings []string
		next     string
	}{
		{name: "two ready servers", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0")}, st: member, tasksOK: true,
			next: "To upgrade, start with siem-b: it does not run the jobs. Upgrade siem-a, which runs them, last."},
		{name: "config behind", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.MaxRev = 7 })}, st: member, tasksOK: true,
			blockers: []string{"config_behind"}},
		{name: "legacy skips config", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.MaxRev = 0 })},
			st: shared.Status{Mode: shared.ModeLegacyC}, tasksOK: true},
		{name: "restart running", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.Restart = &cluster.RestartStatus{Busy: true} })}, st: member, tasksOK: true,
			blockers: []string{"restart_running"}},
		{name: "leader frozen", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads, func(h *cluster.Heartbeat) { h.Frozen = true }), hb("b", "0.2.0")}, st: member, tasksOK: true,
			blockers: []string{"retention_busy"}},
		{name: "delete by query", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0")}, st: member, tasksOK: true,
			tasks: []string{"indices:data/write/delete/byquery delete-by-query [signalith-events-*]"}, blockers: []string{"retention_busy"}},
		{name: "starting", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.State = cluster.StateStarting })}, st: member, tasksOK: true,
			blockers: []string{"starting"}},
		{name: "two versions are fine", hbs: []cluster.Heartbeat{hb("a", "0.1.0", leads), hb("b", "0.2.0")}, st: member, tasksOK: true,
			next: "Upgrade siem-a next: it runs the jobs, so they move once, to the new version."},
		{name: "three versions", hbs: []cluster.Heartbeat{hb("a", "0.1.0", leads), hb("b", "0.2.0"), hb("c", "0.3.0")}, st: member, tasksOK: true,
			blockers: []string{"three_versions"}},
		{name: "level too high", hbs: []cluster.Heartbeat{hb("a", "0.3.0", leads, func(h *cluster.Heartbeat) { h.LevelMax = 4 }), hb("b", "0.2.0")},
			st: shared.Status{Mode: shared.ModeMember, Level: 4}, tasksOK: true, blockers: []string{"level_too_high"}},
		{name: "only eligible", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.LeaderEligible = false })}, st: member, tasksOK: true,
			warnings: []string{"only_eligible"}},
		{name: "older server", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.1.0", func(h *cluster.Heartbeat) { h.Mode, h.MaxRev, h.LevelMax = "", 0, 0 })}, st: member, tasksOK: true,
			warnings: []string{"caught_up_unknown"}, next: "Upgrade siem-b next: siem-a, which runs the jobs, runs the new version already."},
		{name: "offline", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0"), hb("c", "0.2.0", func(h *cluster.Heartbeat) { h.HeartbeatAt = now.Add(-5 * time.Minute) })}, st: member, tasksOK: true,
			warnings: []string{"offline"}},
		{name: "needs upgrade and restart", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) {
			h.NeedsUpgrade, h.RestartNeeded = []string{"settings"}, []string{"server.listen"}
		})}, st: member, tasksOK: true, warnings: []string{"needs_upgrade", "restart_needed"}},
		{name: "tasks unknown", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0")}, st: member,
			warnings: []string{"tasks_unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := judge(now, "n_a", tc.hbs, nil, tc.st, 10, tc.tasks, tc.tasksOK)
			if got := codes(v.Blockers); !slices.Equal(got, tc.blockers) {
				t.Errorf("blockers %v, want %v", got, tc.blockers)
			}
			if got := codes(v.Warnings); !slices.Equal(got, tc.warnings) {
				t.Errorf("warnings %v, want %v", got, tc.warnings)
			}
			if v.Safe != (len(tc.blockers) == 0) {
				t.Errorf("safe %v with blockers %v", v.Safe, v.Blockers)
			}
			if tc.next != "" && v.Next != tc.next {
				t.Errorf("next %q, want %q", v.Next, tc.next)
			}
			for _, b := range v.Blockers {
				if b.Text == "" {
					t.Errorf("blocker %s has no text", b.Code)
				}
			}
		})
	}

	t.Run("older server reports unknown", func(t *testing.T) {
		old := hb("b", "0.1.0", func(h *cluster.Heartbeat) { h.Mode, h.MaxRev, h.LevelMax = "", 0, 0 })
		v := judge(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), old}, nil, member, 10, nil, true)
		if v.Servers[1].CaughtUp != "unknown" || v.Servers[0].CaughtUp != "yes" || !v.Servers[0].Jobs {
			t.Errorf("servers %+v", v.Servers)
		}
		if !slices.Equal(v.Versions, []string{"0.1.0", "0.2.0"}) {
			t.Errorf("versions %v", v.Versions)
		}
	})
	t.Run("offline server is not live", func(t *testing.T) {
		stopped := hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.State = cluster.StateStopped })
		v := judge(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), stopped}, nil, member, 10, nil, true)
		if v.Servers[1].Live || v.Servers[1].State != cluster.StateStopped {
			t.Errorf("stopped server: %+v", v.Servers[1])
		}
		// The leader is then the only live server that can run the jobs.
		if !slices.Equal(codes(v.Warnings), []string{"offline", "only_eligible"}) {
			t.Errorf("warnings %v", v.Warnings)
		}
	})
	t.Run("single server", func(t *testing.T) {
		gone := hb("b", "0.1.0", func(h *cluster.Heartbeat) { h.HeartbeatAt = now.Add(-8 * 24 * time.Hour) })
		v := judge(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), gone}, nil, member, 99, nil, false)
		if !v.Safe || !v.Single || !strings.Contains(v.Next, "the only one using this OpenSearch") || len(v.Warnings) != 0 {
			t.Errorf("single server: %+v", v)
		}
	})
	t.Run("lease names the runner", func(t *testing.T) {
		// A heartbeat that still says leader while the lease moved on
		// does not count as running the jobs.
		a, b := hb("a", "0.2.0", leads), hb("b", "0.2.0", leads)
		v := judge(now, "n_a", []cluster.Heartbeat{a, b}, &cluster.LeaseDoc{Holder: "n_b"}, member, 10, nil, true)
		if v.Servers[0].Jobs || !v.Servers[1].Jobs {
			t.Errorf("servers %+v", v.Servers)
		}
	})
}

func TestJudgeServerDetails(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	a := cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", State: cluster.StateReady, Version: "1.5.0", HeartbeatAt: now, Leader: true,
		LeaderEligible: true, Deployment: "systemd", OS: "linux"}
	b := cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", State: cluster.StateDraining, Version: "1.6.0", HeartbeatAt: now,
		LeaderEligible: true, Deployment: "windows-service", OS: "windows"}
	v := Judge(Inputs{Now: now, Self: "n_a", Heartbeats: []cluster.Heartbeat{a, b}, TasksOK: true,
		Migrations: map[string]string{"intel@1.6.0": "2026-10-14T10:00:00Z"}, LevelVersions: map[string]string{"9": "1.6.0"}})
	if v.Newest != "1.6.0" || v.Migrations["intel@1.6.0"] == "" || v.LevelVersions["9"] != "1.6.0" {
		t.Errorf("verdict %+v", v)
	}
	if s := v.Servers[1]; s.NodeID != "n_b" || s.Deployment != "windows-service" || s.OS != "windows" || !s.Drained {
		t.Errorf("server %+v", s)
	}
	if s := v.Servers[0]; s.Drained || s.Deployment != "systemd" {
		t.Errorf("server %+v", s)
	}
	one := Judge(Inputs{Now: now, Self: "n_a", Heartbeats: []cluster.Heartbeat{a, func() cluster.Heartbeat { b.Version = "1.5.0"; return b }()}, TasksOK: true})
	if one.Newest != "" {
		t.Errorf("one version: newest %q", one.Newest)
	}
}

func TestJudgeHandOverAndBusy(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	member := shared.Status{Mode: shared.ModeMember, Level: 3}
	hb := func(id, version string, leader bool) cluster.Heartbeat {
		return cluster.Heartbeat{NodeID: "n_" + id, Name: "siem-" + id, State: cluster.StateReady, Version: version, HeartbeatAt: now,
			LeaderEligible: true, Leader: leader, Mode: string(shared.ModeMember), MaxRev: 10, LevelMax: 3}
	}
	a, b := hb("a", "1.5.0", true), hb("b", "1.5.0", false)
	a.Features = []string{cluster.FeatureYieldNewer}
	v := judge(now, "n_a", []cluster.Heartbeat{a, b}, nil, member, 10, nil, true)
	if want := "To upgrade, start with siem-b. siem-a hands the jobs to it once it is ready, then upgrade siem-a."; v.Next != want || v.Current != "1.5.0" || v.Newest != "" {
		t.Errorf("next %q, want %q", v.Next, want)
	}
	a.Upgrade = &cluster.UpgradeStatus{Busy: "retention run"}
	v = judge(now, "n_a", []cluster.Heartbeat{a, b}, nil, member, 10, nil, true)
	if v.Safe || len(v.Blockers) != 1 || v.Blockers[0].Code != "retention_busy" || v.Blockers[0].Server != "siem-a" ||
		!strings.Contains(v.Blockers[0].Text, "retention run") {
		t.Errorf("busy leader: %+v", v.Blockers)
	}
	if !RetentionBusy(&a, nil) || RetentionBusy(&b, nil) || !RetentionBusy(nil, []string{"x"}) || RetentionBusy(nil, nil) {
		t.Error("RetentionBusy")
	}
}

func TestNextAfterTheHandOver(t *testing.T) {
	// siem-b runs the new version and the jobs already: siem-a is next,
	// and nothing is handed over any more.
	b := cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", Version: "1.6.0", Leader: true, Features: []string{cluster.FeatureYieldNewer}}
	a := cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "1.5.0"}
	got := Next([]cluster.Heartbeat{a, b}, &b, map[string]int{"1.5.0": 3, "1.6.0": 3})
	if got != "Upgrade siem-a next: siem-b, which runs the jobs, runs the new version already." {
		t.Errorf("next %q", got)
	}
}

func TestNextPromisesOnlyHandOversThatHappen(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	yields := []string{cluster.FeatureYieldNewer}
	leader := cluster.Heartbeat{NodeID: "n_1", Name: "signalith-1", Version: "ae9485c", Leader: true, LeaderEligible: true, Features: yields, StartedAt: now.Add(-time.Hour)}
	two := cluster.Heartbeat{NodeID: "n_2", Name: "signalith-2", Version: "ae9485c", LeaderEligible: true, Features: yields, StartedAt: now.Add(-time.Hour)}
	scanner := cluster.Heartbeat{NodeID: "n_s", Name: "scanner", Version: "ae9485c", Role: cluster.RoleScanner, NotEligible: "scanner", Features: yields, StartedAt: now.Add(-time.Hour)}
	up := func(hb cluster.Heartbeat, ver string) cluster.Heartbeat {
		hb.Version, hb.StartedAt = ver, now
		return hb
	}
	// lab is hb on a cloud lab build (lab-setup.sh), started at now+at.
	lab := func(hb cluster.Heartbeat, sha string, at time.Duration) cluster.Heartbeat {
		hb.Version, hb.StartedAt = "0.0.0-lab-"+sha, now.Add(at)
		return hb
	}
	for _, tc := range []struct {
		name   string
		live   []cluster.Heartbeat
		levels map[string]int
		want   string
	}{
		{name: "a scanner first never takes the jobs",
			live: []cluster.Heartbeat{leader, two, scanner}, levels: map[string]int{"ae9485c": 3},
			want: "To upgrade, start with scanner: it does not run the jobs. Upgrade signalith-1, which runs them, last."},
		{name: "a commit build keeps the jobs until it is upgraded",
			live: []cluster.Heartbeat{leader, two}, levels: map[string]int{"ae9485c": 3},
			want: "To upgrade, start with signalith-2: it does not run the jobs. Upgrade signalith-1, which runs them, last."},
		{name: "commit builds are not handed the jobs",
			live: []cluster.Heartbeat{leader, up(two, "07d3263"), up(scanner, "07d3263")}, levels: map[string]int{"ae9485c": 3, "07d3263": 3},
			want: "Upgrade signalith-1 next: it runs the jobs, so they move once, to the new version."},
		{name: "commit builds, the newer one sorts first",
			live: []cluster.Heartbeat{up(leader, "0a0a0a0"), two, scanner}, levels: map[string]int{"ae9485c": 3, "0a0a0a0": 3},
			want: "Upgrade scanner next: signalith-1, which runs the jobs, runs the new version already."},
		{name: "a release hands the jobs to the upgraded server",
			live: []cluster.Heartbeat{up(leader, "0.2.0"), up(two, "0.3.0"), up(scanner, "0.3.0")}, levels: map[string]int{"0.2.0": 3, "0.3.0": 3},
			want: "Upgrade signalith-1 next: it runs the jobs, so they move once, to the new version."},
		{name: "a release on the first eligible server",
			live: []cluster.Heartbeat{up(leader, "0.2.0"), up(two, "0.2.0"), up(scanner, "0.3.0")}, levels: map[string]int{"0.2.0": 3, "0.3.0": 3},
			want: "Upgrade signalith-2 next. signalith-1 hands the jobs to it once it is ready, then upgrade signalith-1."},
		{name: "commit builds before the first eligible server",
			live: []cluster.Heartbeat{leader, two, up(scanner, "07d3263")}, levels: map[string]int{"ae9485c": 3, "07d3263": 3},
			want: "Upgrade signalith-2 next: it does not run the jobs. Upgrade signalith-1, which runs them, last."},
		{name: "lab builds, only the scanner upgraded",
			live:   []cluster.Heartbeat{lab(leader, "07d3263", -time.Hour), lab(two, "07d3263", -time.Hour), lab(scanner, "2f44844", 0)},
			levels: map[string]int{"0.0.0-lab-07d3263": 3, "0.0.0-lab-2f44844": 3},
			want:   "Upgrade signalith-2 next: it does not run the jobs. Upgrade signalith-1, which runs them, last."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l *cluster.Heartbeat
			for i := range tc.live {
				if tc.live[i].Leader {
					l = &tc.live[i]
				}
			}
			if got := Next(tc.live, l, tc.levels); got != tc.want {
				t.Errorf("next %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestJudgeEveryServerOnOneVersion(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	member := shared.Status{Mode: shared.ModeMember, Level: 3}
	hb := func(id string, leader bool) cluster.Heartbeat {
		return cluster.Heartbeat{NodeID: "n_" + id, Name: "signalith-" + id, State: cluster.StateReady, Version: "07d3263", HeartbeatAt: now,
			LeaderEligible: true, Leader: leader, Mode: string(shared.ModeMember), MaxRev: 10, LevelMax: 3}
	}
	v := judge(now, "n_1", []cluster.Heartbeat{hb("1", true), hb("2", false)}, nil, member, 10, nil, true)
	if !v.Safe || v.Current != "07d3263" || v.Newest != "" || !strings.HasPrefix(v.Next, "To upgrade, start with signalith-2") {
		t.Errorf("one version: %+v", v)
	}
	two := hb("2", false)
	two.Version = "0.3.0"
	v = judge(now, "n_1", []cluster.Heartbeat{hb("1", true), two}, nil, member, 10, nil, true)
	if v.Current != "" || v.Newest != "0.3.0" {
		t.Errorf("two versions: current %q newest %q", v.Current, v.Newest)
	}
}
