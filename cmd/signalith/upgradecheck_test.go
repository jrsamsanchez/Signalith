package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

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
	codes := func(ns []upgradeNote) []string {
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
			next: "Upgrade siem-b next: it does not run the jobs. Upgrade siem-a, which runs them, last."},
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
			warnings: []string{"caught_up_unknown"}, next: "Upgrade siem-b next: it does not run the jobs. Upgrade siem-a, which runs them, last."},
		{name: "offline", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0"), hb("c", "0.2.0", func(h *cluster.Heartbeat) { h.HeartbeatAt = now.Add(-5 * time.Minute) })}, st: member, tasksOK: true,
			warnings: []string{"offline"}},
		{name: "needs upgrade and restart", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0", func(h *cluster.Heartbeat) {
			h.NeedsUpgrade, h.RestartNeeded = []string{"settings"}, []string{"server.listen"}
		})}, st: member, tasksOK: true, warnings: []string{"needs_upgrade", "restart_needed"}},
		{name: "tasks unknown", hbs: []cluster.Heartbeat{hb("a", "0.2.0", leads), hb("b", "0.2.0")}, st: member,
			warnings: []string{"tasks_unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := judgeUpgrade(now, "n_a", tc.hbs, nil, tc.st, 10, tc.tasks, tc.tasksOK)
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
		v := judgeUpgrade(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), old}, nil, member, 10, nil, true)
		if v.Servers[1].CaughtUp != "unknown" || v.Servers[0].CaughtUp != "yes" || !v.Servers[0].Jobs {
			t.Errorf("servers %+v", v.Servers)
		}
		if !slices.Equal(v.Versions, []string{"0.1.0", "0.2.0"}) {
			t.Errorf("versions %v", v.Versions)
		}
	})
	t.Run("offline server is not live", func(t *testing.T) {
		stopped := hb("b", "0.2.0", func(h *cluster.Heartbeat) { h.State = cluster.StateStopped })
		v := judgeUpgrade(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), stopped}, nil, member, 10, nil, true)
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
		v := judgeUpgrade(now, "n_a", []cluster.Heartbeat{hb("a", "0.2.0", leads), gone}, nil, member, 99, nil, false)
		if !v.Safe || !v.Single || !strings.Contains(v.Next, "the only one using this OpenSearch") || len(v.Warnings) != 0 {
			t.Errorf("single server: %+v", v)
		}
	})
	t.Run("lease names the runner", func(t *testing.T) {
		// A heartbeat that still says leader while the lease moved on
		// does not count as running the jobs.
		a, b := hb("a", "0.2.0", leads), hb("b", "0.2.0", leads)
		v := judgeUpgrade(now, "n_a", []cluster.Heartbeat{a, b}, &cluster.LeaseDoc{Holder: "n_b"}, member, 10, nil, true)
		if v.Servers[0].Jobs || !v.Servers[1].Jobs {
			t.Errorf("servers %+v", v.Servers)
		}
	})
}

func TestNewerVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"0.2.0", "0.1.0", true},
		{"0.1.0", "0.2.0", false},
		{"0.1.0-next+abc1234", "0.1.0", true},
		{"0.10.0", "0.9.1", true},
		{"dev", "0.1.0", false},
	} {
		if got := newerVersion(tc.a, tc.b, map[string]int{}); got != tc.want {
			t.Errorf("newerVersion(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
	if !newerVersion("dev", "0.1.0", map[string]int{"dev": 3, "0.1.0": 0}) {
		t.Error("a version that reads higher levels is newer")
	}
}

func TestClusterUpgradeCheck(t *testing.T) {
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: uc\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	exited := -1
	old := exitFunc
	exitFunc = func(code int) { exited = code }
	t.Cleanup(func() { exitFunc = old })
	run := func() (upgradeVerdict, error) {
		t.Helper()
		exited = -1
		var out, errOut bytes.Buffer
		err := runCluster([]string{"upgrade-check", "-c", path, "-json"}, os.Stdin, &out, &errOut)
		var v upgradeVerdict
		if jerr := json.Unmarshal(out.Bytes(), &v); jerr != nil {
			t.Fatalf("upgrade-check -json: %v, %v\n%s%s", err, jerr, out.String(), errOut.String())
		}
		return v, err
	}

	a := clusterServerDir(t, filepath.Join(dir, "state-a"), "siem-a")
	now := time.Now().UTC()
	hbA := cluster.Heartbeat{Kind: "node", NodeID: a.NodeID, Name: "siem-a", State: cluster.StateReady, Version: "0.2.0",
		LeaderEligible: true, Leader: true, HeartbeatAt: now}
	fake.Put("uc_runtime", "node:"+a.NodeID, asMap(t, hbA))
	v, err := run()
	if err != nil || exited != -1 || !v.Single || !v.Safe {
		t.Fatalf("single server: %v, exit %d, %+v", err, exited, v)
	}

	hbB := cluster.Heartbeat{Kind: "node", NodeID: "n_b", Name: "siem-b", State: cluster.StateReady, Version: "0.2.0", LeaderEligible: true, HeartbeatAt: now}
	fake.Put("uc_runtime", "node:n_b", asMap(t, hbB))
	fake.Put("uc_runtime", "lease:jobs", asMap(t, cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: a.NodeID, HolderName: "siem-a", HolderVersion: "0.2.0"}))
	v, err = run()
	if err != nil || exited != -1 || !v.Safe || v.Single || len(v.Servers) != 2 || !strings.Contains(v.Next, "Upgrade siem-b next") {
		t.Fatalf("two servers: %v, exit %d, %+v", err, exited, v)
	}

	hbB.Restart = &cluster.RestartStatus{Busy: true}
	fake.Put("uc_runtime", "node:n_b", asMap(t, hbB))
	v, err = run()
	if !errors.Is(err, errNotSafe) || exited != 3 || v.Safe || len(v.Blockers) != 1 || v.Blockers[0].Code != "restart_running" || v.Blockers[0].Server != "siem-b" {
		t.Fatalf("restart running: %v, exit %d, %+v", err, exited, v)
	}
}
