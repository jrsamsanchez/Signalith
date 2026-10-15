package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/upgradecheck"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestClusterUpgrade(t *testing.T) {
	var fail error
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Upgrade = func(context.Context) (upgradecheck.Verdict, error) {
			if fail != nil {
				return upgradecheck.Verdict{}, fail
			}
			return upgradecheck.Verdict{Safe: true, Versions: []string{"1.5.0", "1.6.0"}, Newest: "1.6.0", Next: "Upgrade siem-b next.",
				Servers:  []upgradecheck.Server{{Name: "siem-b", NodeID: "n_b", Version: "1.5.0", State: "ready", Live: true, Deployment: "systemd", OS: "linux"}},
				Blockers: []upgradecheck.Note{}, Warnings: []upgradecheck.Note{}, LevelVersions: map[string]string{"9": "1.6.0"}}, nil
		}
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if code, _ := doAs(t, ts, "vera", "role-password", "GET", "/api/cluster/upgrade", ""); code != http.StatusForbidden {
		t.Errorf("viewer: %d", code)
	}
	code, out := do(t, ts, "GET", "/api/cluster/upgrade", "", true)
	if code != http.StatusOK || out["safe"] != true || out["newest"] != "1.6.0" || out["next"] != "Upgrade siem-b next." {
		t.Fatalf("admin: %d %v", code, out)
	}
	sv := out["servers"].([]any)[0].(map[string]any)
	if sv["node_id"] != "n_b" || sv["deployment"] != "systemd" || sv["caught_up"] != "" && sv["caught_up"] != nil {
		t.Errorf("server %v", sv)
	}
	if out["level_versions"].(map[string]any)["9"] != "1.6.0" {
		t.Errorf("level_versions %v", out["level_versions"])
	}
	if _, ok := out["blockers"].([]any); !ok {
		t.Errorf("blockers %v", out["blockers"])
	}
	fail = errors.New("could not read the servers' heartbeats: no")
	if code, out := do(t, ts, "GET", "/api/cluster/upgrade", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("failed read: %d %v", code, out)
	}
}

func TestClusterUpgradeWithoutCluster(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/cluster/upgrade", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("%d %v", code, out)
	}
}
