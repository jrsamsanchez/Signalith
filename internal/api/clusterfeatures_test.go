package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestClusterFeatures(t *testing.T) {
	states := []shared.FeatureState{
		{Name: "shared_users", Label: "Users", Level: 2, On: true},
		{Name: "api_tokens", Label: "API tokens", Level: 9, Why: "Available when every server runs 1.6.0 or later",
			Waiting: []shared.Peer{{NodeID: "n_c", Name: "siem-c", Version: "1.5.0"}}},
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Features = func() []shared.FeatureState { return states }
		s.ClusterLevel = func() int { return 8 }
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	code, out := doAs(t, ts, "vera", "role-password", "GET", "/api/cluster/features", "")
	if code != http.StatusOK || out["level"] != float64(8) || out["version"] != "test" {
		t.Fatalf("viewer: %d %v", code, out)
	}
	feats := out["features"].([]any)
	tok := feats[1].(map[string]any)
	if len(feats) != 2 || tok["on"] != false || tok["why"] != "Available when every server runs 1.6.0 or later" || tok["level"] != float64(9) {
		t.Errorf("viewer features %v", feats)
	}
	if _, ok := tok["waiting"]; ok {
		t.Errorf("a viewer sees which servers a feature waits for: %v", tok)
	}
	code, out = do(t, ts, "GET", "/api/cluster/features", "", true)
	if code != http.StatusOK {
		t.Fatalf("admin: %d %v", code, out)
	}
	w, _ := out["features"].([]any)[1].(map[string]any)["waiting"].([]any)
	if len(w) != 1 || w[0].(map[string]any)["name"] != "siem-c" || w[0].(map[string]any)["version"] != "1.5.0" {
		t.Errorf("admin waiting %v", w)
	}
	if _, ok := out["features"].([]any)[0].(map[string]any)["why"]; ok {
		t.Errorf("a feature that is on says why not: %v", out["features"])
	}
}

func TestClusterFeaturesWithoutCluster(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := do(t, ts, "GET", "/api/cluster/features", "", true)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	if f, ok := out["features"].([]any); !ok || len(f) != 0 {
		t.Errorf("features %v, want []", out["features"])
	}
	if _, ok := out["level"]; ok {
		t.Errorf("level without a cluster: %v", out)
	}
}
