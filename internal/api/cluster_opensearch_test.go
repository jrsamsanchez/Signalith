package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// threeNodes answers as an OpenSearch of three nodes would, with one of
// its disks past the low watermark and one Signalith index without a
// replica.
func threeNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/_cluster/health":
		io.WriteString(w, `{"status":"yellow","number_of_nodes":3,"number_of_data_nodes":3,"unassigned_shards":2}`)
	case r.URL.Path == "/_cat/nodes":
		io.WriteString(w, `[{"name":"os-1","node.roles":"dimr","disk.used_percent":"40.5"},{"name":"os-2","node.roles":"dimr","disk.used_percent":"88.0"},{"name":"os-3","node.roles":"di","disk.used_percent":"10"}]`)
	case r.URL.Path == "/_cluster/settings":
		io.WriteString(w, `{"persistent":{"cluster.routing.allocation.disk.watermark.low":"87%"},"transient":{},"defaults":{"cluster.routing.allocation.disk.watermark.low":"85%","cluster.routing.allocation.disk.watermark.high":"90%","cluster.routing.allocation.disk.watermark.flood_stage":"95%"}}`)
	case strings.HasPrefix(r.URL.Path, "/_cat/indices/"):
		io.WriteString(w, `[{"index":"signalith-authentication-2026.10.14","rep":"0"},{"index":"signalith_config","rep":"1"}]`)
	default:
		http.NotFound(w, r)
	}
}

func TestClusterOpenSearchCard(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(threeNodes))
	defer fake.Close()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Backend = store.New(store.Config{URL: fake.URL})
		s.Config.OpenSearch.Replicas = "0"
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ana", Role: users.Analyst, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if code, _ := doAs(t, ts, "ana", "role-password", "GET", "/api/cluster/opensearch", ""); code != http.StatusForbidden {
		t.Errorf("analyst: %d", code)
	}
	code, out := do(t, ts, "GET", "/api/cluster/opensearch", "", true)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if out["status"] != "yellow" || out["nodes"] != float64(3) || out["manager_eligible"] != float64(2) || out["unassigned_shards"] != float64(2) {
		t.Errorf("counts: %v", out)
	}
	if out["suggest_auto"] != true || out["replicas_setting"] != "0" {
		t.Errorf("suggest: %v %v", out["suggest_auto"], out["replicas_setting"])
	}
	disk := out["disk"].([]any)
	if d := disk[1].(map[string]any); d["node"] != "os-2" || d["used_percent"] != 88.0 || d["low"] != 87.0 || d["flood"] != 95.0 {
		t.Errorf("disk %v", disk)
	}
	if nr := out["no_replicas"].([]any); len(nr) != 1 || nr[0] != "signalith-authentication-2026.10.14" {
		t.Errorf("no replicas %v", nr)
	}
	warnings := strings.Join(toStrings(out["warnings"]), "\n")
	for _, want := range []string{"Only 2 cluster-manager-eligible", "2 shards are on no node", "os-2's disk is 88% full", "1 Signalith index has no copy"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings lack %q:\n%s", want, warnings)
		}
	}
	if eps := out["endpoints"].([]any); len(eps) != 1 || eps[0].(map[string]any)["url"] != fake.URL {
		t.Errorf("endpoints %v", eps)
	}
}

// The fake OpenSearch answers no _cat request: those parts are unknown,
// and the card still shows.
func TestClusterOpenSearchUnknownAnswers(t *testing.T) {
	os := ostest.New(t)
	other := ostest.New(t)
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Backend = store.New(store.Config{URL: os.URL, URLs: other.URL})
		s.Config.OpenSearch.Replicas = config.ReplicasAuto
	})
	code, out := do(t, ts, "GET", "/api/cluster/opensearch", "", true)
	if code != 200 || out["status"] != "green" || out["manager_eligible"] != nil || out["suggest_auto"] != false {
		t.Fatalf("%d %v", code, out)
	}
	if w := toStrings(out["warnings"]); len(w) != 1 || !strings.HasPrefix(w[0], "One OpenSearch node") {
		t.Errorf("warnings %v", w)
	}
	if eps := out["endpoints"].([]any); len(eps) != 2 {
		t.Errorf("endpoints %v", eps)
	}

	// OpenSearch out of reach: the card says so.
	os.Close()
	other.Close()
	code, out = do(t, ts, "GET", "/api/cluster/opensearch", "", true)
	if code != 200 || out["status"] != "unreachable" {
		t.Fatalf("%d %v", code, out)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
