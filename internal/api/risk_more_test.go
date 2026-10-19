package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// downSearch is an OpenSearch every search fails on.
type downSearch struct{}

func (downSearch) Search(context.Context, string, map[string]any) (map[string]any, error) {
	return nil, errDown
}

// Without asset and identity lists their routes say so; an unknown list
// or value is a 404.
func TestLookupsOffAndUnknown(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Assets = nil })
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/lookups/assets"}, {"PUT", "/api/lookups/assets"}, {"GET", "/api/lookups/context?field=dest&value=x"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "", true); code != http.StatusServiceUnavailable || out["error"] != errLookupsOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
	ts, _ = newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/lookups/printers", "", true); code != http.StatusNotFound {
		t.Errorf("unknown list: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/lookups/context?field=dest&value=nowhere.example", "", true); code != http.StatusNotFound {
		t.Errorf("unknown value: %d", code)
	}
}

// The risk list is filtered by type and carries each object's asset
// context; a bad type is a 400 and a search that fails a 502.
func TestRiskObjectsMore(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := put(t, ts.URL+"/api/lookups/assets", "ip,owner,priority\n10.0.0.9,it-ops,critical\n"); code != http.StatusOK {
		t.Fatalf("assets: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/risk?type=printer", "", true); code != http.StatusBadRequest {
		t.Errorf("bad type: %d", code)
	}
	code, out := do(t, ts, "GET", "/api/risk?type=system", "", true)
	if code != http.StatusOK || !strings.Contains(out["query"].(string), "risk_object_type=system") {
		t.Fatalf("by type: %d %v", code, out)
	}
	var withContext int
	for _, o := range out["objects"].([]any) {
		if o.(map[string]any)["context"] != nil {
			withContext++
		}
	}
	if withContext != 1 {
		t.Errorf("objects %v", out["objects"])
	}
	code, out = do(t, ts, "GET", "/api/risk/object?object=10.0.0.9&type=system", "", true)
	if code != http.StatusOK || out["context"] == nil {
		t.Errorf("object with context: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/risk/object?object=bob&type=user&since=forever", "", true); code != http.StatusBadRequest {
		t.Errorf("object bad since: %d", code)
	}

	ts, _ = newTestServerWith(t, func(s *Server) { s.Engine = &search.Engine{Store: downSearch{}} })
	for _, path := range []string{"/api/risk", "/api/risk/object?object=bob&type=user"} {
		if code, _ := do(t, ts, "GET", path, "", true); code != http.StatusBadGateway {
			t.Errorf("%s with OpenSearch down: %d", path, code)
		}
	}
}
