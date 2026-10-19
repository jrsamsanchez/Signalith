package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Without baselines the routes say so; a check's profiles are reset by
// name; OpenSearch down is a 502.
func TestBaselinesResetAndErrors(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/baselines"}, {"PUT", "/api/baselines"}, {"POST", "/api/baselines/" + baselines.NewCountry + "/reset"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "{}", true); code != http.StatusServiceUnavailable || out["error"] != errBaselinesOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}

	fake := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: fake.URL}), "t")
	if err := st.EnsureIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ = newTestServerWith(t, func(s *Server) { s.Baselines = st })
	if code, _ := do(t, ts, "PUT", "/api/baselines", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/baselines/no-such-check/reset", "", true); code != http.StatusNotFound {
		t.Errorf("unknown check: %d", code)
	}
	code, out := do(t, ts, "POST", "/api/baselines/"+baselines.NewCountry+"/reset", "", true)
	if code != http.StatusOK || out["checks"] == nil {
		t.Fatalf("reset: %d %v", code, out)
	}
	set, _, err := st.Settings(context.Background())
	if err != nil || set.Checks[baselines.NewCountry].ResetAt.IsZero() {
		t.Errorf("not reset: %+v %v", set.Checks, err)
	}

	fake.Close()
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/baselines"}, {"POST", "/api/baselines/" + baselines.NewCountry + "/reset"},
	} {
		if code, _ := do(t, ts, rt.method, rt.path, "", true); code != http.StatusBadGateway {
			t.Errorf("%s %s with OpenSearch down: %d", rt.method, rt.path, code)
		}
	}
}
