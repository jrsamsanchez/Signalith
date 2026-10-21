// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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

// One value one user learned is asked to be forgotten by its own route;
// saving the settings keeps the request (UEBA-04).
func TestBaselinesUnlearn(t *testing.T) {
	fake := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: fake.URL}), "t")
	if err := st.EnsureIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Baselines = st })
	path := "/api/baselines/" + baselines.NewCountry + "/unlearn"
	for _, c := range []struct {
		path, body string
		code       int
	}{
		{"/api/baselines/no-such-check/unlearn", `{"entity":"alice","value":"BR"}`, http.StatusNotFound},
		{path, `{"entity":"alice"}`, http.StatusBadRequest},
		{path, `{"entity":"","value":"BR"}`, http.StatusBadRequest},
		{"/api/baselines/" + baselines.DataVolume + "/unlearn", `{"entity":"db-01","value":"5 GB"}`, http.StatusBadRequest},
	} {
		if code, out := do(t, ts, "POST", c.path, c.body, true); code != c.code {
			t.Errorf("%s %s: %d %v", c.path, c.body, code, out)
		}
	}
	if code, out := do(t, ts, "POST", path, `{"entity":" alice ","value":"BR"}`, true); code != http.StatusOK {
		t.Fatalf("unlearn: %d %v", code, out)
	}
	code, out := do(t, ts, "GET", "/api/baselines", "", true)
	if code != http.StatusOK {
		t.Fatalf("GET: %d", code)
	}
	for _, c := range out["checks"].([]any) {
		if m := c.(map[string]any); m["id"] == baselines.NewCountry && m["unlearning"] != 1.0 {
			t.Errorf("unlearning = %v", m["unlearning"])
		}
	}
	// The page saves its settings without the request; it stays.
	if code, out := do(t, ts, "PUT", "/api/baselines", `{"version":"`+out["version"].(string)+`","settings":{"learning_days":7}}`, true); code != http.StatusOK {
		t.Fatalf("PUT: %d %v", code, out)
	}
	set, _, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u := set.Checks[baselines.NewCountry].Unlearn
	if len(u) != 1 || u[0].Entity != "alice" || u[0].Value != "BR" || u[0].By != "admin" || u[0].At.IsZero() {
		t.Errorf("unlearn = %+v", u)
	}
	// Only admins.
	ts2, _ := newRoleServer(t)
	if code, _ := doAs(t, ts2, "andy", "role-password", "POST", path, `{"entity":"alice","value":"BR"}`); code != http.StatusForbidden {
		t.Errorf("analyst: %d", code)
	}
}
