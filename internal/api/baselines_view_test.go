// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// baselineOf finds a check in the Baselines page's data.
func baselineOf(t *testing.T, out map[string]any, id string) map[string]any {
	t.Helper()
	for _, c := range out["checks"].([]any) {
		if c := c.(map[string]any); c["id"] == id {
			return c
		}
	}
	t.Fatalf("no check %s in %v", id, out["checks"])
	return nil
}

// The page says how far behind the baselines are, when each check ends
// learning, and why the checks that need the IP database wait. Saving
// needs the version read and settings that check; a reset carries over.
func TestBaselinesViewAndSave(t *testing.T) {
	fake := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: fake.URL}), "t")
	ctx := context.Background()
	if err := st.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	live := started.Add(-24 * time.Hour)
	_, ver, _, err := st.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveState(ctx, baselines.State{Through: started, LiveFrom: live, Checks: map[string]*baselines.CheckState{
		baselines.NewCountry: {Started: started}, baselines.NewNetwork: {Started: live},
	}}, ver); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Baselines = st })

	code, out := do(t, ts, "GET", "/api/baselines", "", true)
	if code != http.StatusOK || out["behind_s"] == nil || out["behind_s"].(float64) < 3000 {
		t.Fatalf("view: %d %v", code, out)
	}
	country := baselineOf(t, out, baselines.NewCountry)
	if country["learning_until"] == nil || !strings.Contains(country["waiting"].(string), "first sign-in from an internet address") {
		t.Errorf("new country %v", country)
	}
	if network := baselineOf(t, out, baselines.NewNetwork); network["learning_until"] != nil {
		t.Errorf("a check that learned from the history still learns: %v", network)
	}

	save := func(settings map[string]any, version string) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"settings": settings, "version": version})
		return do(t, ts, "PUT", "/api/baselines", string(b), true)
	}
	version, _ := out["version"].(string)
	if code, _ := save(map[string]any{}, "stale"); code != http.StatusConflict {
		t.Errorf("stale version: %d", code)
	}
	if code, out := save(map[string]any{"learning_days": 500}, version); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "learning period") {
		t.Errorf("bad settings: %d %v", code, out)
	}

	if code, out := do(t, ts, "POST", "/api/baselines/"+baselines.NewCountry+"/reset", "", true); code != http.StatusOK {
		t.Fatalf("reset: %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/baselines", "", true)
	code, out = save(map[string]any{"ip_database": "off"}, out["version"].(string))
	if code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	if w, _ := baselineOf(t, out, baselines.NewCountry)["waiting"].(string); !strings.Contains(w, "which is off") {
		t.Errorf("IP database off: %q", w)
	}
	set, _, err := st.Settings(ctx)
	if err != nil || set.Checks[baselines.NewCountry].ResetAt.IsZero() {
		t.Errorf("the reset did not carry over: %+v %v", set.Checks, err)
	}
}
