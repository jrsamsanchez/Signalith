// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func newBaselinesServer(t *testing.T) (*httptest.Server, *ostest.Server, *baselines.Store) {
	t.Helper()
	fake := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: fake.URL}), "t")
	if err := st.EnsureIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Baselines = st })
	return ts, fake, st
}

// failWrites makes every write of the baselines settings answer status.
func failWrites(fake *ostest.Server, status int, typ string) {
	fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "PUT" && strings.Contains(path, "/settings") {
			return &ostest.Fault{Status: status, Type: typ}
		}
		return nil
	})
}

// Settings that keep changing under a save are retried a few times and
// then refused with 409; a write OpenSearch refuses is a 502; neither
// saves anything.
func TestBaselineSavesUnderConflict(t *testing.T) {
	ts, fake, st := newBaselinesServer(t)
	unlearn := "/api/baselines/" + baselines.NewCountry + "/unlearn"
	reset := "/api/baselines/" + baselines.NewCountry + "/reset"
	if code, out := do(t, ts, "POST", unlearn, `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d %v", code, out)
	}
	// One save first, so the settings exist and later ones replace them.
	if code, out := do(t, ts, "POST", unlearn, `{"entity":"alice","value":"BR"}`, true); code != http.StatusOK {
		t.Fatalf("unlearn: %d %v", code, out)
	}
	_, out := do(t, ts, "GET", "/api/baselines", "", true)
	version, _ := out["version"].(string)

	failWrites(fake, http.StatusConflict, "version_conflict_engine_exception")
	for _, c := range []struct{ method, path, body string }{
		{"POST", unlearn, `{"entity":"bob","value":"FR"}`},
		{"POST", reset, ``},
		{"PUT", "/api/baselines", `{"version":"` + version + `","settings":{"learning_days":9}}`},
	} {
		if code, out := do(t, ts, c.method, c.path, c.body, true); code != http.StatusConflict {
			t.Errorf("%s %s while it keeps changing: %d %v", c.method, c.path, code, out)
		}
	}
	failWrites(fake, http.StatusInternalServerError, "exception")
	for _, c := range []struct{ method, path, body string }{
		{"POST", unlearn, `{"entity":"bob","value":"FR"}`},
		{"POST", reset, ``},
		{"PUT", "/api/baselines", `{"version":"` + version + `","settings":{"learning_days":9}}`},
	} {
		if code, out := do(t, ts, c.method, c.path, c.body, true); code != http.StatusBadGateway {
			t.Errorf("%s %s with OpenSearch refusing: %d %v", c.method, c.path, code, out)
		}
	}
	fake.SetFault(nil)
	set, _, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cs := set.Checks[baselines.NewCountry]
	if len(cs.Unlearn) != 1 || cs.Unlearn[0].Entity != "alice" || !cs.ResetAt.IsZero() || set.LearningDays == 9 {
		t.Errorf("settings changed by refused saves: %+v %+v", cs, set)
	}

	// The state cannot be read: 502 before anything is saved.
	fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "GET" && strings.Contains(path, "/state") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "exception"}
		}
		return nil
	})
	if code, _ := do(t, ts, "POST", unlearn, `{"entity":"carol","value":"DE"}`, true); code != http.StatusBadGateway {
		t.Errorf("unlearn with the state unreadable: %d", code)
	}
	fake.SetFault(nil)
}

// At most MaxUnlearn values wait to be forgotten at once.
func TestBaselineUnlearnQueueIsBounded(t *testing.T) {
	ts, _, st := newBaselinesServer(t)
	ctx := context.Background()
	set, cur, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Checks == nil {
		set.Checks = map[string]baselines.CheckSettings{}
	}
	cs := set.Checks[baselines.NewCountry]
	at := time.Now().UTC().Add(time.Hour)
	for i := range baselines.MaxUnlearn {
		cs.Unlearn = append(cs.Unlearn, baselines.ForgetValue{Entity: "u", Value: string(rune('A'+i%26)) + string(rune('A'+i/26)), At: at.Add(time.Duration(i) * time.Second), By: "admin"})
	}
	set.Checks[baselines.NewCountry] = cs
	if _, err := st.SaveSettings(ctx, set, cur); err != nil {
		t.Fatal(err)
	}
	code, out := do(t, ts, "POST", "/api/baselines/"+baselines.NewCountry+"/unlearn", `{"entity":"alice","value":"BR"}`, true)
	if msg, _ := out["error"].(string); code != http.StatusConflict || !strings.Contains(msg, "too many values") {
		t.Errorf("full queue: %d %v", code, out)
	}
}
