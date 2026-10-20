// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestAuditOffOnAServerOfItsOwn(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := do(t, ts, http.MethodGet, "/api/audit", "", true)
	if code != http.StatusOK || out["enabled"] != false {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := do(t, ts, http.MethodGet, "/api/audit", "", false); code != http.StatusUnauthorized {
		t.Errorf("without sign-in: %d", code)
	}
}

func TestAuditSearch(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	at := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	evs := []audit.Event{
		{Time: at, Server: "siem-a", NodeID: "a", User: "admin", Action: "users.create", Message: "users.create: user added", Seq: 1},
		{Time: at.Add(time.Minute), Server: "siem-b", NodeID: "b", User: "jlee", Action: "settings.save", Message: "settings.save: saved", Seq: 1},
	}
	if err := audit.Write(context.Background(), cl, "signalith", evs); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Audit = &Audit{Client: cl, Prefix: "signalith", Shared: func() bool { return true }}
	})
	code, out := do(t, ts, http.MethodGet, "/api/audit?server=siem-b", "", true)
	events, _ := out["events"].([]any)
	if code != http.StatusOK || len(events) != 1 || events[0].(map[string]any)["user"] != "jlee" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = do(t, ts, http.MethodGet, "/api/audit?size=1", "", true)
	events, _ = out["events"].([]any)
	if code != http.StatusOK || len(events) != 1 || events[0].(map[string]any)["server"] != "siem-b" || out["next"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := do(t, ts, http.MethodGet, "/api/audit?from=yesterday", "", true); code != http.StatusBadRequest {
		t.Errorf("bad time: %d", code)
	}
}

func TestAuditVerify(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	key := []byte("0123456789abcdef0123456789abcdef")
	sink := audit.NewSink(audit.SinkOptions{Dir: filepath.Join(t.TempDir(), "spool"), Client: cl, Prefix: "signalith", Server: "siem-a", NodeID: "a"})
	t.Cleanup(func() { _ = sink.Close() })
	sink.SetKeySource(func() (string, []byte) { return "k1", key })
	for i := range 3 {
		sink.Add(audit.Event{Action: "users.create", Message: fmt.Sprint("users.create: user ", i)})
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Audit = &Audit{Client: cl, Prefix: "signalith", Shared: func() bool { return true },
			Keys: func() audit.KeyFunc {
				return func(kid string) []byte {
					if kid == "k1" {
						return key
					}
					return nil
				}
			}}
	})
	code, out := do(t, ts, http.MethodGet, "/api/audit/verify", "", true)
	rep, _ := out["report"].(map[string]any)
	if code != http.StatusOK || out["tampered"] != false || rep["ok"] != float64(3) {
		t.Fatalf("%d %v", code, out)
	}

	// A record changed in OpenSearch shows.
	page, err := audit.Search(context.Background(), cl, "signalith", audit.Query{Size: 1})
	if err != nil || len(page.Events) != 1 {
		t.Fatal(page, err)
	}
	h := page.Events[0]
	src := fake.Source(h.Index, h.ID)
	src["message"] = "nothing happened"
	if err := cl.Do(context.Background(), http.MethodPut, "/"+h.Index+"/_doc/"+h.ID, src, nil); err != nil {
		t.Fatal(err)
	}
	code, out = do(t, ts, http.MethodGet, "/api/audit/verify?server=siem-a", "", true)
	rep, _ = out["report"].(map[string]any)
	if code != http.StatusOK || out["tampered"] != true || rep["edited"] != float64(1) {
		t.Fatalf("after the change: %d %v", code, out)
	}
	if code, _ := do(t, ts, http.MethodGet, "/api/audit/verify?to=soon", "", true); code != http.StatusBadRequest {
		t.Errorf("bad time: %d", code)
	}
}

func TestAuditVerifyOffOnAServerOfItsOwn(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, http.MethodGet, "/api/audit/verify", "", true); code != http.StatusOK || out["enabled"] != false {
		t.Fatalf("%d %v", code, out)
	}
}
