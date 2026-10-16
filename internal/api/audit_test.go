package api

import (
	"context"
	"net/http"
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
