// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The audit search pages with the next value it gave, refuses a size or
// page it cannot use, and says when OpenSearch cannot be searched.
func TestAuditSearchPagesAndRefusals(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	evs := []audit.Event{
		{Time: at, Server: "siem-a", NodeID: "a", User: "admin", Action: "users.create", Message: "users.create: user added", Seq: 1},
		{Time: at.Add(time.Minute), Server: "siem-a", NodeID: "a", User: "admin", Action: "users.delete", Message: "users.delete: user removed", Seq: 2},
	}
	if err := audit.Write(context.Background(), cl, "signalith", evs); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Audit = &Audit{Client: cl, Prefix: "signalith", Shared: func() bool { return true }}
	})
	for _, q := range []string{"size=0", "size=many", "after=not-json"} {
		if code, _ := do(t, ts, http.MethodGet, "/api/audit?"+q, "", true); code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, code)
		}
	}
	from := url.QueryEscape(at.Add(-time.Minute).Format(time.RFC3339))
	code, out := do(t, ts, http.MethodGet, "/api/audit?size=1&from="+from, "", true)
	next, _ := out["next"].(string)
	if code != http.StatusOK || next == "" {
		t.Fatalf("first page: %d %v", code, out)
	}
	code, out = do(t, ts, http.MethodGet, "/api/audit?size=1&from="+from+"&after="+url.QueryEscape(next), "", true)
	events, _ := out["events"].([]any)
	if code != http.StatusOK || len(events) != 1 || events[0].(map[string]any)["action"] != "users.create" {
		t.Errorf("second page: %d %v", code, out)
	}

	fake.Close()
	for _, path := range []string{"/api/audit", "/api/audit/verify"} {
		if code, _ := do(t, ts, http.MethodGet, path, "", true); code != http.StatusServiceUnavailable {
			t.Errorf("%s with OpenSearch down: %d", path, code)
		}
	}
}
