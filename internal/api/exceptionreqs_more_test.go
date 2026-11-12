// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/exceptionreqs"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// brokenRequests is an exception request store that cannot be read or
// changed.
type brokenRequests struct{}

func (brokenRequests) List(context.Context) ([]exceptionreqs.Request, error) {
	return nil, errors.New("store down")
}
func (brokenRequests) Modify(context.Context, func([]exceptionreqs.Request) ([]exceptionreqs.Request, error)) error {
	return errors.New("store down")
}

// The proposal and the decisions check what they are sent before they
// change anything: malformed bodies, bad finding updates, notes with
// control characters or too long, and requests that do not exist.
func TestExceptionRequestInputChecks(t *testing.T) {
	var srv *Server
	var ahead atomic.Int64
	mem := &exceptionreqs.Memory{Now: func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }}
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.ExceptionRequests = mem
	})
	now := time.Now()
	for _, id := range []string{"f-1", "f-2"} {
		if err := srv.Findings.Create(context.Background(), &findings.Finding{ID: id, DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium",
			Status: findings.StatusNew, Result: map[string]any{"user": "svc-" + id}, Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		body string
		want string
	}{
		{`{`, "must be JSON"},
		{`{"fields":["user"],"comment":"x","update":{"status":"bogus"}}`, "status must be one of"},
		{`{"fields":["user"],"comment":"x","update":{"severity":"huge"}}`, "severity must be one of"},
		{`{"fields":["user"],"comment":"` + strings.Repeat("x", 20000) + `"}`, ""},
	} {
		code, out := do(t, ts, "POST", "/api/findings/f-1/propose-exception", c.body, true)
		if msg, _ := out["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, c.want) {
			t.Errorf("propose %.60s: %d %v", c.body, code, out)
		}
	}
	if rs, _ := mem.List(t.Context()); len(rs) != 0 {
		t.Fatalf("refused proposals were kept: %v", rs)
	}

	// A proposal with a comment for the finding says both on it.
	code, out := do(t, ts, "POST", "/api/findings/f-1/propose-exception",
		`{"fields":["user"],"comment":"backup job","update":{"status":"closed","disposition":"false_positive","comment":"closing as expected"}}`, true)
	if code != 200 {
		t.Fatalf("propose: %d %v", code, out)
	}
	id := out["request"].(map[string]any)["id"].(string)
	f, _ := srv.Findings.Get(t.Context(), "f-1")
	if last := f.Comments[len(f.Comments)-1].Text; !strings.Contains(last, "backup job") || !strings.Contains(last, "closing as expected") {
		t.Errorf("finding comment %q", last)
	}

	unknown := exceptionreqs.NewID()
	for _, c := range []struct {
		path, body string
		status     int
	}{
		{"/api/exception-requests/" + id + "/approve", `{`, 400},
		{"/api/exception-requests/" + id + "/approve", `{"note":"` + strings.Repeat("n", exceptionreqs.MaxNote+1) + `"}`, 400},
		{"/api/exception-requests/" + id + "/decline", `{`, 400},
		{"/api/exception-requests/" + id + "/decline", `{"note":"bell\u0007"}`, 400},
		{"/api/exception-requests/nope/decline", `{}`, 404},
		{"/api/exception-requests/" + unknown + "/decline", `{}`, 404},
		{"/api/exception-requests/" + unknown + "/approve", `{}`, 404},
	} {
		if code, out := do(t, ts, "POST", c.path, c.body, true); code != c.status {
			t.Errorf("%s %.40s: %d %v", c.path, c.body, code, out)
		}
	}
	// The request still waits for a decision.
	if rs, _ := mem.List(t.Context()); len(rs) != 1 || rs[0].Status != exceptionreqs.Pending {
		t.Errorf("after refused decisions: %+v", rs)
	}

	// Once past its time it expires; the next change stamps when, and a
	// decision on it is refused.
	ahead.Store(int64(exceptionreqs.ExpireAfter + time.Hour))
	if code, out := do(t, ts, "POST", "/api/findings/f-2/propose-exception", `{"fields":["user"],"comment":"another"}`, true); code != 200 {
		t.Fatalf("second proposal: %d %v", code, out)
	}
	rs, _ := mem.List(t.Context())
	var expired *exceptionreqs.Request
	for i := range rs {
		if rs[i].ID == id {
			expired = &rs[i]
		}
	}
	if expired == nil || expired.Status != exceptionreqs.Expired || expired.Decided == nil {
		t.Fatalf("expired request %+v", expired)
	}
	if code, _ := do(t, ts, "POST", "/api/exception-requests/"+id+"/decline", `{}`, true); code != http.StatusConflict {
		t.Errorf("decline an expired request: %d", code)
	}
}

// A store that cannot be read answers 502, never a list that looks empty.
func TestExceptionRequestsStoreDown(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.ExceptionRequests = brokenRequests{} })
	if code, out := do(t, ts, "GET", "/api/exception-requests", "", true); code != http.StatusBadGateway || out["requests"] != nil {
		t.Errorf("list: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/exception-requests/"+exceptionreqs.NewID()+"/decline", `{}`, true); code != http.StatusBadGateway {
		t.Errorf("decline: %d", code)
	}
}
