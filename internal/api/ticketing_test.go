// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/ticketing"
)

// fakeServiceNow answers the few Table API calls opening a ticket and
// testing a connection make, for the user svc with the password
// sn-password-123.
func fakeServiceNow(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "sn-password-123" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"message":"User Not Authenticated"}}`))
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/table/incident":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"sys_id": strings.Repeat("a", 32), "number": "INC0010001", "state": "1", "sys_updated_on": "2026-10-16 10:00:00"}})
		default:
			w.Write([]byte(`{"result":[]}`))
		}
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

func newTicketingServer(t *testing.T, change func(*Server)) (*httptest.Server, *Server, *ticketing.Service) {
	t.Helper()
	var srv *Server
	svc := &ticketing.Service{Settings: &ticketing.Manager{File: filepath.Join(t.TempDir(), "tickets.yaml")}, Links: ticketing.NewMemory(), Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Config.Server.PublicURL = "https://siem.example.com"
		svc.Cases = s.Cases
		svc.PublicURL = func() string { return "https://siem.example.com" }
		s.Ticketing = &Ticketing{Service: svc}
		if change != nil {
			change(s)
		}
	})
	return ts, srv, svc
}

func TestTicketingAPI(t *testing.T) {
	sn, requests := fakeServiceNow(t)
	ts, srv, svc := newTicketingServer(t, nil)

	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", "")
	if code != 200 || len(body["connections"].([]any)) != 0 || body["manage"] != true || body["marker"] != "[Signalith]" {
		t.Fatalf("empty: %d %v", code, body)
	}
	save := `{"connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"` + sn.URL + `","auth":"basic",
		"username":"svc","password":"sn-password-123","allow_loopback":true}]}`
	code, body = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", save)
	if code != 200 {
		t.Fatalf("save: %d %v", code, body)
	}
	if raw := notifyJSON(t, body); strings.Contains(raw, "sn-password-123") {
		t.Errorf("the answer holds the password: %s", raw)
	}
	c := body["connections"].([]any)[0].(map[string]any)
	if c["password_set"] != true || c["table"] != "incident" || c["label"] != "ServiceNow Desk" || c["statuses"].(map[string]any)["resolved"] != "6" {
		t.Errorf("connection view %v", c)
	}

	code, body = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", `{"connections":[{"name":"x","type":"jira","url":"http://example.com"}]}`)
	if code != 400 || len(body["problems"].([]any)) == 0 {
		t.Errorf("bad save: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", `{"revision":"old","connections":[]}`); code != 409 {
		t.Errorf("stale save: %d", code)
	}

	// Test, saved and being edited (with the saved password).
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"id":"desk"}`)
	if code != 200 || body["ok"] != true || !strings.Contains(body["message"].(string), "incident table can be read") {
		t.Errorf("test: %d %v", code, body)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"connection":{"id":"desk","name":"Desk","type":"servicenow","url":"`+sn.URL+`","auth":"basic","username":"bad","allow_loopback":true}}`)
	if code != 200 || body["ok"] != false || !strings.Contains(body["error"].(string), "401") {
		t.Errorf("failed test: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"id":"nope"}`); code != 404 {
		t.Errorf("unknown connection: %d", code)
	}

	// Open a ticket from a case.
	now := time.Now().UTC()
	if err := srv.Cases.Create(context.Background(), &cases.Case{ID: "case-1", Title: "Malware", Severity: "high", Status: "new", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-1/tickets", "")
	if code != 200 || body["available"] != true || len(body["connections"].([]any)) != 1 || len(body["tickets"].([]any)) != 0 {
		t.Fatalf("tickets: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-1/tickets", `{"connection":"nope"}`); code != 404 {
		t.Errorf("unknown connection: %d", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/nope/tickets", `{"connection":"desk"}`); code != 404 {
		t.Errorf("unknown case: %d", code)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-1/tickets", `{"connection":"desk"}`)
	if code != 201 || body["ticket"].(map[string]any)["key"] != "INC0010001" {
		t.Fatalf("create: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-1/tickets", `{"connection":"desk"}`); code != 409 {
		t.Errorf("second ticket: %d", code)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-1/tickets", "")
	tk := body["tickets"].([]any)
	if code != 200 || len(tk) != 1 || tk[0].(map[string]any)["state"] != "linked" || !strings.HasPrefix(tk[0].(map[string]any)["url"].(string), sn.URL+"/nav_to.do") {
		t.Errorf("tickets after create: %d %v", code, body)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-1", "")
	if code != 200 || !strings.Contains(notifyJSON(t, body), `"key":"INC0010001"`) {
		t.Errorf("case: %d %v", code, body)
	}
	if n := len(requests()); n < 3 {
		t.Errorf("requests %v", requests())
	}

	// A failed open says why.
	if err := srv.Cases.Create(context.Background(), &cases.Case{ID: "case-2", Title: "x", Severity: "low", Status: "new", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	in := `{"revision":"` + svc.Settings.Revision() + `","connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"` + sn.URL + `","auth":"basic","username":"svc","password":"wrong-password","allow_loopback":true}]}`
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", in); code != 200 {
		t.Fatalf("resave: %d %v", code, body)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-2/tickets", `{"connection":"desk"}`)
	if code != 502 || !strings.Contains(body["error"].(string), "401") || strings.Contains(body["error"].(string), "wrong-password") {
		t.Errorf("failed create: %d %v", code, body)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-2/tickets", "")
	if tk := body["tickets"].([]any); code != 200 || len(tk) != 1 || tk[0].(map[string]any)["state"] != "failed" || tk[0].(map[string]any)["error"] == "" {
		t.Errorf("failed ticket: %d %v", code, body)
	}
}

// Saving and testing connections go to the audit log with where the
// admin was, the hosts the connections reach, and whether a secret was
// replaced.
func TestTicketingAudit(t *testing.T) {
	sn, _ := fakeServiceNow(t)
	var logs syncBuffer
	ts, srv, _ := newTicketingServer(t, func(s *Server) { s.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	host := strings.TrimPrefix(sn.URL, "http://")
	now := time.Now().UTC()
	if err := srv.Cases.Create(context.Background(), &cases.Case{ID: "case-1", Title: "Malware", Severity: "high", Status: "new", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	save := `{"connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"` + sn.URL + `","auth":"basic",
		"username":"svc","password":"sn-password-123","allow_loopback":true}]}`
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", save); code != 200 {
		t.Fatalf("save: %d %v", code, body)
	}
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"id":"desk"}`); code != 200 || body["ok"] != true {
		t.Fatalf("test: %d %v", code, body)
	}
	var saved, tested string
	for _, line := range strings.Split(logs.String(), "\n") {
		switch {
		case strings.Contains(line, "ticketing connections changed"):
			saved = line
		case strings.Contains(line, "ticketing connection test passed"):
			tested = line
		}
	}
	for _, want := range []string{"audit=true", "by=admin", "client=", "hosts=" + host, "secret_replaced=Desk"} {
		if !strings.Contains(saved, want) {
			t.Errorf("save log lacks %s: %s", want, saved)
		}
	}
	for _, want := range []string{"audit=true", "by=admin", "client=", "host=" + host, "secret_replaced=false"} {
		if !strings.Contains(tested, want) {
			t.Errorf("test log lacks %s: %s", want, tested)
		}
	}
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-1/tickets", `{"connection":"desk"}`); code != 201 {
		t.Fatalf("open: %d %v", code, body)
	}
	opened := ""
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `msg="case.ticket_open:`) {
			opened = line
		}
	}
	for _, want := range []string{"audit=true", "by=admin", "target=case-1", "connection=Desk", "ticket=INC0010001", "queued=false"} {
		if !strings.Contains(opened, want) {
			t.Errorf("ticket log lacks %s: %s", want, opened)
		}
	}
	if strings.Contains(logs.String(), "sn-password-123") {
		t.Error("the log holds the password")
	}
}

// Another server than the one that runs the jobs queues the ticket.
func TestTicketingQueuedElsewhere(t *testing.T) {
	cl := &fakeCluster{}
	cl.set(true, "siem-a")
	ts, srv, svc := newTicketingServer(t, func(s *Server) { s.Cluster = cl })
	save := `{"connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"https://example.service-now.com","auth":"basic","username":"svc","password":"pw-123456"}]}`
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", save); code != 200 {
		t.Fatalf("save: %d %v", code, body)
	}
	cl.set(false, "siem-a")
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", "")
	if code != 200 || body["manage"] != false || body["runs_on"] != "siem-a" {
		t.Errorf("view elsewhere: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", `{"connections":[]}`); code != 409 {
		t.Errorf("save elsewhere: %d", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"id":"desk"}`); code != 409 {
		t.Errorf("test elsewhere: %d", code)
	}
	now := time.Now().UTC()
	if err := srv.Cases.Create(context.Background(), &cases.Case{ID: "case-1", Title: "x", Severity: "high", Status: "new", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/cases/case-1/tickets", `{"connection":"desk"}`)
	if code != 202 || body["queued"] != true || body["ticket"].(map[string]any)["state"] != "pending" {
		t.Errorf("queued: %d %v", code, body)
	}
	if st, err := svc.Links.Get(context.Background(), ticketing.LinkID("desk", "case-1")); err != nil || st.State != ticketing.StatePending {
		t.Errorf("link %+v %v", st, err)
	}
}

func TestTicketingRoles(t *testing.T) {
	ts, _ := newRoleServer(t)
	for _, who := range []string{"vera", "andy"} {
		for _, r := range [][2]string{{"GET", "/api/ticketing"}, {"PUT", "/api/ticketing"}, {"POST", "/api/ticketing/test"}} {
			if code, _ := doAs(t, ts, who, "role-password", r[0], r[1], "{}"); code != 403 {
				t.Errorf("%s %s %s = %d", who, r[0], r[1], code)
			}
		}
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "POST", "/api/cases/x/tickets", `{"connection":"a"}`); code != 403 {
		t.Errorf("viewer opens a ticket: %d", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", ""); code != 503 {
		t.Errorf("ticketing off: %d", code)
	}
}
