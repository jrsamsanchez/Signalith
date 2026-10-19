// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/ticketing"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// tenantSet runs the servers of several tenants, by ID.
type tenantSet map[string]*Server

func (ts tenantSet) Server(id string) *Server { return ts[id] }
func (ts tenantSet) Servers() []*Server {
	var out []*Server
	for _, s := range ts {
		out = append(out, s)
	}
	return out
}
func (ts tenantSet) Changed(context.Context, string) error      { return nil }
func (ts tenantSet) SettingsChanged()                           {}
func (ts tenantSet) Ready() error                               { return nil }
func (ts tenantSet) NotebookStores() map[string]notebooks.Store { return nil }

// A tenant's ticketing connections, tickets and audit lines are its own:
// set up by the provider's users while in the tenant, used by its
// analysts with its cases only, and never seen, used or changed from
// another tenant. A tenant's own admins see their connections but do not
// change or test them, as they make the server send requests to the
// addresses they name.
func TestTicketingStaysInTenant(t *testing.T) {
	// Every ticketing route is the request's tenant's; changing and
	// testing connections is for the provider's users.
	for p, managed := range map[string]bool{
		"GET /api/ticketing": false, "PUT /api/ticketing": true, "POST /api/ticketing/test": true,
		"GET /api/cases/{id}/tickets": false, "POST /api/cases/{id}/tickets": false,
	} {
		if platform, m, shared := routeScope(p); platform || shared || m != managed {
			t.Errorf("%s: platform %v, managed %v, shared %v; want a tenant route, managed %v", p, platform, m, shared, managed)
		}
	}
	sn, requests := fakeServiceNow(t)
	reg, err := tenants.Open(tenants.File(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"acme", "beta"} {
		if _, err := reg.Add(id, id, "test", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	store := users.NewMemory()
	for _, u := range []users.NewUser{
		{Username: "padm", Role: users.Admin},
		{Username: "ada", Role: users.Admin, Tenant: "acme"},
		{Username: "andy", Role: users.Analyst, Tenant: "acme"},
		{Username: "bea", Role: users.Admin, Tenant: "beta"},
		{Username: "bob", Role: users.Analyst, Tenant: "beta"},
	} {
		u.Password = "role-password"
		if _, err := store.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	var logs syncBuffer
	base := slog.New(slog.NewTextHandler(&logs, nil))
	svcs := map[string]*ticketing.Service{}
	servers := tenantSet{}
	for _, id := range []string{"acme", "beta"} {
		newTestServerWith(t, func(s *Server) {
			// As tenantRuntime.start builds a tenant's server: its own
			// connections file, links and cases, and its log tagged
			// with the tenant.
			s.Tenants, s.Users, s.TenantID = reg, store, id
			s.Log = base.With("tenant", id)
			svc := &ticketing.Service{Settings: &ticketing.Manager{File: filepath.Join(t.TempDir(), "tickets.yaml")},
				Links: ticketing.NewMemory(), Cases: s.Cases, Server: "siem-a", Log: s.Log}
			s.Ticketing = &Ticketing{Service: svc}
			svcs[id], servers[id] = svc, s
		})
	}
	front, _, frontSvc := newTicketingServer(t, func(s *Server) {
		s.Tenants, s.Users, s.TenantRuntime = reg, store, servers
		s.Log = base
	})
	ctx := context.Background()
	now := time.Now().UTC()
	for id, s := range servers {
		if err := s.Cases.Create(ctx, &cases.Case{ID: "case-" + id, Title: id + "'s case", Severity: "high", Status: "new", Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
	}

	// The provider's admin sets up acme's connection, in acme.
	_, _, cookie := login(t, front, "padm", "role-password")
	if code, body, _ := call(t, front, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie); code != 200 {
		t.Fatalf("switch: %d %v", code, body)
	}
	save := `{"connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"` + sn.URL + `","auth":"basic",
		"username":"svc","password":"sn-password-123","allow_loopback":true}]}`
	if code, body, _ := call(t, front, "PUT", "/api/ticketing", save, "", "", cookie); code != 200 {
		t.Fatalf("save in acme: %d %v", code, body)
	}
	if set, _ := svcs["acme"].Settings.Settings(); len(set.Connections) != 1 {
		t.Fatalf("acme's connections: %+v", set.Connections)
	}
	for name, svc := range map[string]*ticketing.Service{"beta": svcs["beta"], "default": frontSvc} {
		if set, _ := svc.Settings.Settings(); len(set.Connections) != 0 {
			t.Errorf("acme's save reached %s's connections: %+v", name, set.Connections)
		}
	}
	// Audited as acme's, once.
	var saved string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "ticketing connections changed") {
			saved = line
		}
	}
	if strings.Count(saved, "tenant=acme") != 1 || !strings.Contains(saved, "by=padm") {
		t.Errorf("the save is not audited once as acme's: %s", saved)
	}

	// Beta sees none of it, and cannot use it.
	code, body := doAs(t, front, "bea@beta", "role-password", "GET", "/api/ticketing", "")
	if code != 200 || len(body["connections"].([]any)) != 0 {
		t.Errorf("beta's admin sees connections: %d %v", code, body)
	}
	code, body = doAs(t, front, "bob@beta", "role-password", "GET", "/api/cases/case-beta/tickets", "")
	if code != 200 || len(body["connections"].([]any)) != 0 {
		t.Errorf("beta's case offers connections: %d %v", code, body)
	}
	if code, _ := doAs(t, front, "bob@beta", "role-password", "POST", "/api/cases/case-beta/tickets", `{"connection":"desk"}`); code != http.StatusNotFound {
		t.Errorf("beta's analyst opening a ticket with acme's connection: %d, want 404", code)
	}
	// Nor reaches acme's cases.
	if code, _ := doAs(t, front, "bob@beta", "role-password", "POST", "/api/cases/case-acme/tickets", `{"connection":"desk"}`); code != http.StatusNotFound {
		t.Errorf("beta's analyst opening a ticket for acme's case: %d, want 404", code)
	}
	if code, _ := doAs(t, front, "bob@beta", "role-password", "GET", "/api/cases/case-acme/tickets", ""); code != http.StatusNotFound {
		t.Errorf("beta's analyst reading acme's case's tickets: %d, want 404", code)
	}
	// Nor tests it.
	if code, _ := doAs(t, front, "bea@beta", "role-password", "POST", "/api/ticketing/test", `{"id":"desk"}`); code != http.StatusForbidden {
		t.Errorf("beta's admin testing a connection: %d, want 403", code)
	}
	if n := len(requests()); n != 0 {
		t.Fatalf("beta's requests reached ServiceNow: %v", requests())
	}

	// The default tenant has no connection either.
	if code, _ := doAs(t, front, "padm", "role-password", "POST", "/api/cases/case-acme/tickets", `{"connection":"desk"}`); code != http.StatusNotFound {
		t.Errorf("the default tenant opening a ticket for acme's case: %d", code)
	}

	// Acme's analyst opens a ticket with it, for acme's case.
	code, body = doAs(t, front, "andy@acme", "role-password", "POST", "/api/cases/case-acme/tickets", `{"connection":"desk"}`)
	if code != http.StatusCreated {
		t.Fatalf("acme's ticket: %d %v", code, body)
	}
	if st, err := svcs["acme"].Links.Get(ctx, ticketing.LinkID("desk", "case-acme")); err != nil || st.State != ticketing.StateLinked {
		t.Errorf("acme's link: %+v %v", st, err)
	}
	for name, svc := range map[string]*ticketing.Service{"beta": svcs["beta"], "default": frontSvc} {
		if due, _ := svc.Links.Due(ctx); len(due) != 0 {
			t.Errorf("acme's ticket wrote %s's links: %+v", name, due)
		}
	}

	// Acme's own admin sees the connection, not where the file is, and
	// neither changes nor tests it.
	code, body = doAs(t, front, "ada@acme", "role-password", "GET", "/api/ticketing", "")
	if code != 200 || len(body["connections"].([]any)) != 1 || body["manage"] != false || body["provider_only"] != true || body["file"] != nil {
		t.Errorf("acme's admin's view: %d %v", code, body)
	}
	for _, r := range [][3]string{{"PUT", "/api/ticketing", `{"connections":[]}`}, {"POST", "/api/ticketing/test", `{"id":"desk"}`}} {
		if code, body := doAs(t, front, "ada@acme", "role-password", r[0], r[1], r[2]); code != http.StatusForbidden || body["code"] != "provider_only" {
			t.Errorf("acme's admin %s %s: %d %v", r[0], r[1], code, body)
		}
	}
	if set, _ := svcs["acme"].Settings.Settings(); len(set.Connections) != 1 {
		t.Errorf("acme's connections changed: %+v", set.Connections)
	}
}
