// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// The default tenant keeps the ticket sync index it always had, so an
// install that turns tenants on keeps its links; each other tenant's is
// under its own prefix.
func TestTicketSyncIndexPerTenant(t *testing.T) {
	for id, want := range map[string]string{
		tenants.Default: "signalith_ticket_sync",
		"acme":          "signalith.t.acme_ticket_sync",
		"beta":          "signalith.t.beta_ticket_sync",
	} {
		if got := NewOpenSearch(nil, tenants.Prefix("signalith", id)).Index; got != want {
			t.Errorf("tenant %s: index %q, want %q", id, got, want)
		}
	}
}

// Each tenant has a Service of its own, built from its own connections,
// cases and links (cmd/signalith/tenantruntime.go). Two tenants whose
// connections even have the same ID never reach each other's: a pass of
// tenant A's sync opens tickets for A's cases only, in A's system, and
// writes nothing of B's.
func TestTenantSyncStaysInTenant(t *testing.T) {
	fa := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	fb := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	auto := func(f *fakeJira) Connection {
		c := jiraCloudConn(f)
		c.AutoCreate, c.AutoMinSeverity = true, "low"
		c.AutoSince = newClock().Now().Add(-time.Hour)
		return c
	}
	a, b := newEnv(t, auto(fa)), newEnv(t, auto(fb))
	a.newCase("case-a", "Acme's case", "high")
	b.newCase("case-b", "Beta's case", "high")

	a.pass()
	if fa.made != 1 || fb.made != 0 {
		t.Fatalf("after acme's pass: %d issues in acme's Jira, %d in beta's", fa.made, fb.made)
	}
	if got := fa.issue("SEC-1").summary; got != "Acme's case" {
		t.Errorf("acme's Jira has %q", got)
	}
	if c := b.getCase("case-b"); len(c.Tickets) != 0 {
		t.Errorf("acme's sync gave beta's case tickets %+v", c.Tickets)
	}
	if links, _ := b.links.Due(context.Background()); len(links) != 0 {
		t.Errorf("acme's sync wrote beta's links %+v", links)
	}
	if _, err := a.links.Get(context.Background(), LinkID("jc", "case-b")); err == nil {
		t.Error("acme's links have one for beta's case")
	}

	b.pass()
	if fa.made != 1 || fb.made != 1 || fb.issue("SEC-1").summary != "Beta's case" {
		t.Errorf("after beta's pass: %d issues in acme's Jira, %d in beta's", fa.made, fb.made)
	}
	if c := a.getCase("case-a"); len(c.Tickets) != 1 || c.Tickets[0].URL != fa.URL()+"/browse/SEC-1" {
		t.Errorf("acme's case tickets %+v", c.Tickets)
	}
	// A note on beta's case goes to beta's ticket only.
	b.note("case-b", "Beta's note")
	a.pass()
	b.pass()
	if n := len(fa.issue("SEC-1").comments); n != 0 {
		t.Errorf("beta's note reached acme's Jira: %d comments", n)
	}
	if n := len(fb.issue("SEC-1").comments); n != 1 {
		t.Errorf("beta's ticket has %d comments, want 1", n)
	}

	// Opening a ticket by hand: tenant B cannot name a connection only
	// A has, as B's Service has no such connection.
	if _, err := b.svc.Create(context.Background(), "case-b", "acmeonly", "bob"); err != ErrNoConnection {
		t.Errorf("beta opening a ticket with a connection it does not have: %v, want ErrNoConnection", err)
	}
	// Nor A's connection with B's case.
	if _, err := a.svc.Create(context.Background(), "case-b", "jc", "ann"); err == nil {
		t.Error("acme opened a ticket for beta's case")
	}
}

// A connection that is deleted, or given a new secret, leaves no OAuth
// token or Jira account of its own in memory once the connections are
// saved; the others keep theirs, and so does every other tenant.
func TestSavingForgetsDeletedConnections(t *testing.T) {
	f := newFakeSN(t, "Bearer none-yet")
	f.clientID, f.clientSecret = "signalith-client", "oauth-client-secret-1"
	sn := snConn(f)
	sn.Auth, sn.Username, sn.Password = AuthOAuth, "", ""
	sn.ClientID, sn.ClientSecret = "signalith-client", "oauth-client-secret-1"
	j := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	jc := jiraCloudConn(j)
	e := newEnv(t, sn, jc)
	// Another tenant with connections of the same IDs.
	other := newEnv(t, sn, jc)
	ctx := context.Background()
	for _, env := range []*env{e, other} {
		env.newCase("case-1", "x", "critical")
		if _, err := env.svc.Create(ctx, "case-1", "sn", "ann"); err != nil {
			t.Fatal(err)
		}
		if _, err := env.svc.Create(ctx, "case-1", "jc", "ann"); err != nil {
			t.Fatal(err)
		}
		// A comment from Jira: the sync asks which account is its own.
		env.pass()
	}
	j.humanComment("SEC-1", "Dana Scully", "from Jira")
	j.humanComment("SEC-2", "Dana Scully", "from Jira")
	e.pass()
	other.pass()
	cached := func(env *env) (token, self bool) {
		token = len(env.svc.tokens.all("sn:")) > 0
		_, self = env.svc.selves.Load("jc:")
		return
	}
	for name, env := range map[string]*env{"this tenant": e, "the other tenant": other} {
		if tok, self := cached(env); !tok || !self {
			t.Fatalf("%s: before the save, token cached %v, account cached %v", name, tok, self)
		}
	}

	// The ServiceNow connection is deleted: its token goes, Jira's
	// account stays.
	m := e.svc.Settings
	set, _ := m.Settings()
	m.mu.Lock()
	err := m.save(Settings{Connections: []Connection{set.Connections[1]}})
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	set, _ = m.Settings()
	e.svc.Forget(set)
	if tok, self := cached(e); tok || !self {
		t.Errorf("after deleting ServiceNow: token cached %v (want false), account cached %v (want true)", tok, self)
	}
	// Every connection deleted, through the page's save: the next pass
	// forgets too, even without Forget.
	if _, err := m.Save(Input{Connections: []ConnectionInput{}}); err != nil {
		t.Fatal(err)
	}
	e.pass()
	if tok, self := cached(e); tok || self {
		t.Errorf("after deleting everything: token cached %v, account cached %v", tok, self)
	}
	// The other tenant's are untouched.
	if tok, self := cached(other); !tok || !self {
		t.Errorf("the other tenant lost its cache: token %v, account %v", tok, self)
	}

	// A new client secret: the token issued for the old one goes.
	set, _ = other.svc.Settings.Settings()
	conns := append([]Connection(nil), set.Connections...)
	conns[0].ClientSecret = "oauth-client-secret-2"
	other.svc.Forget(Settings{Connections: conns})
	if tok, self := cached(other); tok || !self {
		t.Errorf("after a new client secret: token cached %v (want false), account cached %v (want true)", tok, self)
	}
}
