package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// someTenants runs the servers of several tenants; ready is what Ready
// says, nil once this server runs them.
type someTenants struct {
	srvs  []*Server
	ready atomic.Pointer[error]
}

func (o *someTenants) Server(id string) *Server {
	for _, s := range o.srvs {
		if s.TenantID == id {
			return s
		}
	}
	return nil
}
func (o *someTenants) Servers() []*Server                         { return o.srvs }
func (o *someTenants) Changed(context.Context, string) error      { return nil }
func (o *someTenants) SettingsChanged()                           {}
func (o *someTenants) NotebookStores() map[string]notebooks.Store { return nil }
func (o *someTenants) Ready() error {
	if e := o.ready.Load(); e != nil {
		return *e
	}
	return nil
}

const (
	acmeToken = "tok-acme-000000000000"
	offToken  = "tok-off-0000000000000"
)

// tenantFront is the default tenant's server, running acme (with its own
// shared token) and off (turned off).
func tenantFront(t *testing.T) (*Server, *Server, *someTenants, func(path, body, token string) (int, map[string]any)) {
	t.Helper()
	reg, err := tenants.Open(tenants.File(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, id := range []string{"acme", "off"} {
		if _, err := reg.Add(id, strings.ToUpper(id[:1])+id[1:], "test", now); err != nil {
			t.Fatal(err)
		}
	}
	off := true
	if _, err := reg.Change("off", nil, &off, "test"); err != nil {
		t.Fatal(err)
	}
	rt := &someTenants{}
	for id, tok := range map[string]string{"acme": acmeToken, "off": offToken} {
		newTestServerWith(t, func(s *Server) {
			s.Tenants, s.TenantID = reg, id
			s.Config.Ingest.Tokens = []string{tok}
			s.Config.Ingest.HEC = true
			rt.srvs = append(rt.srvs, s)
		})
	}
	var front *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		front = s
		s.Tenants = reg
		s.TenantRuntime = rt
		s.Config.Ingest.HEC = true
	})
	acme := rt.Server("acme")
	return front, acme, rt, func(path, body, token string) (int, map[string]any) {
		t.Helper()
		return hecSend(t, ts.URL, path, "Splunk "+token, body, nil)
	}
}

// An agent token belongs to at most one tenant: the default tenant's
// server finds which one and hands the request to that tenant's server,
// or tells the agent to send again while another server runs the
// tenants. A tenant that is turned off has no tokens here.
func TestTokenTenant(t *testing.T) {
	front, acme, rt, _ := tenantFront(t)
	notLoaded := "sgl_" + strings.Repeat("b", 52)
	for _, c := range []struct {
		tok  string
		want *Server
		wait bool
	}{
		{"", nil, false},
		{"tok-0123456789abcdef", nil, false}, // the default tenant's own
		{acmeToken, acme, false},
		{offToken, nil, false},
		{"tok-nobody-000000000", nil, false},
		{notLoaded, acme, false}, // the first tenant still reading its tokens
	} {
		if got, wait := front.tokenTenant(c.tok); got != c.want || wait != c.wait {
			t.Errorf("tokenTenant(%q) = %v, %v", c.tok, got, wait)
		}
	}
	// A tenant's server asks no further.
	if got, wait := acme.tokenTenant(acmeToken); got != nil || wait {
		t.Errorf("on a tenant's own server: %v %v", got, wait)
	}

	// Another server runs the tenants now.
	notNow := errors.New("another server runs the tenants")
	rt.ready.Store(&notNow)
	for _, c := range []struct {
		tok  string
		want *Server
		wait bool
	}{
		{acmeToken, acme, true},
		{notLoaded, nil, true},
		{"tok-nobody-000000000", nil, false},
	} {
		if got, wait := front.tokenTenant(c.tok); got != c.want || wait != c.wait {
			t.Errorf("not running: tokenTenant(%q) = %v, %v", c.tok, got, wait)
		}
	}
}

// HEC with a tenant's token reaches that tenant's server, which stores
// the event; while another server runs the tenants the sender is told to
// send again.
func TestHECTenantToken(t *testing.T) {
	_, _, rt, send := tenantFront(t)
	event := `{"event":"hello","host":"app1"}`
	code, out := send("/services/collector/event", event, acmeToken)
	if code != http.StatusOK || out["text"] != "Success" {
		t.Errorf("acme's event: %d %v", code, out)
	}
	notNow := errors.New("another server runs the tenants")
	rt.ready.Store(&notNow)
	code, out = send("/services/collector/event", event, acmeToken)
	if code != http.StatusServiceUnavailable || out["text"] != tenantAgentWait {
		t.Errorf("while another server runs acme: %d %v", code, out)
	}
}
