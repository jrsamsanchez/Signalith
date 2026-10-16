package api

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newTenantServer starts a server with tenants acme and off (turned off),
// a tenant admin of each (ada of acme, otto of off), and a provider
// analyst (pat), all with the password "role-password".
func newTenantServer(t *testing.T) (*Server, func(method, path, body, user string) (int, map[string]any)) {
	t.Helper()
	reg, err := tenants.Open(tenants.File(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := reg.Add("acme", "Acme", "test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Add("off", "Off", "test", now); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := reg.Change("off", nil, &off); err != nil {
		t.Fatal(err)
	}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Tenants = reg
		s.Users = users.NewMemory()
		for _, u := range []users.NewUser{
			{Username: "ada", Role: users.Admin, Tenant: "acme"},
			{Username: "otto", Role: users.Admin, Tenant: "off"},
			{Username: "pat", Role: users.Analyst},
		} {
			u.Password = "role-password"
			if _, err := s.Users.Create(context.Background(), u); err != nil {
				t.Fatal(err)
			}
		}
	})
	return srv, func(method, path, body, user string) (int, map[string]any) {
		t.Helper()
		return doAs(t, ts, user, "role-password", method, path, body)
	}
}

// A tenant's users can use no route about the server itself, and none of
// another tenant's data: until this server runs their tenant, every other
// route is refused too.
func TestTenantUsersStayInTheirTenant(t *testing.T) {
	s, do := newTenantServer(t)
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	for _, rt := range s.routes {
		if rt.Anytime {
			continue
		}
		method, path, _ := strings.Cut(rt.Pattern, " ")
		path = wildcard.ReplaceAllString(path, "x")
		code, body := do(method, path, "{}", "ada")
		want := "tenant_unavailable"
		if rt.Platform {
			want = "provider_only"
		}
		if body["code"] != want {
			t.Errorf("tenant admin %s: %d %v, want %s", rt.Pattern, code, body, want)
		}
	}
}

func TestDisabledTenantsUsersCannotSignIn(t *testing.T) {
	_, do := newTenantServer(t)
	if code, body := do("GET", "/api/me", "", "otto"); code != http.StatusForbidden || body["code"] != "tenant_disabled" {
		t.Errorf("user of a disabled tenant: %d %v", code, body)
	}
	if code, body := do("GET", "/api/me", "", "ada"); code != 200 || body["tenant"] != "acme" || body["active_tenant"] != "acme" {
		t.Errorf("tenant user's me: %d %v", code, body)
	}
	if code, body := do("GET", "/api/me", "", "pat"); code != 200 || body["tenant"] != "" || body["active_tenant"] != tenants.Default {
		t.Errorf("provider user's me: %d %v", code, body)
	}
}

// A tenant user whose tenant is not one this server knows cannot sign in.
func TestUnknownTenantsUsersCannotSignIn(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ghost", Role: users.Viewer, Tenant: "gone", Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if code, body := doAs(t, ts, "ghost", "role-password", "GET", "/api/me", ""); code != http.StatusForbidden || body["code"] != "tenant_disabled" {
		t.Errorf("user of an unknown tenant: %d %v", code, body)
	}
}

func TestProviderSwitchesTenants(t *testing.T) {
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		reg, err := tenants.Open(tenants.File(t.TempDir()))
		if err != nil {
			t.Fatal(err)
		}
		reg.Add("acme", "Acme", "test", time.Now())
		s.Tenants = reg
		s.Users = users.NewMemory()
		s.Users.Create(context.Background(), users.NewUser{Username: "pat", Role: users.Analyst, Password: "role-password"})
		s.Users.Create(context.Background(), users.NewUser{Username: "ada", Role: users.Admin, Tenant: "acme", Password: "role-password"})
	})
	_ = srv
	code, _, cookie := login(t, ts, "pat", "role-password")
	if code != 200 || cookie == nil {
		t.Fatalf("sign-in = %d", code)
	}
	code, list, _ := call(t, ts, "GET", "/api/tenants", "", "", "", cookie)
	if code != 200 || list["active"] != tenants.Default || list["enabled"] != true || len(list["tenants"].([]any)) != 2 {
		t.Fatalf("tenants = %d %v", code, list)
	}
	if code, _, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != 200 {
		t.Errorf("findings in the default tenant: %d", code)
	}
	for _, bad := range []string{"nope", "off", "", "ACME"} {
		if code, _, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"`+bad+`"}`, "", "", cookie); code != http.StatusNotFound && bad != "" {
			t.Errorf("switch to %q: %d", bad, code)
		}
	}
	if code, body, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie); code != 200 || body["active"] != "acme" {
		t.Fatalf("switch to acme: %d %v", code, body)
	}
	if _, me, _ := call(t, ts, "GET", "/api/me", "", "", "", cookie); me["active_tenant"] != "acme" || me["tenant"] != "" {
		t.Errorf("me after the switch: %v", me)
	}
	// Until this server runs acme, its data cannot be used, and nothing
	// falls back to the default tenant's.
	if code, body, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != http.StatusServiceUnavailable || body["code"] != "tenant_unavailable" {
		t.Errorf("findings in acme: %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"default"}`, "", "", cookie); code != 200 || body["active"] != tenants.Default {
		t.Fatalf("switch back: %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != 200 {
		t.Errorf("findings back in the default tenant: %d", code)
	}
	// Basic sign-ins cannot switch, and tenant users cannot at all.
	if code, body := doAs(t, ts, "pat", "role-password", "POST", "/api/tenants/switch", `{"tenant":"acme"}`); code != http.StatusBadRequest || body["code"] != "session_only" {
		t.Errorf("basic switch: %d %v", code, body)
	}
	_, _, adaCookie := login(t, ts, "ada", "role-password")
	if code, body, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"default"}`, "", "", adaCookie); code != http.StatusForbidden || body["code"] != "provider_only" {
		t.Errorf("tenant user switch: %d %v", code, body)
	}
}

// A provider user's session in a tenant that is turned off afterwards
// goes back to the default tenant.
func TestSwitchedTenantTurnedOff(t *testing.T) {
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Tenants = reg
		s.Users = users.NewMemory()
		s.Users.Create(context.Background(), users.NewUser{Username: "pat", Role: users.Analyst, Password: "role-password"})
	})
	_, _, cookie := login(t, ts, "pat", "role-password")
	if code, _, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie); code != 200 {
		t.Fatalf("switch: %d", code)
	}
	off := true
	if _, err := reg.Change("acme", nil, &off); err != nil {
		t.Fatal(err)
	}
	if _, me, _ := call(t, ts, "GET", "/api/me", "", "", "", cookie); me["active_tenant"] != tenants.Default {
		t.Errorf("me after acme was turned off: %v", me)
	}
}
