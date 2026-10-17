package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
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
	if _, err := reg.Change("off", nil, &off, "test"); err != nil {
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
		if rt.Anytime || rt.Shared {
			continue
		}
		method, path, _ := strings.Cut(rt.Pattern, " ")
		path = wildcard.ReplaceAllString(path, "x")
		code, body := do(method, path, "{}", "ada")
		want := "tenant_unavailable"
		if rt.Platform || rt.Managed {
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

// A provider user's session in a tenant that is turned off afterwards is
// refused once, never answered with the default tenant's data, and then
// is back in the default tenant.
func TestSwitchedTenantTurnedOff(t *testing.T) {
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Tenants, s.TenantRuntime = reg, &fakeTenantRuntime{}
		s.Users = users.NewMemory()
		s.Users.Create(context.Background(), users.NewUser{Username: "pat", Role: users.Analyst, Password: "role-password"})
	})
	_, _, cookie := login(t, ts, "pat", "role-password")
	if code, _, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie); code != 200 {
		t.Fatalf("switch: %d", code)
	}
	off := true
	if _, err := reg.Change("acme", nil, &off, "test"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != http.StatusConflict || body["code"] != "tenant_unavailable" {
		t.Errorf("findings after acme was turned off: %d %v", code, body)
	}
	if _, me, _ := call(t, ts, "GET", "/api/me", "", "", "", cookie); me["active_tenant"] != tenants.Default {
		t.Errorf("me after the refusal: %v", me)
	}
	if code, _, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != 200 {
		t.Errorf("findings back in the default tenant: %d", code)
	}
}

// A provider analyst lowered to viewer cannot stay in the tenant they
// switched to.
func TestSwitchedTenantRoleLowered(t *testing.T) {
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	store := users.NewMemory()
	store.Create(context.Background(), users.NewUser{Username: "pat", Role: users.Analyst, Password: "role-password"})
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Tenants = reg
		s.TenantRuntime = &fakeTenantRuntime{}
		s.Users = store
	})
	_, _, cookie := login(t, ts, "pat", "role-password")
	if code, _, _ := call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie); code != 200 {
		t.Fatalf("switch: %d", code)
	}
	viewer := users.Viewer
	if _, err := store.Update(context.Background(), "pat", users.Change{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie); code != http.StatusConflict || body["code"] != "tenant_unavailable" {
		t.Errorf("findings as a viewer in acme: %d %v", code, body)
	}
	if _, me, _ := call(t, ts, "GET", "/api/me", "", "", "", cookie); me["active_tenant"] != tenants.Default {
		t.Errorf("me after the refusal: %v", me)
	}
}

// Every route is classified: its resource is in exactly one of the lists,
// and the lists name only routes and resources there are.
func TestEveryRouteHasAScope(t *testing.T) {
	_, s := newRoleServer(t)
	for _, r := range slices.Concat(tenantResources, platformResources) {
		if slices.Contains(tenantResources, r) && slices.Contains(platformResources, r) {
			t.Errorf("resource %q is both a tenant's and the platform's", r)
		}
	}
	// The web UI's files are the same for every tenant.
	for _, p := range []string{"GET /", "GET /v/1.2.3/"} {
		if platform, managed, shared := routeScope(p); platform || managed || !shared {
			t.Errorf("%s is not shared", p)
		}
	}
	patterns := map[string]bool{}
	used := map[string]bool{}
	for _, rt := range s.routes {
		patterns[rt.Pattern] = true
		res, ok := routeResource(rt.Pattern)
		if !ok {
			if !rt.Shared {
				t.Errorf("route %s outside /api/ is not shared", rt.Pattern)
			}
			continue
		}
		used[res] = true
		if !slices.Contains(tenantResources, res) && !slices.Contains(platformResources, res) {
			t.Errorf("route %s: add %q to tenantResources or platformResources (internal/api/tenants.go)", rt.Pattern, res)
		}
	}
	for _, p := range slices.Concat(providerManaged, tenantVisible) {
		if !patterns[p] {
			t.Errorf("%s is not a route", p)
		}
	}
	for _, r := range slices.Concat(tenantResources, platformResources) {
		if !used[r] {
			t.Errorf("no route has resource %q", r)
		}
	}
}

// A tenant's admins see and manage only their tenant's users: the
// provider's, the built-in admin and other tenants' users are not there.
func TestTenantAdminsManageOnlyTheirUsers(t *testing.T) {
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	reg.Add("beta", "Beta", "test", time.Now())
	store := users.NewMemory()
	for _, u := range []users.NewUser{
		{Username: "ada", Role: users.Admin, Tenant: "acme"},
		{Username: "bob", Role: users.Viewer, Tenant: "acme"},
		{Username: "eve", Role: users.Admin, Tenant: "beta"},
		{Username: "pat", Role: users.Admin},
	} {
		u.Password = "role-password"
		if _, err := store.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	var acme, def *Server
	acmeTS, _ := newTestServerWith(t, func(s *Server) {
		acme = s
		s.Tenants, s.Users, s.TenantID = reg, store, "acme"
	})
	defTS, _ := newTestServerWith(t, func(s *Server) {
		def = s
		s.Tenants, s.Users = reg, store
	})
	names := func(ts *httptest.Server, user string) []string {
		t.Helper()
		code, body := doAs(t, ts, user, "role-password", "GET", "/api/users", "")
		if code != 200 {
			t.Fatalf("users as %s: %d %v", user, code, body)
		}
		var out []string
		for _, u := range body["users"].([]any) {
			out = append(out, u.(map[string]any)["username"].(string))
		}
		slices.Sort(out)
		return out
	}
	if got := names(acmeTS, "ada"); !slices.Equal(got, []string{"ada", "bob"}) {
		t.Errorf("acme's users = %v", got)
	}
	if got := names(defTS, "pat"); slices.Contains(got, "ada") || slices.Contains(got, "eve") || !slices.Contains(got, "pat") || !slices.Contains(got, def.builtinName()) {
		t.Errorf("the provider's users = %v", got)
	}
	for _, other := range []string{"pat", "eve", acme.builtinName()} {
		for _, req := range [][2]string{
			{"PUT", "/api/users/" + other}, {"DELETE", "/api/users/" + other},
			{"POST", "/api/users/" + other + "/password"}, {"DELETE", "/api/users/" + other + "/mfa"},
		} {
			if code, body := doAs(t, acmeTS, "ada", "role-password", req[0], req[1], `{"role":"viewer"}`); code != http.StatusNotFound {
				t.Errorf("acme's admin %s %s: %d %v", req[0], req[1], code, body)
			}
		}
	}
	if code, body := doAs(t, acmeTS, "ada", "role-password", "POST", "/api/users", `{"username":"carl","role":"admin","password":"a-long-enough-password-1"}`); code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, body)
	}
	if u, _ := store.Get("carl"); u.Tenant != "acme" {
		t.Errorf("carl's tenant = %q, want acme", u.Tenant)
	}
	if code, _ := doAs(t, acmeTS, "ada", "role-password", "DELETE", "/api/users/bob", ""); code != 200 {
		t.Errorf("acme's admin deleting acme's user: %d", code)
	}
}

// fakeTenantRuntime runs no tenant, and records which were changed.
type fakeTenantRuntime struct{ changed []string }

func (f *fakeTenantRuntime) Server(string) *Server                      { return nil }
func (f *fakeTenantRuntime) Servers() []*Server                         { return nil }
func (f *fakeTenantRuntime) SettingsChanged()                           {}
func (f *fakeTenantRuntime) NotebookStores() map[string]notebooks.Store { return nil }
func (f *fakeTenantRuntime) Ready() error                               { return nil }
func (f *fakeTenantRuntime) Changed(_ context.Context, id string) error {
	f.changed = append(f.changed, id)
	return nil
}

func TestAddAndChangeTenants(t *testing.T) {
	rt := &fakeTenantRuntime{}
	s, do := newTenantServer(t)
	s.Users.Create(context.Background(), users.NewUser{Username: "boss", Role: users.Admin, Password: "role-password"})
	// Without a runtime (a server sharing its users), nothing changes.
	if code, body := do("POST", "/api/tenants", `{"id":"beta","name":"Beta"}`, "boss"); code != http.StatusConflict {
		t.Errorf("add without a runtime: %d %v", code, body)
	}
	s.TenantRuntime = rt
	for _, c := range []struct {
		method, path, body, user string
		want                     int
	}{
		{"POST", "/api/tenants", `{"id":"beta","name":"Beta"}`, "ada", http.StatusForbidden},
		{"POST", "/api/tenants", `{"id":"beta","name":"Beta"}`, "pat", http.StatusForbidden},
		{"POST", "/api/tenants", `{"id":"Beta!","name":"Beta"}`, "boss", http.StatusBadRequest},
		{"POST", "/api/tenants", `{"id":"default","name":"Beta"}`, "boss", http.StatusBadRequest},
		{"POST", "/api/tenants", `{"id":"acme","name":"Again"}`, "boss", http.StatusConflict},
		{"POST", "/api/tenants", `{"id":"beta","name":"Beta"}`, "boss", http.StatusCreated},
		{"PATCH", "/api/tenants/nope", `{"disabled":true}`, "boss", http.StatusNotFound},
		{"PATCH", "/api/tenants/beta", `{"name":"Beta Inc"}`, "boss", http.StatusOK},
		{"PATCH", "/api/tenants/beta", `{"disabled":true}`, "boss", http.StatusOK},
		{"PATCH", "/api/tenants/acme", `{"disabled":true}`, "ada", http.StatusForbidden},
	} {
		if code, body := do(c.method, c.path, c.body, c.user); code != c.want {
			t.Errorf("%s %s %s as %s: %d %v, want %d", c.method, c.path, c.body, c.user, code, body, c.want)
		}
	}
	if !slices.Equal(rt.changed, []string{"beta", "beta"}) {
		t.Errorf("runtime told of %v, want beta added and turned off", rt.changed)
	}
	if b, _ := s.Tenants.Get("beta"); b.Name != "Beta Inc" || !b.Disabled || b.CreatedBy != "boss" {
		t.Errorf("beta = %+v", b)
	}
}

// oneTenant runs one tenant's server.
type oneTenant struct{ srv *Server }

func (o oneTenant) Server(id string) *Server {
	if o.srv != nil && id == o.srv.TenantID {
		return o.srv
	}
	return nil
}
func (o oneTenant) Servers() []*Server                         { return []*Server{o.srv} }
func (o oneTenant) Changed(context.Context, string) error      { return nil }
func (o oneTenant) SettingsChanged()                           {}
func (o oneTenant) NotebookStores() map[string]notebooks.Store { return nil }
func (o oneTenant) Ready() error                               { return nil }

// A tenant's requests are answered by its own server, with its own data,
// whoever asks: its users, and the provider's users switched into it.
// Neither ever sees the default tenant's data, nor the other way round.
func TestTenantRequestsReachOnlyTheirData(t *testing.T) {
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	store := users.NewMemory()
	for _, u := range []users.NewUser{
		{Username: "ada", Role: users.Analyst, Tenant: "acme"},
		{Username: "pat", Role: users.Analyst},
	} {
		u.Password = "role-password"
		store.Create(context.Background(), u)
	}
	var acme *Server
	newTestServerWith(t, func(s *Server) {
		acme = s
		s.Tenants, s.Users, s.TenantID = reg, store, "acme"
	})
	var front *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		front = s
		s.Tenants, s.Users = reg, store
		s.TenantRuntime = oneTenant{acme}
	})
	ctx := context.Background()
	front.Findings.Create(ctx, &findings.Finding{ID: "f-default", Title: "default's", Severity: "low", Status: "new"})
	acme.Findings.Create(ctx, &findings.Finding{ID: "f-acme", Title: "acme's", Severity: "low", Status: "new"})
	seen := func(code int, body map[string]any) []string {
		t.Helper()
		if code != 200 {
			t.Fatalf("findings: %d %v", code, body)
		}
		var ids []string
		for _, f := range body["findings"].([]any) {
			ids = append(ids, f.(map[string]any)["id"].(string))
		}
		return ids
	}
	if got := seen(doAs(t, ts, "ada", "role-password", "GET", "/api/findings", "")); !slices.Equal(got, []string{"f-acme"}) {
		t.Errorf("acme's analyst sees %v", got)
	}
	if got := seen(doAs(t, ts, "pat", "role-password", "GET", "/api/findings", "")); !slices.Equal(got, []string{"f-default"}) {
		t.Errorf("the provider's analyst sees %v", got)
	}
	_, _, cookie := login(t, ts, "pat", "role-password")
	call(t, ts, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, "", "", cookie)
	code, body, _ := call(t, ts, "GET", "/api/findings", "", "", "", cookie)
	if got := seen(code, body); !slices.Equal(got, []string{"f-acme"}) {
		t.Errorf("the provider's analyst in acme sees %v", got)
	}
	// One finding by id: never the other tenant's.
	if code, _ := doAs(t, ts, "ada", "role-password", "GET", "/api/findings/f-default", ""); code != http.StatusNotFound {
		t.Errorf("acme's analyst reading the default tenant's finding: %d", code)
	}
	if code, _ := doAs(t, ts, "pat", "role-password", "GET", "/api/findings/f-acme", ""); code != http.StatusNotFound {
		t.Errorf("the provider's analyst reading acme's finding from the default tenant: %d", code)
	}
	// Searches run on the tenant's own engine.
	if code, _ := doAs(t, ts, "ada", "role-password", "POST", "/api/search", `{"query":"search *","earliest":"-24h"}`); code != 200 {
		t.Errorf("acme's search: %d", code)
	}
}
