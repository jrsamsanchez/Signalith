package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// routePattern matches a route pattern written in the source, with or
// without a method.
var routePattern = regexp.MustCompile(`^([A-Z]+ )?/api/.`)

// TestEveryRouteHasARole fails when an API route has no explicit role.
// It checks the routes Handler registered, and every route pattern in
// this package's source, so a route added on another branch, or straight
// on a ServeMux, cannot slip through unclassified. Such routes are
// admin-only until they get a role.
func TestEveryRouteHasARole(t *testing.T) {
	_, s := newRoleServer(t)
	classified := map[string]users.Role{}
	for _, r := range s.routes {
		if r.Unclassified {
			t.Errorf("%s has no role; register it with api.viewer, api.analyst or api.admin", r.Pattern)
			continue
		}
		if _, dup := classified[r.Pattern]; dup {
			t.Errorf("%s is registered twice", r.Pattern)
		}
		classified[r.Pattern] = r.Role
	}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil || !routePattern.MatchString(v) {
				return true
			}
			found++
			if _, ok := classified[v]; !ok && !slices.Contains(publicRoutes, v) {
				t.Errorf("%s (%s) is not registered with a role", v, fset.Position(lit.Pos()))
			}
			return true
		})
	}
	if found < 70 {
		t.Errorf("found only %d route patterns in the source; is the scan still working?", found)
	}
	// A few routes whose role matters most.
	for pattern, want := range map[string]users.Role{
		"GET /api/agents/config":     users.Admin,
		"GET /api/agents":            users.Analyst,
		"POST /api/users":            users.Admin,
		"PUT /api/auth/directory":    users.Admin,
		"PATCH /api/findings/{id}":   users.Analyst,
		"POST /api/intel/indicators": users.Analyst,
		"POST /api/intel/upload":     users.Admin,
		"POST /api/intel/feeds/test": users.Admin,
		"GET /api/intel/feeds":       users.Viewer,
		"POST /api/search":           users.Viewer,
		"GET /api/me":                users.Viewer,
		"GET /api/settings":          users.Admin,
		"PUT /api/settings":          users.Admin,
		"POST /api/settings/restart": users.Admin,
		"GET /api/settings/export":   users.Admin,
	} {
		if classified[pattern] != want {
			t.Errorf("%s = %s, want %s", pattern, classified[pattern], want)
		}
	}
}

// The role table in docs/users.md lists every route under its role,
// itself or as "every `/api/<prefix>` route".
func TestUsersDocListsEveryRoute(t *testing.T) {
	_, s := newRoleServer(t)
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "users.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Git on Windows may check the doc out with CRLF line endings.
	doc := strings.ReplaceAll(string(b), "\r\n", "\n")
	start := strings.Index(doc, "### Roles of every route")
	end := strings.Index(doc, "A route added without a role")
	if start < 0 || end < start {
		t.Fatal("docs/users.md has no role table")
	}
	paras := map[string]string{}
	for _, p := range strings.Split(doc[start:end], "\n\n") {
		for _, head := range []string{"**Every role**", "**Viewer:**", "**Analyst:**", "**Admin:**"} {
			if strings.HasPrefix(p, head) {
				paras[head] = strings.Join(strings.Fields(p), " ")
			}
		}
	}
	if len(paras) != 4 {
		t.Fatalf("role paragraphs %v", paras)
	}
	prefix := regexp.MustCompile("`(/api/[a-z/]+)`")
	for _, r := range s.routes {
		head := map[users.Role]string{users.Viewer: "**Viewer:**", users.Analyst: "**Analyst:**", users.Admin: "**Admin:**"}[r.Role]
		if r.Anytime {
			head = "**Every role**"
		}
		p := paras[head]
		if strings.Contains(p, "`"+r.Pattern+"`") {
			continue
		}
		_, path, _ := strings.Cut(r.Pattern, " ")
		covered := false
		for _, m := range prefix.FindAllStringSubmatch(p, -1) {
			if path == m[1] || strings.HasPrefix(path, m[1]+"/") {
				covered = true
			}
		}
		if !covered {
			t.Errorf("docs/users.md does not list %s under %s", r.Pattern, head)
		}
	}
}

// newRoleServer starts a server with a viewer (vera) and an analyst
// (andy), both with the password "role-password".
func newRoleServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
	})
	return ts, srv
}

// TestRolesAreEnforced calls every route as a viewer and as an analyst:
// routes above their role answer 403 before doing anything, and the rest
// do not.
func TestRolesAreEnforced(t *testing.T) {
	ts, s := newRoleServer(t)
	if len(s.routes) < 70 {
		t.Fatalf("only %d routes registered", len(s.routes))
	}
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	for _, who := range []struct {
		user string
		role users.Role
	}{{"vera", users.Viewer}, {"andy", users.Analyst}} {
		for _, rt := range s.routes {
			method, path, _ := strings.Cut(rt.Pattern, " ")
			path = wildcard.ReplaceAllString(path, "x")
			req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
			req.SetBasicAuth(who.user, "role-password")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			denied := resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), `"code":"forbidden"`)
			if want := !who.role.AtLeast(rt.Role); denied != want {
				t.Errorf("%s %s: status %d, denied=%v, want denied=%v (%s)", who.user, rt.Pattern, resp.StatusCode, denied, want, body)
			}
		}
	}
	// The 403 says what is needed in plain words.
	code, body := doAs(t, ts, "vera", "role-password", "POST", "/api/cases", `{"title":"x"}`)
	if code != 403 || body["error"] != "This needs the Analyst role, and your role is Viewer. Ask an admin if you need access." || body["required"] != "analyst" {
		t.Errorf("viewer post = %d %v", code, body)
	}
}

func TestUnclassifiedRoutesAreAdminOnly(t *testing.T) {
	cfg := config.Default()
	h, _ := config.HashPassword("s3cret-pass")
	cfg.Auth.AdminPasswordHash = h
	s := &Server{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Users: users.NewMemory()}
	s.Users.Create(context.Background(), users.NewUser{Username: "andy", Role: users.Analyst, Password: "role-password"})
	rt := &router{s: s, mux: http.NewServeMux()}
	rt.HandleFunc("POST /api/new-thing", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	if len(rt.routes) != 1 || !rt.routes[0].Unclassified || rt.routes[0].Role != users.Admin {
		t.Fatalf("routes = %+v", rt.routes)
	}
	ts := httptest.NewServer(s.requireUser(rt.mux))
	defer ts.Close()
	if code, _ := doAs(t, ts, "andy", "role-password", "POST", "/api/new-thing", ""); code != 403 {
		t.Errorf("analyst on unclassified route = %d", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/new-thing", ""); code != http.StatusTeapot {
		t.Errorf("admin on unclassified route = %d", code)
	}
}

// TestHealthDetailsAreForAdmins: everyone sees whether things work, but
// file paths, addresses and setup advice only reach admins.
func TestHealthDetailsAreForAdmins(t *testing.T) {
	ts, _ := newRoleServer(t)
	code, body := doAs(t, ts, "vera", "role-password", "GET", "/api/health", "")
	if code != 200 {
		t.Fatalf("viewer health = %d", code)
	}
	for _, k := range []string{"config_file", "config_has_syslog", "runtime", "warnings"} {
		if _, ok := body[k]; ok {
			t.Errorf("viewer sees %s", k)
		}
	}
	if os, _ := body["opensearch"].(map[string]any); os["status"] == nil || os["url"] != nil || os["error"] != nil {
		t.Errorf("viewer opensearch = %v", body["opensearch"])
	}
	if _, ok := body["ingest"]; !ok {
		t.Error("viewer health has no ingest stats")
	}
	_, body = do(t, ts, "GET", "/api/health", "", true)
	if os, _ := body["opensearch"].(map[string]any); os["url"] == nil || body["runtime"] == nil {
		t.Errorf("admin health = %v", body)
	}
}
