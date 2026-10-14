package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

// doAs calls the API with Basic auth as user.
func doAs(t *testing.T, ts *httptest.Server, user, pass, method, path, body string) (int, map[string]any) {
	t.Helper()
	code, out, _ := call(t, ts, method, path, body, user, pass, nil)
	return code, out
}

// call sends a request with Basic auth (when user is set) or a session
// cookie, and returns the status, the JSON body and the raw body.
func call(t *testing.T, ts *httptest.Server, method, path, body, user, pass string, c *http.Cookie) (int, map[string]any, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out, string(raw)
}

// login signs in through the sign-in page's API and returns the reply
// and the session cookie.
func login(t *testing.T, ts *httptest.Server, user, pass string) (int, map[string]any, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(string(b)))
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return resp.StatusCode, out, c
		}
	}
	return resp.StatusCode, out, nil
}

func newUsersServer(t *testing.T, change func(*Server)) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<h1>app</h1>")}, "login.html": {Data: []byte("<h1>sign in</h1>")}}
		if change != nil {
			change(s)
		}
	})
	return ts, srv
}

const adminPass = "s3cret-pass"

func TestManagingLocalUsers(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}

	// Create with a generated temporary password, shown once.
	code, body, _ := admin("POST", "/api/users", `{"username":"JDoe","name":"Jane Doe","email":"jdoe@example.com","role":"analyst"}`)
	if code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}
	temp, _ := body["temporary_password"].(string)
	u := body["user"].(map[string]any)
	if len(temp) != 19 || u["username"] != "jdoe" || u["must_change_password"] != true || u["source"] != "local" {
		t.Errorf("created %v", body)
	}
	if code, body, _ := admin("POST", "/api/users", `{"username":"jdoe","role":"viewer","password":"short"}`); code != 409 || body["field"] != "username" {
		t.Errorf("duplicate = %d %v", code, body)
	}
	if code, body, _ := admin("POST", "/api/users", `{"username":"zed","role":"viewer","password":"short"}`); code != 400 || body["field"] != "password" {
		t.Errorf("short password = %d %v", code, body)
	}
	if code, body, _ := admin("POST", "/api/users", `{"username":"zed","role":"boss"}`); code != 400 || body["field"] != "role" {
		t.Errorf("unknown role = %d %v", code, body)
	}
	if code, _, _ := admin("POST", "/api/users", `{"username":"ADMIN","role":"viewer"}`); code != 409 {
		t.Errorf("built-in admin's name = %d", code)
	}
	if code, body, _ := admin("POST", "/api/users", `{"username":"x y","role":"viewer"}`); code != 400 || !strings.Contains(body["error"].(string), "usernames are") {
		t.Errorf("bad username = %d %v", code, body)
	}

	// The list starts with the built-in admin and never shows hashes.
	code, body, raw := admin("GET", "/api/users", "")
	list := body["users"].([]any)
	first := list[0].(map[string]any)
	if code != 200 || len(list) != 2 || first["source"] != "builtin" || first["you"] != true || len(first["actions"].([]any)) != 0 {
		t.Errorf("list = %d %s", code, raw)
	}
	if strings.Contains(raw, "$2a$") || strings.Contains(raw, "password_hash") || strings.Contains(raw, temp) {
		t.Errorf("list leaks secrets: %s", raw)
	}
	if roles := body["roles"].([]any); len(roles) != 3 {
		t.Errorf("roles = %v", roles)
	}

	// Signing in with the temporary password allows only a password change.
	code, me, c := login(t, ts, "JDOE", temp)
	if code != 200 || me["must_change_password"] != true || me["role"] != "analyst" || c == nil {
		t.Fatalf("login = %d %v", code, me)
	}
	if code, body, _ := call(t, ts, "GET", "/api/health", "", "", "", c); code != 403 || body["code"] != "password_change_required" {
		t.Errorf("health before change = %d %v", code, body)
	}
	if resp := send(t, "GET", ts.URL+"/", "", map[string]string{"Sec-Fetch-Mode": "navigate"}, c); resp.StatusCode != 303 || resp.Header.Get("Location") != "/login?change=1" {
		t.Errorf("app page before change = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := send(t, "GET", ts.URL+"/login", "", nil, c); resp.StatusCode != 200 {
		t.Errorf("sign-in page before change = %d", resp.StatusCode)
	}
	if code, body, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 200 || body["must_change_password"] != true || body["can_change_password"] != true {
		t.Errorf("me = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"nope","new_password":"jane-new-pass"}`, "", "", c); code != 400 || body["field"] != "current_password" {
		t.Errorf("wrong current = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+temp+`","new_password":"short"}`, "", "", c); code != 400 || body["field"] != "new_password" {
		t.Errorf("short new = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+temp+`","new_password":"jane-new-pass"}`, "", "", c); code != 200 || body["must_change_password"] != false {
		t.Errorf("change = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "GET", "/api/health", "", "", "", c); code != 200 {
		t.Errorf("health after change = %d", code)
	}
	// Basic auth works with the new password, as the same user.
	if code, body := doAs(t, ts, "jdoe", "jane-new-pass", "GET", "/api/me", ""); code != 200 || body["auth"] != "basic" || body["role"] != "analyst" {
		t.Errorf("basic = %d %v", code, body)
	}

	// Analysts cannot manage users.
	if code, body, _ := call(t, ts, "POST", "/api/users", `{"username":"x","role":"admin"}`, "", "", c); code != 403 || body["code"] != "forbidden" {
		t.Errorf("analyst creates user = %d %v", code, body)
	}

	// A role change applies to the next request, in the session and with
	// Basic auth (whose check is cached).
	if code, body, _ := admin("PUT", "/api/users/jdoe", `{"role":"viewer"}`); code != 200 || body["user"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("demote = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "POST", "/api/cases", `{"title":"x"}`, "", "", c); code != 403 {
		t.Errorf("viewer session posts a case = %d", code)
	}
	if code, _ := doAs(t, ts, "jdoe", "jane-new-pass", "POST", "/api/cases", `{"title":"x"}`); code != 403 {
		t.Errorf("viewer basic posts a case = %d", code)
	}

	// A reset gives a new temporary password and ends sessions; the old
	// password stops working even though Basic checks are cached.
	code, body, _ = admin("POST", "/api/users/jdoe/password", "")
	temp2, _ := body["temporary_password"].(string)
	if code != 200 || temp2 == "" || temp2 == temp {
		t.Fatalf("reset = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
		t.Errorf("session after reset = %d", code)
	}
	if code, _ := doAs(t, ts, "jdoe", "jane-new-pass", "GET", "/api/me", ""); code != 401 {
		t.Errorf("old password after reset = %d", code)
	}
	if code, body := doAs(t, ts, "jdoe", temp2, "GET", "/api/health", ""); code != 403 || body["code"] != "password_change_required" {
		t.Errorf("basic with temporary password = %d %v", code, body)
	}

	// Disabling a user ends their sessions and refuses sign-in.
	_, _, c = login(t, ts, "jdoe", temp2)
	if code, _, _ := admin("PUT", "/api/users/jdoe", `{"disabled":true}`); code != 200 {
		t.Fatalf("disable = %d", code)
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
		t.Errorf("session after disable = %d", code)
	}
	if code, body, _ := login(t, ts, "jdoe", temp2); code != 403 || body["code"] != "disabled" {
		t.Errorf("login while disabled = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "jdoe", temp2, "GET", "/api/me", ""); code != 403 {
		t.Errorf("basic while disabled = %d", code)
	}
	if code, _, _ := login(t, ts, "jdoe", "wrong-password"); code != 401 {
		t.Errorf("wrong password while disabled = %d (should not reveal the account)", code)
	}

	// Deleting removes the user; they cannot sign in.
	if code, body, _ := admin("DELETE", "/api/users/jdoe", ""); code != 200 || body["deleted"] != "jdoe" {
		t.Errorf("delete = %d %v", code, body)
	}
	if code, _, _ := login(t, ts, "jdoe", temp2); code != 401 {
		t.Errorf("login after delete = %d", code)
	}
	if code, _, _ := admin("DELETE", "/api/users/jdoe", ""); code != 404 {
		t.Errorf("delete again = %d", code)
	}

	// The built-in admin cannot be changed here.
	for _, req := range [][2]string{{"PUT", "/api/users/admin"}, {"DELETE", "/api/users/admin"}, {"POST", "/api/users/Admin/password"}} {
		if code, _, _ := admin(req[0], req[1], `{"disabled":true}`); code != 409 {
			t.Errorf("%s %s = %d", req[0], req[1], code)
		}
	}
	if code, body, _ := admin("POST", "/api/me/password", `{"current_password":"s3cret-pass","new_password":"another-pass"}`); code != 400 || body["code"] != "builtin" {
		t.Errorf("built-in admin changes own password = %d %v", code, body)
	}
	if s.userStore().BuiltinLastSignIn() == nil {
		t.Error("built-in admin's sign-in not recorded")
	}
}

func TestAdminsCannotLockThemselvesOut(t *testing.T) {
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "ann-password"})
		s.Users.Create(context.Background(), users.NewUser{Username: "ben", Role: users.Viewer, Password: "ben-password"})
	})
	ann := func(method, path, body string) (int, map[string]any) {
		return doAs(t, ts, "ann", "ann-password", method, path, body)
	}
	for _, c := range []struct{ method, path, body, want string }{
		{"PUT", "/api/users/ann", `{"disabled":true}`, "disable your own"},
		{"PUT", "/api/users/ann", `{"role":"analyst"}`, "change your own role"},
		{"DELETE", "/api/users/ann", ``, "delete your own"},
		{"POST", "/api/users/ann/password", ``, "Change password in your user menu"},
	} {
		code, body := ann(c.method, c.path, c.body)
		if code != 409 || !strings.Contains(body["error"].(string), c.want) {
			t.Errorf("%s %s = %d %v", c.method, c.path, code, body)
		}
	}
	// Editing their own name is fine, and the list marks them.
	if code, _ := ann("PUT", "/api/users/ann", `{"name":"Ann Admin","role":"admin"}`); code != 200 {
		t.Errorf("own name = %d", code)
	}
	_, body := ann("GET", "/api/users", "")
	for _, u := range body["users"].([]any) {
		u := u.(map[string]any)
		actions, _ := json.Marshal(u["actions"])
		switch u["username"] {
		case "ann":
			if u["you"] != true || string(actions) != `["edit"]` {
				t.Errorf("ann = %v", u)
			}
		case "ben":
			if string(actions) != `["edit","role","reset_password","disable","delete"]` {
				t.Errorf("ben actions = %s", actions)
			}
		}
	}
}

func adSettingsJSON(srv *ldaptest.Server, extra string) string {
	b, _ := json.Marshal(map[string]any{
		"enabled": true, "type": "ad", "url": srv.URL, "ca_cert": srv.CACert,
		"bind_dn": ldaptest.ADService, "bind_password": ldaptest.ServicePassword,
		"user_base_dn": ldaptest.ADBase, "admin_groups": []string{ldaptest.ADAdmins},
		"analyst_groups": []string{ldaptest.ADAnalysts}, "viewer_groups": []string{ldaptest.ADViewers},
	})
	if extra != "" {
		return strings.TrimSuffix(string(b), "}") + "," + extra + "}"
	}
	return string(b)
}

func TestDirectorySignIn(t *testing.T) {
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true, ActiveDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ldaptest.LoadActiveDirectory(srv)
	ts, _ := newUsersServer(t, func(s *Server) {
		// carol is also a local user, so the directory is never asked about her.
		s.Users.Create(context.Background(), users.NewUser{Username: "carol", Role: users.Viewer, Password: "local-carol"})
	})
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}

	// Off by default, with presets for the form.
	code, body, _ := admin("GET", "/api/auth/directory", "")
	if code != 200 || body["settings"].(map[string]any)["enabled"] != false || body["from_config"] != false {
		t.Fatalf("get = %d %v", code, body)
	}
	if p := body["presets"].(map[string]any)["openldap"].(map[string]any); p["username_attribute"] != "uid" || p["group_search"] != "search" {
		t.Errorf("openldap preset = %v", p)
	}
	// Problems are reported per field.
	if code, body, _ := admin("PUT", "/api/auth/directory", `{"enabled":true,"type":"ad","url":"http://x"}`); code != 400 || body["fields"].(map[string]any)["url"] == nil {
		t.Errorf("bad settings = %d %v", code, body)
	}
	// Analysts cannot see or change directory settings.
	if code, _ := doAs(t, ts, "carol", "local-carol", "GET", "/api/auth/directory", ""); code != 403 {
		t.Errorf("viewer reads settings = %d", code)
	}

	// Test before saving, with the form's values.
	code, body, _ = admin("POST", "/api/auth/directory/test", `{"settings":`+adSettingsJSON(srv, "")+`}`)
	if code != 200 || body["ok"] != true {
		t.Errorf("test = %d %v", code, body)
	}
	code, body, _ = admin("POST", "/api/auth/directory/test-user", `{"username":"bob","settings":`+adSettingsJSON(srv, "")+`}`)
	if code != 200 || body["ok"] != true || body["user"].(map[string]any)["role"] != "analyst" || body["password_checked"] != false {
		t.Errorf("test user = %d %v", code, body)
	}

	// Save; the bind password is never returned, and an empty one keeps it.
	code, body, raw := admin("PUT", "/api/auth/directory", adSettingsJSON(srv, ""))
	if code != 200 || body["settings"].(map[string]any)["bind_password_set"] != true || strings.Contains(raw, ldaptest.ServicePassword) {
		t.Fatalf("save = %d %s", code, raw)
	}
	keep := strings.Replace(adSettingsJSON(srv, ""), ldaptest.ServicePassword, "", 1)
	if code, body, raw := admin("PUT", "/api/auth/directory", keep); code != 200 || body["settings"].(map[string]any)["bind_password_set"] != true || strings.Contains(raw, ldaptest.ServicePassword) {
		t.Fatalf("save keeping password = %d %s", code, raw)
	}
	if _, _, raw := admin("GET", "/api/auth/directory", ""); strings.Contains(raw, ldaptest.ServicePassword) {
		t.Errorf("get leaks the bind password: %s", raw)
	}
	// Saved settings test without a body; a wrong password is counted.
	if code, body, _ := admin("POST", "/api/auth/directory/test", ""); code != 200 || body["ok"] != true {
		t.Errorf("saved test = %d %v", code, body)
	}
	if code, body, _ := admin("POST", "/api/auth/directory/test-user", `{"username":"bob","password":"nope"}`); code != 200 || body["code"] != "wrong_password" {
		t.Errorf("test wrong password = %d %v", code, body)
	}
	if code, body, _ := admin("POST", "/api/auth/directory/test-user", `{"username":"carol"}`); code != 200 || !strings.Contains(body["warning"].(string), "local Signalith user") {
		t.Errorf("test local name = %d %v", code, body)
	}

	// Directory users sign in with their directory password and role.
	code, me, c := login(t, ts, "alice@corp.example.com", ldaptest.Password)
	if code != 200 || me["username"] != "alice" || me["role"] != "admin" || me["source"] != "directory" || me["can_change_password"] != false {
		t.Fatalf("alice = %d %v", code, me)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"x","new_password":"yyyyyyyy"}`, "", "", c); code != 400 || body["code"] != "directory" {
		t.Errorf("directory user changes password = %d %v", code, body)
	}
	if code, body, _ := login(t, ts, "dave", ldaptest.Password); code != 403 || body["code"] != "not_in_group" {
		t.Errorf("dave = %d %v", code, body)
	}
	if code, body, _ := login(t, ts, "frank", ldaptest.Password); code != 403 || body["code"] != "password_expired" {
		t.Errorf("frank = %d %v", code, body)
	}
	if code, _, _ := login(t, ts, "bob", "wrong"); code != 401 {
		t.Errorf("bob wrong password = %d", code)
	}
	if code, _, _ := login(t, ts, "nobody", ldaptest.Password); code != 401 {
		t.Errorf("unknown user = %d", code)
	}
	// carol is local: her directory password does not work here.
	binds := len(srv.Binds())
	if code, _, _ := login(t, ts, "carol", ldaptest.Password); code != 401 {
		t.Errorf("carol with directory password = %d", code)
	}
	if code, _, _ := login(t, ts, `CORP\carol`, ldaptest.Password); code != 401 {
		t.Errorf(`CORP\carol with directory password = %d`, code)
	}
	if code, _, _ := login(t, ts, `CORP\admin`, adminPass); code != 401 {
		t.Errorf(`CORP\admin = %d`, code)
	}
	if len(srv.Binds()) != binds {
		t.Error("a local username was looked up in the directory")
	}
	// Basic auth works for directory users, and is cached briefly.
	if code, body := doAs(t, ts, "bob", ldaptest.Password, "GET", "/api/me", ""); code != 200 || body["role"] != "analyst" {
		t.Errorf("bob basic = %d %v", code, body)
	}
	binds = len(srv.Binds())
	doAs(t, ts, "bob", ldaptest.Password, "GET", "/api/me", "")
	if len(srv.Binds()) != binds {
		t.Error("basic auth for a directory user was not cached")
	}

	// They appear in the list, read-only except for disabling them.
	_, body, _ = admin("GET", "/api/users", "")
	var alice map[string]any
	for _, u := range body["users"].([]any) {
		if u.(map[string]any)["username"] == "alice" {
			alice = u.(map[string]any)
		}
	}
	if alice == nil || alice["source"] != "directory" || alice["dn"] != ldaptest.ADAliceDN || alice["last_sign_in"] == nil {
		t.Fatalf("alice in list = %v", alice)
	}
	if a, _ := json.Marshal(alice["actions"]); string(a) != `["disable","delete"]` {
		t.Errorf("alice actions = %s", a)
	}
	if code, _, _ := admin("PUT", "/api/users/alice", `{"role":"viewer"}`); code != 409 {
		t.Errorf("role change on directory user = %d", code)
	}
	// Disabling alice here blocks her even though the directory says yes.
	if code, _, _ := admin("PUT", "/api/users/alice", `{"disabled":true}`); code != 200 {
		t.Fatal("disable alice")
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
		t.Errorf("alice's session after disable = %d", code)
	}
	if code, body, _ := login(t, ts, "alice", ldaptest.Password); code != 403 || body["code"] != "disabled" {
		t.Errorf("alice after disable = %d %v", code, body)
	}

	// Switching directory sign-in off ends directory users' access.
	_, _, bc := login(t, ts, "bob", ldaptest.Password)
	if code, _, _ := admin("PUT", "/api/auth/directory", adSettingsJSON(srv, `"enabled":false`)); code != 200 {
		t.Fatal("switch off")
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", bc); code != 401 {
		t.Errorf("bob's session with directory off = %d", code)
	}
	if code, _ := doAs(t, ts, "bob", ldaptest.Password, "GET", "/api/me", ""); code != 401 {
		t.Errorf("bob's basic with directory off = %d", code)
	}
}

func TestDirectoryUnavailable(t *testing.T) {
	srv, _ := ldaptest.Start(ldaptest.Options{})
	ldaptest.LoadOpenLDAP(srv)
	url := srv.URL
	srv.Close()
	on := true
	set := users.Preset(users.TypeOpenLDAP)
	set.Enabled, set.URL, set.UserBaseDN = &on, url, ldaptest.OLBase
	set.DefaultRole = "viewer"
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Directory, _ = users.OpenDirectory("", &set)
	})
	if code, body, _ := login(t, ts, "alice", ldaptest.Password); code != 503 || body["code"] != "directory_unavailable" {
		t.Errorf("directory down = %d %v", code, body)
	}
	// Settings from signalith.yaml are read-only here.
	code, body, _ := call(t, ts, "GET", "/api/auth/directory", "", "admin", adminPass, nil)
	if code != 200 || body["from_config"] != true || len(body["warnings"].([]any)) == 0 {
		t.Errorf("get = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "PUT", "/api/auth/directory", `{"enabled":false}`, "admin", adminPass, nil); code != 409 {
		t.Errorf("put over config = %d", code)
	}
	// An unreachable directory does not count toward the lockout.
	for range 12 {
		login(t, ts, "alice", ldaptest.Password)
	}
	if code, _, _ := login(t, ts, "admin", adminPass); code != 200 {
		t.Errorf("admin after directory failures = %d", code)
	}
}

// TestPasswordChangeEndsSessionsOnOtherServers: servers that share the
// users file sign a user out everywhere when they change their password
// on one of them, except in the browser they changed it from.
func TestPasswordChangeEndsSessionsOnOtherServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	first, err := users.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Create(context.Background(), users.NewUser{Username: "jane", Role: users.Analyst, Password: "jane-old-pass"}); err != nil {
		t.Fatal(err)
	}
	server := func() *httptest.Server {
		st, err := users.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := newUsersServer(t, func(s *Server) { s.Users = st })
		return ts
	}
	a, b := server(), server()
	_, _, onA := login(t, a, "jane", "jane-old-pass")
	_, _, onB := login(t, b, "jane", "jane-old-pass")
	if onA == nil || onB == nil {
		t.Fatal("sign-in failed")
	}
	if code, _, _ := call(t, b, "GET", "/api/me", "", "", "", onB); code != 200 {
		t.Fatalf("B before = %d", code)
	}
	if code, body, _ := call(t, a, "POST", "/api/me/password", `{"current_password":"jane-old-pass","new_password":"jane-new-pass"}`, "", "", onA); code != 200 {
		t.Fatalf("change = %d %v", code, body)
	}
	ended := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if code, _, _ := call(t, b, "GET", "/api/me", "", "", "", onB); code == 401 {
			ended = true
			break
		}
	}
	if !ended {
		t.Error("the session on the other server outlived the password change")
	}
	// The browser the change was made in, and new sign-ins, carry on.
	_, _, again := login(t, b, "jane", "jane-new-pass")
	time.Sleep(1100 * time.Millisecond) // past the users file recheck
	if code, _, _ := call(t, a, "GET", "/api/me", "", "", "", onA); code != 200 {
		t.Errorf("the browser that changed the password = %d, want 200", code)
	}
	if again == nil {
		t.Fatal("sign-in with the new password failed")
	}
	if code, _, _ := call(t, b, "GET", "/api/me", "", "", "", again); code != 200 {
		t.Errorf("new sign-in on the other server = %d, want 200", code)
	}
}
