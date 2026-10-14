package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

// Signing in to one account must not reset the guesses counted against
// another, or anyone with an account could guess the admin's password
// without ever being locked out.
func TestSignInToOneAccountDoesNotResetAnother(t *testing.T) {
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "vera-password"})
	})
	refused := false
	for round := 0; round < 3 && !refused; round++ {
		for i := 0; i < 9; i++ {
			code, _, _ := login(t, ts, "admin", "wrong-guess")
			if code == 429 {
				refused = true
				break
			}
			if code != 401 {
				t.Fatalf("guess = %d", code)
			}
		}
		if code, _, _ := login(t, ts, "vera", "vera-password"); code != 200 {
			t.Fatalf("vera = %d", code)
		}
	}
	if !refused {
		t.Fatal("guesses against admin were never limited while vera kept signing in")
	}
	// The right admin password is refused too while locked, and vera is not.
	if code, _, _ := login(t, ts, "admin", adminPass); code != 429 {
		t.Errorf("admin while locked = %d", code)
	}
	if code, _, _ := login(t, ts, "vera", "vera-password"); code != 200 {
		t.Errorf("vera after the admin lockout = %d", code)
	}
}

// Parallel guesses are counted while they are checked, so a burst cannot
// get more than the limit checked before the first failure is recorded.
func TestParallelGuessesAreLimited(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	var checked, refused atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch code, _, _ := login(t, ts, "admin", "burst-guess"); code {
			case 401:
				checked.Add(1)
			case 429:
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if checked.Load() > 10 || checked.Load()+refused.Load() != 60 {
		t.Errorf("60 parallel guesses: %d checked, %d refused; at most 10 may be checked", checked.Load(), refused.Load())
	}
}

// The guards against changing yourself compare names the way the store
// does, so spacing or case in the URL cannot get around them.
func TestSelfGuardsIgnoreSpacingAndCase(t *testing.T) {
	ts, s := newUsersServer(t, func(s *Server) {
		s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "ann-password"})
	})
	for _, path := range []string{"/api/users/ann%20", "/api/users/ANN", "/api/users/%20Ann"} {
		if code, body := doAs(t, ts, "ann", "ann-password", "DELETE", path, ""); code != 409 {
			t.Errorf("DELETE %s = %d %v", path, code, body)
		}
		if code, body := doAs(t, ts, "ann", "ann-password", "POST", path+"/password", `{"password":"new-ann-password"}`); code != 409 {
			t.Errorf("reset %s = %d %v", path, code, body)
		}
		if code, body := doAs(t, ts, "ann", "ann-password", "PUT", path, `{"disabled":true}`); code != 409 {
			t.Errorf("disable %s = %d %v", path, code, body)
		}
	}
	if _, ok := s.Users.Get("ann"); !ok || !s.Users.CheckPassword("ann", "ann-password") {
		t.Error("ann was deleted or her password changed")
	}
	// Other users are still found with odd spacing.
	s.Users.Create(context.Background(), users.NewUser{Username: "ben", Role: users.Viewer, Password: "ben-password"})
	if code, body := doAs(t, ts, "ann", "ann-password", "POST", "/api/users/BEN%20/password", ""); code != 200 || body["temporary_password"] == nil {
		t.Errorf("reset ben = %d %v", code, body)
	}
}

// A listener that records the first bytes a client sends.
func listen(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			b := make([]byte, 4096)
			n, _ := io.ReadAtLeast(c, b, 1)
			got <- b[:n]
			c.Close()
		}
	}()
	return "ldap://" + ln.Addr().String(), got
}

// The saved service account password is only reused with the saved
// servers, bind DN and TLS settings, so nobody can have it sent elsewhere.
func TestSavedBindPasswordStaysWithItsServer(t *testing.T) {
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true, ActiveDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ldaptest.LoadActiveDirectory(srv)
	ts, _ := newUsersServer(t, nil)
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}
	if code, _, raw := admin("PUT", "/api/auth/directory", adSettingsJSON(srv, "")); code != 200 {
		t.Fatalf("save = %d %s", code, raw)
	}
	other, got := listen(t)
	without := func(extra string) string {
		return strings.Replace(adSettingsJSON(srv, extra), `"bind_password":"`+ldaptest.ServicePassword+`"`, `"bind_password":""`, 1)
	}
	moved := strings.Replace(without(""), `"url":"`+srv.URL+`"`, `"url":"`+other+`"`, 1)
	for name, form := range map[string]string{
		"another server":     moved,
		"a failover server":  without(`"failover_url":"` + other + `"`),
		"another bind DN":    strings.Replace(without(""), ldaptest.ADService, "CN=someone,"+ldaptest.ADBase, 1),
		"certificate checks": without(`"tls_skip_verify":true`),
		"another CA":         strings.Replace(without(""), `"ca_cert":`, `"ca_cert_was":`, 1),
		"StartTLS changed":   without(`"start_tls":true`),
	} {
		for _, path := range []string{"/api/auth/directory/test", "/api/auth/directory/test-user"} {
			code, body, _ := admin("POST", path, `{"username":"bob","settings":`+form+`}`)
			fields, _ := body["fields"].(map[string]any)
			if code != 400 || !strings.Contains(fmt_(fields["bind_password"]), "again") {
				t.Errorf("%s, %s = %d %v", name, path, code, body)
			}
		}
		if code, body, _ := admin("PUT", "/api/auth/directory", form); code != 400 || body["fields"].(map[string]any)["bind_password"] == nil {
			t.Errorf("%s, save = %d %v", name, code, body)
		}
	}
	select {
	case b := <-got:
		t.Errorf("something was sent to the other server: %q", b)
	case <-time.After(100 * time.Millisecond):
	}
	// The same connection keeps working without the password.
	if code, body, _ := admin("POST", "/api/auth/directory/test", `{"settings":`+without("")+`}`); code != 200 || body["ok"] != true {
		t.Errorf("same server = %d %v", code, body)
	}
	if code, _, _ := admin("PUT", "/api/auth/directory", without(`"viewer_groups":[]`)); code != 200 {
		t.Errorf("save other fields without the password = %d", code)
	}
	// Typing a password for another server is fine: that is the admin's own.
	typed := strings.Replace(moved, `"bind_password":""`, `"bind_password":"typed-here"`, 1)
	admin("POST", "/api/auth/directory/test", `{"settings":`+typed+`}`)
	select {
	case b := <-got:
		if strings.Contains(string(b), ldaptest.ServicePassword) || !strings.Contains(string(b), "typed-here") {
			t.Errorf("other server got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Error("the typed password was not tried")
	}
}

func fmt_(v any) string {
	s, _ := v.(string)
	return s
}

// startAD runs the fake Active Directory and a server using it.
func startAD(t *testing.T, change func(*Server)) (*ldaptest.Server, *httptest.Server, *Server) {
	t.Helper()
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true, ActiveDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ldaptest.LoadActiveDirectory(srv)
	ts, s := newUsersServer(t, change)
	t.Cleanup(s.background.Wait)
	if code, _, raw := call(t, ts, "PUT", "/api/auth/directory", adSettingsJSON(srv, ""), "admin", adminPass, nil); code != 200 {
		t.Fatalf("save = %d %s", code, raw)
	}
	return srv, ts, s
}

// get calls a route with a session and, when a directory check started in
// the background, waits for it and calls again.
func getTwice(t *testing.T, ts *httptest.Server, s *Server, path string, c *http.Cookie) (int, map[string]any) {
	t.Helper()
	call(t, ts, "GET", path, "", "", "", c)
	s.background.Wait()
	code, body, _ := call(t, ts, "GET", path, "", "", "", c)
	return code, body
}

func listedUser(t *testing.T, ts *httptest.Server, name string) map[string]any {
	t.Helper()
	_, body, _ := call(t, ts, "GET", "/api/users", "", "admin", adminPass, nil)
	for _, u := range body["users"].([]any) {
		if u.(map[string]any)["username"] == name {
			return u.(map[string]any)
		}
	}
	return nil
}

// A refused directory sign-in takes the stored role away and ends the
// person's sessions at once.
func TestRefusedDirectorySignInEndsAccess(t *testing.T) {
	srv, ts, _ := startAD(t, nil)
	code, me, c := login(t, ts, "alice", ldaptest.Password)
	if code != 200 || me["role"] != "admin" {
		t.Fatalf("alice = %d %v", code, me)
	}
	// Removed from IT Leads, the group nested in Signalith Admins.
	srv.Add(ldaptest.ADITLeads, map[string][]string{"objectClass": {"top", "group"}, "member": {ldaptest.ADBobDN}})
	if code, body, _ := login(t, ts, "alice", ldaptest.Password); code != 403 || body["code"] != "not_in_group" {
		t.Fatalf("alice again = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "GET", "/api/users", "", "", "", c); code != 401 {
		t.Errorf("alice's old session = %d", code)
	}
	if u := listedUser(t, ts, "alice"); u == nil || u["role"] != "" || !strings.Contains(fmt_(u["refused"]), "not in a group") {
		t.Errorf("alice in the list = %v", u)
	}
	// A stranger's wrong password does not take anyone's access away.
	_, _, bc := login(t, ts, "bob", ldaptest.Password)
	login(t, ts, "bob", "wrong-password")
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", bc); code != 200 {
		t.Errorf("bob after someone typed a wrong password for him = %d", code)
	}
	// Back in the group, alice can sign in again.
	srv.Add(ldaptest.ADITLeads, map[string][]string{"objectClass": {"top", "group"}, "member": {ldaptest.ADAliceDN}})
	if code, me, _ := login(t, ts, "alice", ldaptest.Password); code != 200 || me["role"] != "admin" {
		t.Errorf("alice back in the group = %d %v", code, me)
	}
	if u := listedUser(t, ts, "alice"); u["role"] != "admin" || u["refused"] != nil {
		t.Errorf("alice in the list = %v", u)
	}
}

// Signed-in directory users are looked up again while they use
// Signalith: a group change, or being disabled in the directory, applies
// without signing in again.
func TestDirectoryUsersAreCheckedAgain(t *testing.T) {
	srv, ts, s := startAD(t, func(s *Server) { s.DirectoryRecheck = time.Nanosecond })
	_, _, alice := login(t, ts, "alice", ldaptest.Password)
	_, _, bob := login(t, ts, "bob", ldaptest.Password)

	// Moved out of the admin groups: the session loses access.
	srv.Add(ldaptest.ADITLeads, map[string][]string{"objectClass": {"top", "group"}, "member": {}})
	if code, _ := getTwice(t, ts, s, "/api/me", alice); code != 401 {
		t.Errorf("alice after leaving the groups = %d", code)
	}
	// Disabled in Active Directory (the user filter skips disabled accounts).
	srv.Add(ldaptest.ADBobDN, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "user"}, "objectCategory": {"CN=Person,CN=Schema,CN=Configuration," + ldaptest.ADBase},
		"sAMAccountName": {"bob"}, "displayName": {"Bob Analyst"}, "userAccountControl": {"514"},
	})
	if code, _ := getTwice(t, ts, s, "/api/me", bob); code != 401 {
		t.Errorf("bob after being disabled in AD = %d", code)
	}
	if u := listedUser(t, ts, "bob"); u == nil || !strings.Contains(fmt_(u["refused"]), "not found") {
		t.Errorf("bob in the list = %v", u)
	}
}

// A change to the group mappings applies to signed-in directory users at
// their next requests, and checks wait for the interval otherwise.
func TestMappingChangeAppliesToSignedInUsers(t *testing.T) {
	srv, ts, s := startAD(t, nil) // the default 5 minute interval
	_, me, bob := login(t, ts, "bob", ldaptest.Password)
	if me["role"] != "analyst" {
		t.Fatalf("bob = %v", me)
	}
	binds := len(srv.Binds())
	if code, me := getTwice(t, ts, s, "/api/me", bob); code != 200 || me["role"] != "analyst" || len(srv.Binds()) != binds {
		t.Errorf("bob before the change = %d %v, %d binds", code, me, len(srv.Binds())-binds)
	}
	// SOC Analysts now gives Viewer.
	moved := adSettingsJSON(srv, `"analyst_groups":[],"viewer_groups":["`+ldaptest.ADViewers+`","`+ldaptest.ADAnalysts+`"]`)
	if code, _, raw := call(t, ts, "PUT", "/api/auth/directory", moved, "admin", adminPass, nil); code != 200 {
		t.Fatalf("save = %d %s", code, raw)
	}
	// Saving checks signed-in directory users again straight away.
	s.background.Wait()
	if code, me, _ := call(t, ts, "GET", "/api/me", "", "", "", bob); code != 200 || me["role"] != "viewer" {
		t.Errorf("bob after the mapping change = %d %v", code, me)
	}
	if code, _, _ := call(t, ts, "POST", "/api/cases", `{"title":"x"}`, "", "", bob); code != 403 {
		t.Errorf("bob as viewer opens a case = %d", code)
	}
}

// With directory sign-in on, a name that is not a local user still costs a
// password hash check, so the time a refusal takes does not tell which
// names are local users.
func TestRefusalTimeDoesNotRevealLocalUsers(t *testing.T) {
	_, ts, s := startAD(t, func(s *Server) {
		s.Users.Create(context.Background(), users.NewUser{Username: "localann", Role: users.Viewer, Password: "ann-password"})
	})
	s.Limiter.MaxPerAddress, s.Limiter.Max, s.Limiter.MaxPerAccount = 1000, 1000, 1000
	median := func(name string) time.Duration {
		var d []time.Duration
		for range 5 {
			start := time.Now()
			login(t, ts, name, "wrong-password")
			d = append(d, time.Since(start))
		}
		slices.Sort(d)
		return d[2]
	}
	median("warm-up")
	local, unknown := median("localann"), median("nosuchuser")
	if unknown < local/2 {
		t.Errorf("a local name takes %v to refuse, an unknown one %v", local, unknown)
	}
}

// A route registered straight on the outer mux, without a role, is
// admin-only rather than public.
func TestOuterMuxAPIRoutesNeedAdmin(t *testing.T) {
	ts, s := newRoleServer(t)
	ts.Close()
	ran := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/syslog/", func(w http.ResponseWriter, r *http.Request) { ran++; w.WriteHeader(http.StatusTeapot) })
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("/", http.NotFoundHandler())
	guarded := httptest.NewServer(s.guardAPI(mux))
	defer guarded.Close()
	if code, _, _ := call(t, guarded, "POST", "/api/syslog/x", "", "", "", nil); code != 401 || ran != 0 {
		t.Errorf("signed out = %d, ran %d", code, ran)
	}
	if code, _ := doAs(t, guarded, "andy", "role-password", "POST", "/api/syslog/x", ""); code != 403 || ran != 0 {
		t.Errorf("analyst = %d, ran %d", code, ran)
	}
	if code, _ := doAs(t, guarded, "admin", adminPass, "POST", "/api/syslog/x", ""); code != http.StatusTeapot || ran != 1 {
		t.Errorf("admin = %d, ran %d", code, ran)
	}
	if code, _, _ := call(t, guarded, "POST", "/api/login", "", "", "", nil); code != http.StatusNoContent {
		t.Errorf("public route = %d", code)
	}
}

// Analysts remove only the case notes, events and searches they added;
// admins remove anyone's.
func TestOnlyTheAuthorOrAnAdminRemovesCaseEntries(t *testing.T) {
	ts, s := newRoleServer(t)
	s.Users.Create(context.Background(), users.NewUser{Username: "amy", Role: users.Analyst, Password: "role-password"})
	code, body := doAs(t, ts, "andy", "role-password", "POST", "/api/cases", `{"title":"Phishing"}`)
	if code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}
	id := body["case"].(map[string]any)["id"].(string)
	note := func(who, pass string) string {
		code, body := doAs(t, ts, who, pass, "POST", "/api/cases/"+id+"/entries", `{"kind":"note","text":"note by `+who+`"}`)
		if code != 201 {
			t.Fatalf("note = %d %v", code, body)
		}
		return body["entry"].(map[string]any)["id"].(string)
	}
	andys, andys2 := note("andy", "role-password"), note("andy", "role-password")
	amys := note("amy", "role-password")
	if code, body := doAs(t, ts, "amy", "role-password", "DELETE", "/api/cases/"+id+"/entries/"+andys, ""); code != 403 || body["code"] != "not_author" {
		t.Errorf("amy removes andy's note = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "amy", "role-password", "DELETE", "/api/cases/"+id+"/entries/"+amys, ""); code != 200 {
		t.Errorf("amy removes her own note = %d", code)
	}
	if code, _ := doAs(t, ts, "admin", adminPass, "DELETE", "/api/cases/"+id+"/entries/"+andys, ""); code != 200 {
		t.Errorf("admin removes andy's note = %d", code)
	}
	code, body = doAs(t, ts, "andy", "role-password", "GET", "/api/cases/"+id, "")
	b, _ := json.Marshal(body)
	if code != 200 || !strings.Contains(string(b), andys2) || strings.Contains(string(b), `"`+amys+`"`) {
		t.Errorf("case = %d %s", code, b)
	}
}
