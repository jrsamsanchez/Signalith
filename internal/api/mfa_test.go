package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// loginCode signs in with a two-step code and returns the status, the
// reply and the session cookie.
func loginCode(t *testing.T, ts *httptest.Server, user, pass, code string) (int, map[string]any, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass, "code": code})
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

// setUpMFA turns two-step sign-in on for the user of session c and
// returns the key and the recovery codes.
func setUpMFA(t *testing.T, ts *httptest.Server, c *http.Cookie) (string, []string) {
	t.Helper()
	code, out, raw := call(t, ts, "POST", "/api/me/mfa/setup", "{}", "", "", c)
	if code != 200 {
		t.Fatalf("setup = %d %s", code, raw)
	}
	secret := strings.ReplaceAll(out["secret"].(string), " ", "")
	if svg, _ := out["qr_svg"].(string); !strings.HasPrefix(svg, "<svg") || !strings.HasPrefix(out["otpauth"].(string), "otpauth://totp/Signalith:") {
		t.Errorf("setup %v", out)
	}
	now, _ := users.TOTP(secret, time.Now())
	code, out, raw = call(t, ts, "POST", "/api/me/mfa/confirm", `{"code":"`+now+`"}`, "", "", c)
	if code != 200 {
		t.Fatalf("confirm = %d %s", code, raw)
	}
	var codes []string
	for _, v := range out["recovery_codes"].([]any) {
		codes = append(codes, v.(string))
	}
	if len(codes) != users.RecoveryCodes {
		t.Fatalf("recovery codes %v", out)
	}
	return secret, codes
}

func TestMFASignIn(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "jdoe", Role: users.Analyst, Password: "jdoe-password"}); err != nil {
		t.Fatal(err)
	}
	code, _, c := login(t, ts, "jdoe", "jdoe-password")
	if code != 200 || c == nil {
		t.Fatalf("login = %d", code)
	}
	if code, out, _ := call(t, ts, "GET", "/api/me/mfa", "", "", "", c); code != 200 || out["on"] != false || out["possible"] != true {
		t.Errorf("status before = %d %v", code, out)
	}
	secret, codes := setUpMFA(t, ts, c)
	if code, out, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 200 || out["mfa"] != true {
		t.Errorf("me after set-up = %d %v", code, out)
	}

	// The password alone now asks for the code, and sets no cookie.
	code, out, c2 := loginCode(t, ts, "jdoe", "jdoe-password", "")
	if code != 401 || out["code"] != "mfa_required" || c2 != nil {
		t.Errorf("password only = %d %v", code, out)
	}
	if code, out, _ := loginCode(t, ts, "jdoe", "wrong-password", ""); code != 401 || out["code"] != "wrong_credentials" {
		t.Errorf("wrong password = %d %v", code, out)
	}
	if code, out, _ := loginCode(t, ts, "jdoe", "jdoe-password", "000000"); code != 401 || out["code"] != "mfa_wrong" {
		t.Errorf("wrong code = %d %v", code, out)
	}
	// The code of the next step works (a phone a little ahead), once.
	next, _ := users.TOTP(secret, time.Now().Add(30*time.Second))
	if code, out, c := loginCode(t, ts, "jdoe", "jdoe-password", next); code != 200 || c == nil || out["mfa"] != true {
		t.Errorf("right code = %d %v", code, out)
	}
	if code, out, _ := loginCode(t, ts, "jdoe", "jdoe-password", next); code != 401 || out["code"] != "mfa_wrong" {
		t.Errorf("same code again = %d %v", code, out)
	}
	if code, out, c := loginCode(t, ts, "jdoe", "jdoe-password", codes[0]); code != 200 || c == nil || out["recovery_codes_left"] != float64(users.RecoveryCodes-1) {
		t.Errorf("recovery code = %d %v", code, out)
	}

	// Basic auth has no code, so it is refused, from the cache too.
	if code, out := doAs(t, ts, "jdoe", "jdoe-password", "GET", "/api/me", ""); code != 403 || out["code"] != "mfa_basic" {
		t.Errorf("basic auth = %d %v", code, out)
	}

	// Turning it off takes a code.
	if code, out, _ := call(t, ts, "POST", "/api/me/mfa/off", `{"code":"123456"}`, "", "", c); code != 400 || out["code"] != "mfa_wrong" {
		t.Errorf("off with a wrong code = %d %v", code, out)
	}
	if code, out, _ := call(t, ts, "POST", "/api/me/mfa/recovery", `{"code":"`+codes[1]+`"}`, "", "", c); code != 200 || len(out["recovery_codes"].([]any)) != users.RecoveryCodes {
		t.Errorf("new recovery codes = %d %v", code, out)
	}

	// An admin resets it, and the password alone works again.
	if code, out, _ := call(t, ts, "GET", "/api/users", "", "admin", adminPass, nil); code != 200 || !hasUser(out, "jdoe", true, "reset_mfa") {
		t.Errorf("users list = %d %v", code, out)
	}
	if code, out, _ := call(t, ts, "DELETE", "/api/users/jdoe/mfa", "", "admin", adminPass, nil); code != 200 {
		t.Errorf("reset = %d %v", code, out)
	}
	if code, out, c := login(t, ts, "jdoe", "jdoe-password"); code != 200 || c == nil || out["mfa"] != false {
		t.Errorf("login after reset = %d %v", code, out)
	}
	if code, _ := doAs(t, ts, "jdoe", "jdoe-password", "GET", "/api/me", ""); code != 200 {
		t.Errorf("basic auth after reset = %d", code)
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/users/admin/mfa", "", "admin", adminPass, nil); code != 409 {
		t.Errorf("reset own = %d", code)
	}
}

// hasUser reports whether the users list has name with two-step sign-in
// on or off as given, and the action when it is set.
func hasUser(out map[string]any, name string, mfa bool, action string) bool {
	list, _ := out["users"].([]any)
	for _, v := range list {
		u := v.(map[string]any)
		if u["username"] != name {
			continue
		}
		if u["mfa"] != mfa {
			return false
		}
		if action == "" {
			return true
		}
		for _, a := range u["actions"].([]any) {
			if a == action {
				return true
			}
		}
	}
	return false
}

func TestMFARequired(t *testing.T) {
	ts, s := newUsersServer(t, func(s *Server) { s.Config.Auth.MFARequired = "everyone" })
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "vera-password"}); err != nil {
		t.Fatal(err)
	}
	code, out, c := login(t, ts, "vera", "vera-password")
	if code != 200 || c == nil || out["must_setup_mfa"] != true {
		t.Fatalf("login = %d %v", code, out)
	}
	// Nothing but setting it up works until then.
	if code, out, _ := call(t, ts, "GET", "/api/findings", "", "", "", c); code != 403 || out["code"] != "mfa_setup_required" {
		t.Errorf("findings = %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.AddCookie(c)
	if resp, err := noRedirect.Do(req); err != nil || resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?mfa=setup" {
		t.Errorf("page = %v %v", resp, err)
	}
	if code, _ := doAs(t, ts, "vera", "vera-password", "GET", "/api/me", ""); code != 403 {
		t.Errorf("basic auth while required = %d", code)
	}
	setUpMFA(t, ts, c)
	if code, _, _ := call(t, ts, "GET", "/api/findings", "", "", "", c); code != 200 {
		t.Errorf("findings after set-up = %d", code)
	}
	// Admins only: a viewer is not asked.
	s.Config.Auth.MFARequired = "admins"
	if p := s.principalFor("vera"); p == nil || p.MustSetupMFA || !p.MFA {
		t.Errorf("vera %+v", p)
	}
	if p := s.principalFor("admin"); p == nil || !p.MustSetupMFA {
		t.Errorf("admin %+v", p)
	}
}

// Wrong codes count toward the sign-in limits like wrong passwords, so
// the code cannot be guessed by someone who knows the password.
func TestWrongCodesLockOut(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "jdoe", Role: users.Analyst, Password: "jdoe-password"}); err != nil {
		t.Fatal(err)
	}
	_, _, c := login(t, ts, "jdoe", "jdoe-password")
	secret, _ := setUpMFA(t, ts, c)
	for range 10 {
		loginCode(t, ts, "jdoe", "jdoe-password", "000000")
	}
	next, _ := users.TOTP(secret, time.Now().Add(30*time.Second))
	if code, out, _ := loginCode(t, ts, "jdoe", "jdoe-password", next); code != 429 || out["code"] != "locked_out" {
		t.Errorf("right code after 10 wrong ones = %d %v", code, out)
	}
	// The password alone does not clear the count either.
	if code, _, _ := loginCode(t, ts, "jdoe", "jdoe-password", ""); code != 429 {
		t.Errorf("password only after 10 wrong codes = %d", code)
	}
}

func TestBuiltinAdminMFA(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	_, _, c := login(t, ts, "admin", adminPass)
	secret, _ := setUpMFA(t, ts, c)
	if code, out, _ := login(t, ts, "admin", adminPass); code != 401 || out["code"] != "mfa_required" {
		t.Errorf("password only = %d %v", code, out)
	}
	next, _ := users.TOTP(secret, time.Now().Add(30*time.Second))
	if code, _, c := loginCode(t, ts, "admin", adminPass, next); code != 200 || c == nil {
		t.Errorf("with code = %d", code)
	}
}
