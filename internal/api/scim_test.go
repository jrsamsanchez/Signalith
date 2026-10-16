package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
	"github.com/jrsamsanchez/signalith/internal/users"
)

const scimTestToken = "sgl_scim_test-token-0123456789abcdefghijklmnopqrstuvwxyz"

// newSCIMServer starts a single sign-on server with provisioning on.
func newSCIMServer(t *testing.T, p *oidctest.Provider) (*httptest.Server, *Server) {
	t.Helper()
	ts, s := newSSOServer(t, p, nil)
	sum := sha256.Sum256([]byte(scimTestToken))
	s.Config.Auth.SCIM.Enabled = true
	s.Config.Auth.SCIM.TokenSHA256 = hex.EncodeToString(sum[:])
	return ts, s
}

// scimCall sends a SCIM request with the token and returns the status
// and the decoded answer.
func scimCall(t *testing.T, ts *httptest.Server, method, path, body, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+"/api/scim/v2"+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/scim+json" {
			t.Errorf("%s %s: content type %q", method, path, ct)
		}
	}
	return resp.StatusCode, out
}

func TestSCIMNeedsTheToken(t *testing.T) {
	p := oidctest.New(t)
	ts, s := newSCIMServer(t, p)
	for _, tok := range []string{"", "wrong", strings.ToUpper(scimTestToken)} {
		if code, out := scimCall(t, ts, "GET", "/Users", "", tok); code != 401 || out["status"] != "401" {
			t.Errorf("token %q: %d %v", tok, code, out)
		}
	}
	// Signing in as an admin is not enough either.
	if code, _, _ := call(t, ts, "GET", "/api/scim/v2/Users", "", "admin", adminPass, nil); code != 401 {
		t.Errorf("admin password: %d", code)
	}
	if code, _ := scimCall(t, ts, "GET", "/Users", "", scimTestToken); code != 200 {
		t.Errorf("token: %d", code)
	}
	s.Config.Auth.SCIM.Enabled = false
	if code, _ := scimCall(t, ts, "GET", "/Users", "", scimTestToken); code != 403 {
		t.Errorf("provisioning off: %d", code)
	}
}

// An Entra ID provisioning cycle: look up, add, update, disable, then the
// person signs in, and is finally removed.
func TestSCIMEntraCycle(t *testing.T) {
	p := oidctest.New(t)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "alice@contoso.com", "groups": []any{"/soc"}, "oid": "E1"}
	})
	ts, s := newSCIMServer(t, p)
	if _, err := s.userStore().Create(t.Context(), users.NewUser{Username: "bob", Role: users.Analyst, Password: "a long password"}); err != nil {
		t.Fatal(err)
	}

	code, out := scimCall(t, ts, "GET", `/Users?filter=userName+eq+%22alice%40contoso.com%22`, "", scimTestToken)
	if code != 200 || out["totalResults"] != 0.0 {
		t.Fatalf("lookup: %d %v", code, out)
	}
	code, out = scimCall(t, ts, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"E1",
		"userName":"Alice@Contoso.com","active":true,"displayName":"Alice Smith","emails":[{"primary":true,"type":"work","value":"alice@contoso.com"}]}`, scimTestToken)
	if code != 201 || out["id"] != "alice@contoso.com" || out["externalId"] != "E1" || out["active"] != true {
		t.Fatalf("add: %d %v", code, out)
	}
	if code, out := scimCall(t, ts, "POST", "/Users", `{"userName":"alice@contoso.com"}`, scimTestToken); code != 409 || out["scimType"] != "uniqueness" {
		t.Errorf("add again: %d %v", code, out)
	}
	if code, out := scimCall(t, ts, "POST", "/Users", `{"userName":"bob"}`, scimTestToken); code != 409 || out["scimType"] != "uniqueness" {
		t.Errorf("local user's name: %d %v", code, out)
	}
	// Local users are not provisioning's to see or change.
	if code, _ := scimCall(t, ts, "GET", "/Users/bob", "", scimTestToken); code != 404 {
		t.Errorf("get local user: %d", code)
	}
	if code, _ := scimCall(t, ts, "DELETE", "/Users/bob", "", scimTestToken); code != 404 {
		t.Errorf("delete local user: %d", code)
	}
	code, out = scimCall(t, ts, "GET", `/Users?filter=externalId+eq+%22E1%22`, "", scimTestToken)
	if code != 200 || out["totalResults"] != 1.0 {
		t.Fatalf("by externalId: %d %v", code, out)
	}

	// The Users page shows them as not signed in yet.
	code, list, _ := call(t, ts, "GET", "/api/users", "", "admin", adminPass, nil)
	if code != 200 || !strings.Contains(mustJSON(list), `"pending":true`) {
		t.Errorf("users page: %d %v", code, list)
	}

	code, out = scimCall(t, ts, "PATCH", "/Users/alice@contoso.com", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"Replace","path":"displayName","value":"Alice Jones"},
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"alice.jones@contoso.com"},
		{"op":"Replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"SOC"}]}`, scimTestToken)
	if code != 200 || out["displayName"] != "Alice Jones" {
		t.Fatalf("patch: %d %v", code, out)
	}
	if code, out := scimCall(t, ts, "PATCH", "/Users/alice@contoso.com", `{"Operations":[{"op":"Replace","path":"userName","value":"alice2@contoso.com"}]}`, scimTestToken); code != 400 || out["scimType"] != "mutability" {
		t.Errorf("rename: %d %v", code, out)
	}

	// Someone else whose username claim says the same is refused: the
	// first sign-in must match the externalId or the verified email.
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "alice@contoso.com", "groups": []any{"/soc"}, "oid": "someone-else"}
	})
	if at, _ := ssoSignIn(t, browser(t, p), ts, ""); at.Query().Get("sso_error") != "unconfirmed" {
		t.Errorf("unconfirmed first sign-in ended at %s", at)
	}
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "alice@contoso.com", "groups": []any{"/soc"}, "oid": "E1"}
	})

	// They sign in: the identity is bound, the role comes from groups.
	b := browser(t, p)
	ssoSignIn(t, b, ts, "")
	if code, who := me(t, b, ts); code != 200 || who["username"] != "alice@contoso.com" || who["role"] != "analyst" || who["name"] != "Alice Jones" {
		t.Fatalf("me = %d %v", code, who)
	}
	if u, _ := s.userStore().Get("alice@contoso.com"); u.Pending() || u.Subject != users.SSOSubject(p.Issuer, "00u1abcd") {
		t.Errorf("after sign-in %+v", u)
	}

	// Disabled at the provider: signed out at once.
	code, out = scimCall(t, ts, "PATCH", "/Users/alice@contoso.com", `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, scimTestToken)
	if code != 200 || out["active"] != false {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, _ := me(t, b, ts); code != 401 {
		t.Errorf("session after disable: %d", code)
	}
	ssoSignIn(t, b, ts, "")
	if code, _ := me(t, b, ts); code != 401 {
		t.Errorf("sign-in while disabled: %d", code)
	}

	// An admin's disable here is not undone by the provider's next sync.
	if code, _ := scimCall(t, ts, "PATCH", "/Users/alice@contoso.com", `{"Operations":[{"op":"Replace","path":"active","value":"True"}]}`, scimTestToken); code != 200 {
		t.Fatalf("enable: %d", code)
	}
	if code, _, _ := call(t, ts, "PUT", "/api/users/alice@contoso.com", `{"disabled":true}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("admin disable: %d", code)
	}
	code, out = scimCall(t, ts, "PUT", "/Users/alice@contoso.com", `{"userName":"alice@contoso.com","displayName":"Alice Jones","active":true}`, scimTestToken)
	if code != 200 || out["active"] != false {
		t.Errorf("sync after an admin's disable: %d %v", code, out)
	}

	if code, _ := scimCall(t, ts, "DELETE", "/Users/alice@contoso.com", "", scimTestToken); code != 204 {
		t.Errorf("delete: %d", code)
	}
	if _, ok := s.userStore().Get("alice@contoso.com"); ok {
		t.Error("still there after delete")
	}
}

// Okta replaces whole users with PUT and disables with a PATCH that has
// no path.
func TestSCIMOktaCycle(t *testing.T) {
	p := oidctest.New(t)
	ts, s := newSCIMServer(t, p)
	code, out := scimCall(t, ts, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol@example.com",
		"name":{"givenName":"Carol","familyName":"King"},"emails":[{"primary":true,"value":"carol@example.com","type":"work"}],
		"displayName":"Carol King","locale":"en-US","externalId":"00u5","groups":[],"password":"never-kept","active":true}`, scimTestToken)
	if code != 201 || out["displayName"] != "Carol King" {
		t.Fatalf("add: %d %v", code, out)
	}
	code, out = scimCall(t, ts, "PUT", "/Users/carol@example.com", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"carol@example.com",
		"userName":"carol@example.com","name":{"givenName":"Carol","familyName":"Klein"},"emails":[{"primary":true,"value":"carol.k@example.com"}],
		"externalId":"00u5","active":true}`, scimTestToken)
	if code != 200 || out["displayName"] != "Carol Klein" {
		t.Fatalf("put: %d %v", code, out)
	}
	if code, out := scimCall(t, ts, "PATCH", "/Users/carol@example.com", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`, scimTestToken); code != 200 || out["active"] != false {
		t.Fatalf("deactivate: %d %v", code, out)
	}
	if u, _ := s.userStore().Get("carol@example.com"); !u.Disabled || u.Email != "carol.k@example.com" {
		t.Errorf("user %+v", u)
	}
	for _, path := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas", "/Groups", "/Users?startIndex=1&count=10"} {
		if code, out := scimCall(t, ts, "GET", path, "", scimTestToken); code != 200 || out["schemas"] == nil {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
	if code, out := scimCall(t, ts, "GET", `/Users?filter=title+eq+%22x%22`, "", scimTestToken); code != 400 || out["scimType"] != "invalidFilter" {
		t.Errorf("unknown filter: %d %v", code, out)
	}
	if code, _ := scimCall(t, ts, "POST", "/Users", `{"userName":"`+strings.Repeat("x", 70<<10)+`"}`, scimTestToken); code != 413 {
		t.Errorf("huge body: %d", code)
	}
}

func TestSCIMToken(t *testing.T) {
	p := oidctest.New(t)
	ts, _ := newSSOServer(t, p, nil)
	code, out, _ := call(t, ts, "POST", "/api/auth/scim/token", "", "admin", adminPass, nil)
	tok, _ := out["token"].(string)
	sum := sha256.Sum256([]byte(tok))
	if code != 200 || !strings.HasPrefix(tok, "sgl_scim_") || len(tok) < 50 || out["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("token: %d %v", code, out)
	}
	code, out, _ = call(t, ts, "GET", "/api/auth/oidc", "", "admin", adminPass, nil)
	if code != 200 || out["scim_url"] != ts.URL+"/api/scim/v2" {
		t.Errorf("tab: %d %v", code, out["scim_url"])
	}
}

// A token made on the tab and saved with the settings works at once,
// and a bad fingerprint is refused.
func TestSCIMTokenSaved(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", nil)
	code, out, _ := call(t, ts, "POST", "/api/auth/scim/token", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("token: %d %v", code, out)
	}
	tok := out["token"].(string)
	if code, _ := scimCall(t, ts, "GET", "/Users", "", tok); code != 403 {
		t.Errorf("before saving: %d", code)
	}
	body := `{"values":{"auth.scim.enabled":true,"auth.scim.token_sha256":"` + out["sha256"].(string) + `"}}`
	if code, out, raw := call(t, ts, "PUT", "/api/settings", body, "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("save: %d %v %s", code, out, raw)
	}
	if code, out := scimCall(t, ts, "GET", "/Users", "", tok); code != 200 || out["totalResults"] != 0.0 {
		t.Errorf("after saving: %d %v", code, out)
	}
	if code, _, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"auth.scim.token_sha256":"not-a-hash"}}`, "admin", "s3cret-pass", nil); code != 400 {
		t.Errorf("bad fingerprint saved: %d", code)
	}
	if code, _, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"auth.scim.enabled":true},"clear":["auth.scim.token_sha256"]}`, "admin", "s3cret-pass", nil); code != 400 {
		t.Errorf("on without a token saved: %d", code)
	}
}

func TestSCIMRefusalsLogOncePerMinute(t *testing.T) {
	var f scimRefusals
	now := time.Now()
	if n := f.note("10.0.0.1", now); n != 1 {
		t.Errorf("first: %d", n)
	}
	for i := 0; i < 50; i++ {
		if n := f.note("10.0.0.1", now.Add(time.Second)); n != 0 {
			t.Fatalf("within the minute: %d", n)
		}
	}
	if n := f.note("10.0.0.2", now); n != 1 {
		t.Errorf("another address: %d", n)
	}
	if n := f.note("10.0.0.1", now.Add(61*time.Second)); n != 51 {
		t.Errorf("a minute on: %d", n)
	}
}
