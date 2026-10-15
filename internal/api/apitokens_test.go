package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// An API token made on one server reads on every server of the cluster,
// as its role, but can only read; revoked, it is refused everywhere.
func TestAPITokensAcrossServers(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, code := c.a.signIn("admin", "s3cret-pass")
	if admin == nil {
		t.Fatalf("sign in: %d", code)
	}
	code, out, _ := c.a.call("POST", "/api/api-tokens", `{"name":"Claude Desktop","role":"viewer"}`, admin, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	tok, _ := out["token"].(string)
	id, _ := out["id"].(string)
	if !strings.HasPrefix(tok, "sgl_api_") || len(tok) != 60 || out["user"] != "api-token:Claude Desktop" {
		t.Fatalf("created %v", out)
	}
	if !strings.Contains(c.a.logs.String(), "api_token.create") || !strings.Contains(c.a.logs.String(), `token="Claude Desktop"`) {
		t.Errorf("no audit record of the creation:\n%s", c.a.logs.String())
	}
	// The list never shows the secret.
	code, out, _ = c.a.call("GET", "/api/api-tokens", "", admin, nil)
	if code != 200 || out["on"] != true || strings.Contains(stringOf(out), tok) || strings.Contains(stringOf(out), "hash") {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _, _ := c.a.call("POST", "/api/api-tokens", `{"name":"claude desktop"}`, admin, nil); code != http.StatusConflict {
		t.Errorf("a second active token of that name: %d", code)
	}
	if code, _, _ := c.a.call("POST", "/api/api-tokens", `{"name":"x","role":"admin"}`, admin, nil); code != http.StatusBadRequest {
		t.Errorf("an admin token: %d", code)
	}

	bearer := map[string]string{"Authorization": "Bearer " + tok}
	c.b.cycle()
	code, out, _ = c.b.call("GET", "/api/me", "", nil, bearer)
	if code != 200 || out["username"] != "api-token:Claude Desktop" || out["role"] != string(users.Viewer) || out["auth"] != "token" {
		t.Fatalf("me with the token on the other server: %d %v", code, out)
	}
	// Only reads: a change is refused whatever the role allows.
	code, out, _ = c.b.call("POST", "/api/cases", `{"title":"x"}`, nil, bearer)
	if code != http.StatusForbidden || out["code"] != "token_read_only" {
		t.Errorf("a change with the token: %d %v", code, out)
	}
	if code, out, _ := c.b.call("POST", "/api/parse", `{"query":"index=main"}`, nil, bearer); out["code"] == "token_read_only" {
		t.Errorf("parse is a read: %d %v", code, out)
	}
	// Its role: a viewer's.
	if code, _, _ := c.b.call("GET", "/api/agent-tokens", "", nil, bearer); code != http.StatusForbidden {
		t.Errorf("an analyst route with a viewer token: %d", code)
	}
	if code, _, _ := c.b.call("GET", "/api/api-tokens", "", nil, bearer); code != http.StatusForbidden {
		t.Errorf("the token list with a token: %d", code)
	}
	// A token not accepted never falls back to the session.
	wrong := map[string]string{"Authorization": "Bearer sgl_api_" + strings.Repeat("a", 52)}
	if code, _, _ := c.a.call("GET", "/api/me", "", admin, wrong); code != http.StatusUnauthorized {
		t.Errorf("a wrong token with a session cookie: %d", code)
	}

	// Revoked on B: refused on A after a poll.
	code, out, _ = c.b.call("POST", "/api/api-tokens/"+id+"/revoke", "", nil, map[string]string{"Authorization": basicHeader("admin", "s3cret-pass")})
	if code != 200 || out["active"] != false {
		t.Fatalf("revoke: %d %v", code, out)
	}
	c.a.cycle()
	if code, _, _ := c.a.call("GET", "/api/me", "", nil, bearer); code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", code)
	}
	if code, _, _ := c.a.call("POST", "/api/api-tokens/0123456789ab/revoke", "", admin, nil); code != http.StatusNotFound {
		t.Errorf("revoke an unknown token: %d", code)
	}
	// The name is free again.
	if code, _, _ := c.a.call("POST", "/api/api-tokens", `{"name":"Claude Desktop","role":"analyst"}`, admin, nil); code != http.StatusCreated {
		t.Errorf("a new token of a revoked one's name: %d", code)
	}
}

// Below the level of API tokens, none can be made.
func TestAPITokensOff(t *testing.T) {
	c := newMemberCluster(t, func(s *Server) {
		s.SharedUsers.APITokens = func() string { return "upgrade the others first" }
	})
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	if code, out, _ := c.a.call("GET", "/api/api-tokens", "", admin, nil); code != 200 || out["on"] != false {
		t.Errorf("list: %d %v", code, out)
	}
	if code, _, _ := c.a.call("POST", "/api/api-tokens", `{"name":"x"}`, admin, nil); code != http.StatusServiceUnavailable {
		t.Errorf("create: %d", code)
	}
	// A server without shared users has none.
	ts, _ := newTestServerWith(t, nil)
	if code, out := do(t, ts, "GET", "/api/api-tokens", "", true); code != 200 || out["on"] != false {
		t.Errorf("without shared users: %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer sgl_api_"+strings.Repeat("a", 52))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a token without shared users: %d", resp.StatusCode)
	}
}

func stringOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
