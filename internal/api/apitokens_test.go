// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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

// A new token lasts 90 days unless another number of days, or never, is
// chosen; an expired token is refused and its use logged like a revoked
// one's; a token without an expiry, as every old one, is accepted.
func TestAPITokenExpiry(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, code := c.a.signIn("admin", "s3cret-pass")
	if admin == nil {
		t.Fatalf("sign in: %d", code)
	}
	for _, body := range []string{
		`{"name":"x","expires_in_days":0}`,
		`{"name":"x","expires_in_days":-1}`,
		`{"name":"x","expires_in_days":366}`,
		`{"name":"x","expires_in_days":30,"never":true}`,
		`{"name":"x","expires_in_days":"never"}`,
	} {
		if code, out, _ := c.a.call("POST", "/api/api-tokens", body, admin, nil); code != http.StatusBadRequest {
			t.Errorf("create %s: %d %v", body, code, out)
		}
	}
	days := func(out map[string]any) int {
		created, _ := time.Parse(time.RFC3339Nano, out["created"].(string))
		exp, ok := out["expires"].(string)
		if !ok {
			return 0
		}
		e, _ := time.Parse(time.RFC3339Nano, exp)
		return int(e.Sub(created).Hours() / 24)
	}
	code, out, _ := c.a.call("POST", "/api/api-tokens", `{"name":"Default"}`, admin, nil)
	if code != http.StatusCreated || days(out) != 90 || out["expired"] != false {
		t.Errorf("a token made without a number of days: %d %v", code, out)
	}
	if !strings.Contains(c.a.logs.String(), "expires=20") {
		t.Errorf("the audit record lacks the expiry:\n%s", c.a.logs.String())
	}
	code, out, _ = c.a.call("POST", "/api/api-tokens", `{"name":"Month","expires_in_days":30}`, admin, nil)
	if code != http.StatusCreated || days(out) != 30 {
		t.Errorf("a token for 30 days: %d %v", code, out)
	}
	code, out, _ = c.a.call("POST", "/api/api-tokens", `{"name":"Forever","never":true}`, admin, nil)
	if code != http.StatusCreated || out["expires"] != nil {
		t.Fatalf("a token that never expires: %d %v", code, out)
	}
	if !strings.Contains(c.a.logs.String(), "expires=never") {
		t.Errorf("the audit record lacks that it never expires:\n%s", c.a.logs.String())
	}
	forever, _ := out["token"].(string)
	code, out, _ = c.a.call("GET", "/api/me", "", nil, map[string]string{"Authorization": "Bearer " + forever})
	if code != 200 {
		t.Errorf("a token that never expires: %d %v", code, out)
	}
	// Its first use is recorded, off the request's path.
	c.a.srv.background.Wait()
	_, out, _ = c.a.call("GET", "/api/api-tokens", "", admin, nil)
	var listed map[string]any
	for _, tk := range out["tokens"].([]any) {
		if m := tk.(map[string]any); m["name"] == "Forever" {
			listed = m
		}
	}
	if listed == nil || listed["last_used"] == nil {
		t.Errorf("the token's last use: %v", listed)
	}

	// Made two days ago for one day: expired a day ago.
	old, secret, err := c.a.docs.CreateAPIToken(context.Background(), "admin", "Expired", users.Viewer, 1, time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c.b.cycle()
	bearer := map[string]string{"Authorization": "Bearer " + secret}
	if code, _, _ := c.b.call("GET", "/api/me", "", nil, bearer); code != http.StatusUnauthorized {
		t.Errorf("an expired token: %d", code)
	}
	if logs := c.b.logs.String(); !strings.Contains(logs, "api_token.refused") || !strings.Contains(logs, "reason=expired") ||
		!strings.Contains(logs, "token_id="+old.ID) {
		t.Errorf("no audit record of the expired token's use:\n%s", logs)
	}
	// Logged once an hour, not once a request.
	c.b.call("GET", "/api/me", "", nil, bearer)
	if n := strings.Count(c.b.logs.String(), "api_token.refused"); n != 1 {
		t.Errorf("the refusal was logged %d times", n)
	}
	code, out, _ = c.b.call("GET", "/api/api-tokens", "", nil, map[string]string{"Authorization": basicHeader("admin", "s3cret-pass")})
	for _, tk := range out["tokens"].([]any) {
		if m := tk.(map[string]any); m["name"] == "Expired" && (m["active"] != false || m["expired"] != true) {
			t.Errorf("the expired token is listed as %v", m)
		}
	}
	// A revoked token's use is logged the same way.
	if _, err := c.b.docs.RevokeAPIToken(context.Background(), "admin", old.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, secret2, err := c.a.docs.CreateAPIToken(context.Background(), "admin", "Revoked", users.Viewer, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c.a.cycle()
	for _, b := range c.a.docs.APITokens() {
		if b.Name == "Revoked" {
			if _, err := c.a.docs.RevokeAPIToken(context.Background(), "admin", b.ID, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if code, _, _ := c.a.call("GET", "/api/me", "", nil, map[string]string{"Authorization": "Bearer " + secret2}); code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", code)
	}
	if !strings.Contains(c.a.logs.String(), "reason=revoked") {
		t.Errorf("no audit record of the revoked token's use:\n%s", c.a.logs.String())
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
