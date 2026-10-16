package main

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// A tenant added on a running server gets data of its own: its agents'
// events go to its indices only, its users see only its data, and the
// default tenant's agents and users never reach it.
func TestTenantsDataStaysApart(t *testing.T) {
	// Without the background jobs this server never founds a cluster,
	// whose shared users cannot have tenants yet.
	rs := startRunnerWith(t, runOptions{server: plainHTTP})
	must := func(method, path, body string, want int) map[string]any {
		t.Helper()
		code, out, err := rs.call("", method, path, body)
		if err != nil || code != want {
			t.Fatalf("%s %s: %d %v %v, want %d\n%s", method, path, code, out, err, want, rs.logs.String())
		}
		return out
	}
	must("POST", "/api/tenants", `{"id":"acme","name":"Acme Corp"}`, http.StatusCreated)
	if out := must("GET", "/api/tenants", "", 200); out["enabled"] != true {
		t.Fatalf("tenants: %v", out)
	}
	// Its index template, apart from the default tenant's.
	for deadline := time.Now().Add(20 * time.Second); !slices.Contains(rs.os.Templates(), "signalith.t.acme"); {
		if time.Now().After(deadline) {
			t.Fatalf("no template for acme: %v\n%s", rs.os.Templates(), rs.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// In acme: a user and an agent token of acme's.
	must("POST", "/api/tenants/switch", `{"tenant":"acme"}`, 200)
	must("POST", "/api/users", `{"username":"ada","role":"admin","password":"Long-pass-for-acme-9","must_change_password":false}`, http.StatusCreated)
	acmeToken, _ := must("POST", "/api/agent-tokens", `{"name":"acme agents"}`, http.StatusCreated)["secret"].(string)
	if acmeToken == "" {
		t.Fatal("no token")
	}
	// Changes made in acme are audited as acme's.
	audited := false
	for _, line := range strings.Split(rs.logs.String(), "\n") {
		if strings.Contains(line, `msg="user created"`) && strings.Contains(line, "user=ada") {
			audited = strings.Count(line, "tenant=acme") == 1 && strings.Contains(line, "audit=true")
		}
	}
	if !audited {
		t.Errorf("creating ada is not audited once as acme's:\n%s", rs.logs.String())
	}
	users := must("GET", "/api/users", "", 200)["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["username"] != "ada" {
		t.Errorf("acme's users: %v", users)
	}
	must("POST", "/api/tenants/switch", `{"tenant":"default"}`, 200)
	for _, u := range must("GET", "/api/users", "", 200)["users"].([]any) {
		if u.(map[string]any)["username"] == "ada" {
			t.Error("acme's user is listed in the default tenant")
		}
	}

	ingest := func(token, line string) int {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+rs.addr+"/api/ingest", strings.NewReader(`[{"log":"`+line+`"}]`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		code := ingest(acmeToken, "acme-event")
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("acme's agent: %d\n%s", code, rs.logs.String())
		}
	}
	if code := ingest("tok-0123456789abcdef", "default-event"); code != 200 {
		t.Fatalf("default tenant's agent: %d", code)
	}
	if code := ingest("sgl_not-a-token-of-anyone", "x"); code == 200 {
		t.Error("an unknown token was accepted")
	}
	var acmeIdx, defIdx []string
	for _, ix := range rs.os.Indices() {
		switch {
		case strings.HasPrefix(ix, "signalith.t.acme-") || strings.HasPrefix(ix, "signalith.t.acme_"):
			acmeIdx = append(acmeIdx, ix)
		case strings.HasPrefix(ix, "signalith-") || strings.HasPrefix(ix, "signalith_"):
			defIdx = append(defIdx, ix)
		case strings.HasPrefix(ix, "signalith.t."):
			t.Errorf("index %s of no tenant", ix)
		}
	}
	has := func(indices []string, text string) bool {
		for _, ix := range indices {
			resp, err := http.Post(rs.os.URL+"/"+ix+"/_search", "application/json", strings.NewReader(`{"query":{"match_all":{}},"size":100}`))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), text) {
				return true
			}
		}
		return false
	}
	if !has(acmeIdx, "acme-event") || has(defIdx, "acme-event") {
		t.Errorf("acme's event is not only in acme's indices: %v / %v", acmeIdx, defIdx)
	}
	if !has(defIdx, "default-event") || has(acmeIdx, "default-event") {
		t.Errorf("the default tenant's event is not only in its indices: %v / %v", acmeIdx, defIdx)
	}

	// Acme's admin, signed in, works in acme only, and cannot reach the
	// server's own pages.
	ada := &running{t: t, r: rs.r, addr: rs.addr, os: rs.os, scheme: "http", client: rs.client}
	resp, err := rs.client.Post("http://"+rs.addr+"/api/login", "application/json", strings.NewReader(`{"username":"ada","password":"Long-pass-for-acme-9"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "signalith_session") {
			ada.cookie = c.Name + "=" + c.Value
		}
	}
	if resp.StatusCode != 200 || ada.cookie == "" {
		t.Fatalf("ada's sign-in: %d", resp.StatusCode)
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/findings", 200},
		{"GET", "/api/agent-tokens", 200},
		{"GET", "/api/settings", http.StatusForbidden},
		{"GET", "/api/audit", http.StatusForbidden},
		{"POST", "/api/tenants/switch", http.StatusForbidden},
		{"PUT", "/api/notify", http.StatusForbidden},
	} {
		if code, out, err := ada.call("", c.method, c.path, `{"tenant":"default"}`); err != nil || code != c.want {
			t.Errorf("ada %s %s: %d %v %v, want %d", c.method, c.path, code, out, err, c.want)
		}
	}
	code, out, _ := ada.call("", "GET", "/api/agent-tokens", "")
	if code != 200 || !strings.Contains(fmt.Sprint(out), "acme agents") {
		t.Errorf("acme's tokens: %d %v", code, out)
	}

	// Turned off: its agents and users are refused at once.
	must("PATCH", "/api/tenants/acme", `{"disabled":true}`, 200)
	if code := ingest(acmeToken, "late"); code == 200 {
		t.Error("an agent of a tenant turned off was accepted")
	}
	if code, _, _ := ada.call("", "GET", "/api/findings", ""); code == 200 {
		t.Error("a user of a tenant turned off was let in")
	}
}
