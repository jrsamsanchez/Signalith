package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// A tenant added on a running server gets data of its own: its agents'
// events go to its indices only, its users see only its data, and the
// default tenant's agents and users never reach it.
func TestTenantsDataStaysApart(t *testing.T) {
	// Without the background jobs this server never founds a cluster:
	// a server that keeps its users in its own files.
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
	signIn := func(name, password string) *running {
		t.Helper()
		who := &running{t: t, r: rs.r, addr: rs.addr, os: rs.os, scheme: "http", client: rs.client}
		resp, err := rs.client.Post("http://"+rs.addr+"/api/login", "application/json", strings.NewReader(`{"username":"`+name+`","password":"`+password+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		for _, c := range resp.Cookies() {
			if strings.HasSuffix(c.Name, "signalith_session") {
				who.cookie = c.Name + "=" + c.Value
			}
		}
		if resp.StatusCode != 200 || who.cookie == "" {
			t.Fatalf("%s's sign-in: %d", name, resp.StatusCode)
		}
		return who
	}
	ada := signIn("ada", "Long-pass-for-acme-9")
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
	// Hunting notebooks are acme's own; custom parsers are the provider's.
	if code, out, err := ada.call("", "POST", "/api/notebooks", `{"title":"Acme hunt","sharing":"read"}`); err != nil || code != http.StatusCreated {
		t.Fatalf("ada's notebook: %d %v %v", code, out, err)
	}
	if code, out, _ := ada.call("", "GET", "/api/notebooks", ""); code != 200 || !strings.Contains(fmt.Sprint(out["notebooks"]), "Acme hunt") {
		t.Errorf("acme's notebooks: %d %v", code, out)
	}
	if out := must("GET", "/api/notebooks", "", 200); strings.Contains(fmt.Sprint(out["notebooks"]), "Acme hunt") {
		t.Errorf("acme's notebook is listed in the default tenant: %v", out)
	}
	if code, _, _ := ada.call("", "GET", "/api/parsers", ""); code != http.StatusForbidden {
		t.Errorf("ada GET /api/parsers: %d, want 403", code)
	}

	// Settings applied at once on the Settings page apply to every
	// tenant, as do those of a tenant added after.
	aiOn := func(who *running) any {
		t.Helper()
		code, out, err := who.call("", "GET", "/api/ask", "")
		if err != nil || code != 200 {
			t.Fatalf("ask: %d %v %v", code, out, err)
		}
		return out["ai_available"]
	}
	if aiOn(ada) != false {
		t.Fatal("acme has an AI model before one was set")
	}
	must("PUT", "/api/settings", `{"values":{"assistant.provider":"openai","assistant.url":"http://127.0.0.1:11434/v1","assistant.model":"llama3"}}`, 200)
	if aiOn(ada) != true {
		t.Error("acme does not use the AI model set on the Settings page")
	}
	must("POST", "/api/tenants", `{"id":"contoso","name":"Contoso"}`, http.StatusCreated)
	must("POST", "/api/tenants/switch", `{"tenant":"contoso"}`, 200)
	if aiOn(rs) != true {
		t.Error("a tenant added after the change does not use the AI model")
	}
	must("PUT", "/api/settings", `{"reset":["assistant.provider"]}`, 200)
	if aiOn(ada) != false || aiOn(rs) != false {
		t.Error("the AI model turned off on the Settings page is still in use in a tenant")
	}
	must("POST", "/api/tenants/switch", `{"tenant":"default"}`, 200)

	// A provider user's notebooks in a tenant are released with their
	// account, so a later account of the same name does not get them.
	must("POST", "/api/users", `{"username":"pat","role":"analyst","password":"Quiet-river-stone-77","must_change_password":false}`, http.StatusCreated)
	pat := signIn("pat", "Quiet-river-stone-77")
	if code, out, err := pat.call("", "POST", "/api/tenants/switch", `{"tenant":"acme"}`); err != nil || code != 200 {
		t.Fatalf("pat's switch: %d %v %v", code, out, err)
	}
	if code, out, err := pat.call("", "POST", "/api/notebooks", `{"title":"Pat's hunt"}`); err != nil || code != http.StatusCreated {
		t.Fatalf("pat's notebook: %d %v %v", code, out, err)
	}
	must("DELETE", "/api/users/pat", "", 200)
	must("POST", "/api/users", `{"username":"pat","role":"analyst","password":"Quiet-river-stone-88","must_change_password":false}`, http.StatusCreated)
	pat = signIn("pat", "Quiet-river-stone-88")
	if code, out, err := pat.call("", "POST", "/api/tenants/switch", `{"tenant":"acme"}`); err != nil || code != 200 {
		t.Fatalf("new pat's switch: %d %v %v", code, out, err)
	}
	if code, out, _ := pat.call("", "GET", "/api/notebooks", ""); code != 200 || strings.Contains(fmt.Sprint(out["notebooks"]), "Pat's hunt") {
		t.Errorf("the new pat sees the deleted pat's private notebook in acme: %d %v", code, out)
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

// In a cluster at the tenants' level, tenants run on the server that runs
// the background jobs. Another server refuses tenants' users, provider
// users switching and tenants' agents; so does the first once it gave the
// jobs up, rather than serve data it no longer keeps up to date.
func TestTenantsInACluster(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a"})
	a.usersShared()
	giveKey(t, a)
	b := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b"})
	b.usersShared()
	must := func(rs *running, method, path, body string, want int) map[string]any {
		t.Helper()
		code, out, err := rs.call("", method, path, body)
		if err != nil || code != want {
			t.Fatalf("%s %s %s: %d %v %v, want %d", rs.r.node.Name(), method, path, code, out, err, want)
		}
		return out
	}
	eventually(t, "the cluster keeps tenants", func() bool { return a.r.shared.Tenants() && b.r.shared.Tenants() })
	must(a, "POST", "/api/tenants", `{"id":"acme","name":"Acme"}`, http.StatusCreated)
	must(a, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, 200)
	must(a, "POST", "/api/users", `{"username":"ada","role":"analyst","password":"Long-pass-for-acme-9","must_change_password":false}`, http.StatusCreated)
	token, _ := must(a, "POST", "/api/agent-tokens", `{"name":"acme agents"}`, http.StatusCreated)["secret"].(string)
	ingest := func(rs *running) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+rs.addr+"/api/ingest", strings.NewReader(`[{"log":"acme"}]`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	accepted := func(rs *running) bool { code, _ := ingest(rs); return code == 200 }
	// B, which runs no tenant now, tells acme's agents to send again
	// later, so no batch is lost.
	toldToWait := func(rs *running) bool {
		code, retry := ingest(rs)
		return code == http.StatusServiceUnavailable && retry != ""
	}
	eventually(t, "acme's agent is accepted on A", func() bool { return accepted(a) })
	eventually(t, "B knows acme", func() bool {
		tn, err := b.r.srv.Load().Tenants.Get("acme")
		return err == nil && !tn.Disabled
	})
	eventually(t, "B tells acme's agent to wait", func() bool { return toldToWait(b) })
	// The session's tenant is shared: B, which runs no tenant, refuses.
	b.cookie = a.cookie
	if code, out, _ := b.call("", "GET", "/api/findings", ""); code != http.StatusServiceUnavailable || out["code"] != "tenant_unavailable" {
		t.Errorf("B on acme's findings: %d %v", code, out)
	}
	saved := b.cookie
	// Once B has read ada, she signs in there too, and is told acme's
	// data is not run there now.
	eventually(t, "B read acme's user", func() bool {
		if err := b.r.shared.Hub().Cycle(context.Background()); err != nil {
			return false
		}
		_, ok := b.r.srv.Load().Users.Get("ada")
		return ok
	})
	if code := b.signInAs("ada", "Long-pass-for-acme-9"); code != 200 {
		t.Errorf("acme's user signing in on B: %d", code)
	}
	if code, out, _ := b.call("", "GET", "/api/findings", ""); code != http.StatusServiceUnavailable || out["code"] != "tenant_unavailable" {
		t.Errorf("ada on B: %d %v", code, out)
	}
	b.cookie = saved
	// Turned off on A, acme is off on B as well.
	off := func(disabled bool) {
		t.Helper()
		must(a, "PATCH", "/api/tenants/acme", fmt.Sprintf(`{"disabled":%v}`, disabled), 200)
		eventually(t, "B knows whether acme is off", func() bool {
			tn, err := b.r.srv.Load().Tenants.Get("acme")
			return err == nil && tn.Disabled == disabled
		})
	}
	must(a, "POST", "/api/tenants/switch", `{"tenant":"default"}`, 200)
	off(true)
	if code, _ := ingest(b); code == 200 || code == http.StatusServiceUnavailable {
		t.Errorf("B: acme's agent after acme was turned off: %d", code)
	}
	if code := b.signInAs("ada", "Long-pass-for-acme-9"); code != http.StatusForbidden {
		t.Errorf("B: acme's user after acme was turned off: %d", code)
	}
	b.cookie = saved
	off(false)
	must(a, "POST", "/api/tenants/switch", `{"tenant":"acme"}`, 200)
	// A gives the jobs up: it refuses acme's requests, and tells its
	// agents to wait.
	a.r.node.Drain("test")
	eventually(t, "A gave the jobs up", func() bool { return !a.r.node.RunsJobs() })
	if code, out, _ := a.call("", "GET", "/api/findings", ""); code != http.StatusServiceUnavailable || out["code"] != "tenant_unavailable" {
		t.Errorf("A on acme's findings without the jobs: %d %v", code, out)
	}
	eventually(t, "A tells acme's agent to wait", func() bool { return toldToWait(a) })
	// A stops: B takes the jobs over, and acme's data with them.
	a.stop()
	eventually(t, "B takes the jobs over", b.r.node.RunsJobs)
	eventually(t, "B accepts acme's agent", func() bool { return accepted(b) })
}
