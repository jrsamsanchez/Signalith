// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// Scan logins are saved encrypted, never sent back or logged, and a
// network can only name one of the right kind.
func TestVulnLogins(t *testing.T) {
	docs := endpoint.NewMemoryDocs()
	st := vulnscan.NewStore(docs, "signalith")
	key, err := secrets.NewKey(bytes.Repeat([]byte{7}, 32), "cluster key")
	if err != nil {
		t.Fatal(err)
	}
	st.Keys = key
	var logs bytes.Buffer
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
		s.Vulns = &Vulns{Store: st}
	})
	const pass = "Very-secret-Win-1"
	code, out, _ := call(t, ts, "PUT", "/api/vulns/logins/win", `{"name":"Windows","kind":"smb","username":"CORP\\scan","secret":"`+pass+`"}`, "admin", "s3cret-pass", nil)
	if code != 200 || out["readable"] != true || out["username"] != `CORP\scan` {
		t.Fatalf("save %d %v", code, out)
	}
	if code, out, _ = call(t, ts, "PUT", "/api/vulns/logins/bad", `{"name":"Bad","kind":"ssh","username":"u","auth":"key","secret":"nope"}`, "admin", "s3cret-pass", nil); code != 400 {
		t.Fatalf("a bad key: %d %v", code, out)
	}
	code, out, raw := call(t, ts, "GET", "/api/vulns/logins", "", "admin", "s3cret-pass", nil)
	if code != 200 || strings.Contains(raw, pass) || strings.Contains(raw, "enc:") || out["can_save"] != true {
		t.Fatalf("list %d %s", code, raw)
	}
	stored, _, _, _ := docs.Get(t.Context(), st.Index, "credentials")
	if bytes.Contains(stored, []byte(pass)) {
		t.Fatal("the password is stored in the clear")
	}
	if strings.Contains(logs.String(), pass) || !strings.Contains(logs.String(), "vulnerability scan login saved") {
		t.Fatalf("logs:\n%s", logs.String())
	}

	// A network names it, and then it cannot be removed.
	_, out, _ = call(t, ts, "GET", "/api/vulns", "", "admin", "s3cret-pass", nil)
	net := func(field, id string) string {
		b, _ := json.Marshal(map[string]any{"version": out["version"], "settings": map[string]any{"targets": []any{map[string]any{
			"id": "office", "name": "Office", "networks": []string{"10.0.0.0/24"}, "ports": "top100", "enabled": true,
			"schedule": map[string]any{"every": "manual"}, "openvas": true, field: id}}}})
		return string(b)
	}
	if code, o, _ := call(t, ts, "PUT", "/api/vulns/settings", net("ssh_login", "win"), "admin", "s3cret-pass", nil); code != 400 {
		t.Fatalf("a Windows login as SSH: %d %v", code, o)
	}
	if code, o, _ := call(t, ts, "PUT", "/api/vulns/settings", net("smb_login", "win"), "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("save network %d %v", code, o)
	}
	// The audit log says which addresses get which login.
	if !strings.Contains(logs.String(), "Office added: scans 10.0.0.0/24, skips none, scanner none, SSH login none, Windows login win") {
		t.Errorf("settings audit:\n%s", logs.String())
	}
	_, out, _ = call(t, ts, "GET", "/api/vulns/logins", "", "admin", "s3cret-pass", nil)
	if used := out["logins"].([]any)[0].(map[string]any)["used_by"].([]any); len(used) != 1 || used[0] != "Office" {
		t.Fatalf("used by %v", used)
	}
	if code, o, _ := call(t, ts, "DELETE", "/api/vulns/logins/win", "", "admin", "s3cret-pass", nil); code != 409 {
		t.Fatalf("removed a login in use: %d %v", code, o)
	}
	if code, o, _ := call(t, ts, "DELETE", "/api/vulns/logins/nope", "", "admin", "s3cret-pass", nil); code != 404 {
		t.Fatalf("removed a missing login: %d %v", code, o)
	}

	// SNMPv3: both passwords stay out of the answer, the list and the
	// logs; the audit record says the privacy password changed.
	const auth, priv = "Snmp-auth-pass-1", "Snmp-priv-pass-1"
	code, out, raw = call(t, ts, "PUT", "/api/vulns/logins/sw", `{"name":"Switches","kind":"snmp","username":"scan","auth":"v3","secret":"`+auth+`","privacy":"`+priv+`"}`, "admin", "s3cret-pass", nil)
	if code != 200 || out["readable"] != true || strings.Contains(raw, auth) || strings.Contains(raw, priv) || strings.Contains(raw, "enc:") {
		t.Fatalf("save SNMP %d %s", code, raw)
	}
	if _, _, raw = call(t, ts, "GET", "/api/vulns/logins", "", "admin", "s3cret-pass", nil); strings.Contains(raw, priv) || strings.Contains(raw, "enc:") {
		t.Fatalf("list %s", raw)
	}
	if strings.Contains(logs.String(), priv) || !strings.Contains(logs.String(), "privacy_changed=true") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	_, out, _ = call(t, ts, "GET", "/api/vulns", "", "admin", "s3cret-pass", nil)
	if code, o, _ := call(t, ts, "PUT", "/api/vulns/settings", net("esxi_login", "sw"), "admin", "s3cret-pass", nil); code != 400 {
		t.Fatalf("an SNMP login as ESXi: %d %v", code, o)
	}
}

// With no encryption key, nothing is saved.
func TestVulnLoginsNoKey(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Vulns = &Vulns{Store: vulnscan.NewStore(endpoint.NewMemoryDocs(), "signalith")}
	})
	if code, out, _ := call(t, ts, "PUT", "/api/vulns/logins/a", `{"name":"A","kind":"smb","username":"u","secret":"p"}`, "admin", "s3cret-pass", nil); code != 503 {
		t.Fatalf("saved with no key: %d %v", code, out)
	}
}

func TestVulnChanges(t *testing.T) {
	a := vulnscan.Target{ID: "o", Name: "Office", Networks: []string{"10.0.0.0/24"}, OpenVAS: true, SMBLogin: "win"}
	b := a
	b.Networks, b.SMBLogin, b.SSHLogin = []string{"0.0.0.0/0"}, "", "lin"
	got := strings.Join(vulnChanges(vulnscan.Settings{Targets: []vulnscan.Target{a, {ID: "x", Name: "Lab"}}}, vulnscan.Settings{Targets: []vulnscan.Target{b}}), "; ")
	want := "Office: addresses 10.0.0.0/24 -> 0.0.0.0/0; Office: SSH login none -> lin; Office: Windows login win -> none; Lab removed"
	if got != want {
		t.Errorf("changes = %s\nwant %s", got, want)
	}
}
