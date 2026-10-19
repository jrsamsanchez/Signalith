// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSignalith answers /api/me for the token it is given, over HTTPS, and
// returns its address and a file with its certificate.
func fakeSignalith(t *testing.T, token string) (string, string, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":"sign in"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/me" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"username": "mcp-bot", "role": "viewer", "source": "token", "secret": "not shown"})
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, ca, &seen
}

func clearMCPEnv(t *testing.T) {
	for _, k := range []string{"SIGNALITH_URL", "SIGNALITH_USER", "SIGNALITH_PASSWORD", "SIGNALITH_PASSWORD_FILE", "SIGNALITH_TOKEN", "SIGNALITH_TOKEN_FILE", "SIGNALITH_CA_FILE"} {
		t.Setenv(k, "")
	}
}

func TestMCPCommandCheck(t *testing.T) {
	clearMCPEnv(t)
	const token = "sgl_api_made-up-test-token"
	url, ca, _ := fakeSignalith(t, token)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return cmdMCP([]string{"-url", url, "-token-file", tokenFile, "-ca", ca, "-check"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Signalith answered; the MCP server will read as:") || !strings.Contains(out, `"username": "mcp-bot"`) ||
		!strings.Contains(out, `"role": "viewer"`) || strings.Contains(out, "not shown") {
		t.Errorf("check:\n%s", out)
	}

	// A token the server does not take fails the check.
	t.Setenv("SIGNALITH_TOKEN", "sgl_api_another-made-up-token")
	if _, err := capture(t, func() error { return cmdMCP([]string{"-url", url, "-ca", ca, "-check"}) }); err == nil {
		t.Error("a refused token passed the check")
	}
}

func TestMCPCommandFiles(t *testing.T) {
	clearMCPEnv(t)
	dir := t.TempDir()
	if err := cmdMCP([]string{"-url", "https://siem.example.test", "-user", "u", "-password-file", filepath.Join(dir, "missing")}); err == nil ||
		!strings.Contains(err.Error(), "reading the password file") {
		t.Errorf("missing password file: %v", err)
	}
	if err := cmdMCP([]string{"-url", "https://siem.example.test", "-token-file", filepath.Join(dir, "missing")}); err == nil ||
		!strings.Contains(err.Error(), "reading the token file") {
		t.Errorf("missing token file: %v", err)
	}
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("made-up-pass\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdMCP([]string{"-url", "https://siem.example.test", "-user", "u", "-password-file", pass, "-ca", filepath.Join(dir, "missing")}); err == nil ||
		!strings.Contains(err.Error(), "reading the CA file") {
		t.Errorf("missing CA file: %v", err)
	}
	notPEM := filepath.Join(dir, "ca.txt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdMCP([]string{"-url", "https://siem.example.test", "-user", "u", "-password-file", pass, "-ca", notPEM}); err == nil ||
		!strings.Contains(err.Error(), "holds no PEM certificate") {
		t.Errorf("CA file without a certificate: %v", err)
	}
	if err := cmdMCP(nil); err == nil || !strings.Contains(err.Error(), "-url") {
		t.Errorf("no address: %v", err)
	}
}

// Without -check the command speaks MCP on standard input and output until
// standard input ends.
func TestMCPCommandServes(t *testing.T) {
	clearMCPEnv(t)
	const token = "sgl_api_made-up-test-token"
	url, ca, _ := fakeSignalith(t, token)
	t.Setenv("SIGNALITH_TOKEN", token)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin; r.Close() })
	go func() {
		w.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n")
		w.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
		w.Close()
	}()
	out, err := capture(t, func() error { return cmdMCP([]string{"-url", url, "-ca", ca}) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("answers:\n%s", out)
	}
	var init struct {
		ID     int `json:"id"`
		Result struct {
			ServerInfo struct{ Name string } `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &init); err != nil || init.ID != 1 || init.Result.ServerInfo.Name == "" {
		t.Errorf("initialize: %v %s", err, lines[0])
	}
	if !strings.Contains(lines[1], `"whoami"`) {
		t.Errorf("tools/list: %s", lines[1])
	}
}
