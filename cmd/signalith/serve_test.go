package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// serveEnv clears the settings a test's environment could give serve.
func serveEnv(t *testing.T) {
	t.Helper()
	noServiceSettings(t)
	for _, name := range []string{"SIGNALITH_LISTEN", "SIGNALITH_PUBLIC_URL", "SIGNALITH_OPENSEARCH_URL", "SIGNALITH_OPENSEARCH_USERNAME",
		"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_SETTINGS_FILE", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_ASSISTANT_API_KEY",
		"SIGNALITH_SYSLOG_UDP", "SIGNALITH_SYSLOG_TCP", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_USERS_FILE", "SIGNALITH_ARCHIVE_DIR",
		"SIGNALITH_STATE_DIR", "SIGNALITH_NODE_URL", "SIGNALITH_JOIN", "SIGNALITH_JOIN_FILE", "SIGNALITH_MASTER_KEY", "SIGNALITH_MASTER_KEY_FILE",
		"SIGNALITH_DETECTIONS_DIR", "SIGNALITH_DASHBOARDS_DIR"} {
		t.Setenv(name, "")
	}
	t.Setenv("SIGNALITH_NODE_NAME", "siem-serve")
}

// serveConfig writes a signalith.yaml for a server on a free local port
// over plain HTTP, using fos.
func serveConfig(t *testing.T, fos *ostest.Server, extra string) (path, addr string) {
	t.Helper()
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	addr = freeAddr(t)
	path = filepath.Join(t.TempDir(), "signalith.yaml")
	body := "server:\n  listen: " + addr + "\n  tls:\n    mode: off\nopensearch:\n  url: " + fos.URL + "\nauth:\n  admin_password_hash: " + h +
		"\ningest:\n  tokens: [tok-0123456789abcdef]\ndetections:\n  scheduler: true\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, addr
}

// runServe runs serve until the test stops it, waits for the web page to
// answer, and returns a function that stops it and returns serve's error.
func runServe(t *testing.T, path, addr string, logs *syncBuffer) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, path, slog.New(slog.NewTextHandler(logs, nil))) }()
	var result error
	stopped := false
	stop := func() error {
		if !stopped {
			stopped = true
			cancel()
			select {
			case result = <-done:
			case <-time.After(30 * time.Second):
				t.Error("serve did not stop")
			}
		}
		return result
	}
	t.Cleanup(func() { stop() })
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("serve ended: %v\n%s", err, logs.String())
		default:
		}
		if resp, err := noFollow.Get("http://" + addr + "/api/me"); err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not start:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return stop
}

func TestServeStartsAndStops(t *testing.T) {
	serveEnv(t)
	fos := newFakeOpenSearch(t)
	path, addr := serveConfig(t, fos, "")
	logs := &syncBuffer{}
	stop := runServe(t, path, addr, logs)

	// The server founds the cluster, and its audit records go to
	// OpenSearch from then on.
	auditIndex := func() bool {
		for _, n := range fos.Indices() {
			if strings.HasPrefix(n, "signalith_audit-") {
				return true
			}
		}
		return false
	}
	// Sign-ins are audited: sign in until the records show up there.
	signIn := func() int {
		resp, err := http.Post("http://"+addr+"/api/login", "application/json", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := signIn(); code != http.StatusOK {
		t.Errorf("sign in: %d", code)
	}
	deadline := time.Now().Add(40 * time.Second)
	for !auditIndex() {
		if time.Now().After(deadline) {
			t.Fatalf("no audit records in OpenSearch: %v\n%s", fos.Indices(), logs.String())
		}
		time.Sleep(200 * time.Millisecond)
		signIn()
	}
	if err := stop(); err != nil {
		t.Fatalf("serve: %v\n%s", err, logs.String())
	}
	// The server made its identity in its state folder, and its templates
	// in OpenSearch.
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"node.id", "signin.key", "audit-spool"} {
		if _, err := os.Stat(filepath.Join(c.StateDir(), f)); err != nil {
			t.Errorf("state folder: %v", err)
		}
	}
	if len(fos.Templates()) == 0 {
		t.Errorf("no index templates: %v", fos.Requests())
	}

	// audit verify reads what the server wrote.
	out, err := capture(t, func() error { return cmdAudit([]string{"verify", "-c", path, "-from", "2020-01-01"}) })
	if err != nil {
		t.Fatalf("audit verify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Checked ") || strings.Contains(out, "Checked 0 ") || !strings.Contains(out, "No audit record was changed or removed.") {
		t.Errorf("audit verify:\n%s", out)
	}
	out, err = capture(t, func() error { return cmdAudit([]string{"verify", "-c", path, "-json", "-server", "siem-serve"}) })
	var rep map[string]any
	if err != nil || json.Unmarshal([]byte(out), &rep) != nil {
		t.Errorf("audit verify -json: %v\n%s", err, out)
	}
}

func TestServeRefusesABadConfig(t *testing.T) {
	serveEnv(t)
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(path, []byte("server: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serve(context.Background(), path, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("serve started with a broken config file")
	}
}

func TestAuditCommandErrors(t *testing.T) {
	serveEnv(t)
	if err := cmdAudit(nil); err == nil || !strings.Contains(err.Error(), "audit verify") {
		t.Errorf("no command: %v", err)
	}
	if err := cmdAudit([]string{"verify", "-from", "yesterday"}); err == nil || !strings.Contains(err.Error(), "-from") {
		t.Errorf("-from yesterday: %v", err)
	}
	if err := cmdAudit([]string{"verify", "-to", "tomorrow"}); err == nil || !strings.Contains(err.Error(), "-to") {
		t.Errorf("-to tomorrow: %v", err)
	}
	if err := cmdAudit([]string{"verify", "-c", filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Error("verify with no config file")
	}
	path := sampleConfig(t, "http://127.0.0.1:1")
	if err := cmdAudit([]string{"verify", "-c", path}); err == nil {
		t.Error("verify with no OpenSearch")
	}
	// A server that never started holds no cluster key: only the links
	// are checked.
	fos := newFakeOpenSearch(t)
	path = sampleConfig(t, fos.URL)
	out, err := capture(t, func() error { return cmdAudit([]string{"verify", "-c", path, "-to", "2099-01-01"}) })
	if err != nil || !strings.Contains(out, "Checked 0 audit records before ") {
		t.Errorf("verify with no records: %v\n%s", err, out)
	}
}
