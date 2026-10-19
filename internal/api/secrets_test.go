// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// TestHealthWarnsAboutSecrets checks the admin health reply: plain text
// passwords in signalith.yaml, a master key from SIGNALITH_MASTER_KEY,
// and a directory password that cannot be decrypted are all reported.
func TestHealthWarnsAboutSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	h, _ := config.HashPassword("s3cret-pass")
	if err := os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\nopensearch:\n  password: plain-os-pw\ningest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// directory.json written with another master key.
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal(users.BindPasswordField, "bind-pw")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_MASTER_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dirFile := filepath.Join(dir, "directory.json")
	os.WriteFile(dirFile, []byte(`{"version":1,"settings":{"type":"ad","url":"ldaps://dc1.example.com","bind_dn":"CN=svc,DC=example,DC=com","user_base_dn":"DC=example,DC=com","admin_groups":["CN=A,DC=example,DC=com"]},"bind_password":"`+sealed+`"}`), 0o600)
	d, err := users.OpenDirectory(dirFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	ts, _ := newTestServerWith(t, func(s *Server) { s.Config, s.Directory = cfg, d })
	_, body := do(t, ts, "GET", "/api/health", "", true)
	w := fmt.Sprint(body["warnings"])
	for _, want := range []string{
		"2 passwords or keys in signalith.yaml are stored as plain text (opensearch.password, ingest.tokens[0]). Run: signalith secrets encrypt",
		"SIGNALITH_MASTER_KEY",
		"Directory sign-in cannot search for users until the service account password is entered again",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "plain-os-pw") || strings.Contains(w, "bind-pw") {
		t.Errorf("warnings show a secret: %s", w)
	}
	_, view := do(t, ts, "GET", "/api/auth/directory", "", true)
	if !strings.Contains(fmt.Sprint(view["warnings"]), "Directory sign-in cannot search for users") {
		t.Errorf("directory view warnings: %v", view["warnings"])
	}
}

// A password saved on the Settings page that cannot be decrypted (the
// master key it was saved with is gone) is reported on Health and next
// to the setting, without the value, and Signalith runs without it.
func TestUnreadablePageSecretIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	h, _ := config.HashPassword("s3cret-pass")
	if err := os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\nopensearch:\n  url: https://os.example:9200\ningest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("settings.opensearch.password", "lost-page-pw")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(file), 0o750)
	if err := os.WriteFile(file, []byte("settings:\n  opensearch.password:\n    secret: "+sealed+"\n    sent_to: https://os.example:9200\n    changed_by: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OpenSearch.Password != "" {
		t.Fatalf("password %q", cfg.OpenSearch.Password)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Config = cfg })
	_, body := do(t, ts, "GET", "/api/health", "", true)
	w := fmt.Sprint(body["warnings"])
	if !strings.Contains(w, "On the Settings page ("+file+"), opensearch.password is encrypted with master key "+other.KeyID()) ||
		!strings.Contains(w, "Enter it again on the Settings page") || strings.Contains(w, "lost-page-pw") {
		t.Errorf("health warnings:\n%s", w)
	}
	_, view := do(t, ts, "GET", "/api/settings", "", true)
	f := field(t, view, "opensearch.password")
	if msg, _ := f["warning"].(string); !strings.Contains(msg, "master key "+other.KeyID()) || !strings.Contains(msg, "enter it again") {
		t.Errorf("field %v", f)
	}
	if strings.Contains(fmt.Sprint(view), "lost-page-pw") || strings.Contains(fmt.Sprint(view), sealed) {
		t.Error("the settings view shows the stored value")
	}
}

// A key saved on the Settings page that cannot be decrypted and is then
// entered again on the page goes into use at once, and Health stops
// saying it cannot be decrypted.
func TestReenteredPageSecretIsNoLongerReported(t *testing.T) {
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("settings.assistant.api_key", "lost-key")
	if err != nil {
		t.Fatal(err)
	}
	ts, srv, _ := newSettingsServer(t, "assistant:\n  provider: openai\n  url: http://127.0.0.1:11434/v1\n  model: llama3.1\n", func(s *Server) {
		file := s.Config.SettingsFile()
		os.MkdirAll(filepath.Dir(file), 0o750)
		if err := os.WriteFile(file, []byte("settings:\n  assistant.api_key:\n    secret: "+sealed+"\n    sent_to: http://127.0.0.1:11434\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(s.Config.Path())
		if err != nil || cfg.PageSecretProblem("assistant.api_key") == "" {
			t.Fatalf("load: %v", err)
		}
		s.Config = cfg
	})
	before := srv.conf()
	_, body := do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(body["warnings"]); !strings.Contains(w, "assistant.api_key is encrypted with master key "+other.KeyID()) {
		t.Fatalf("health before:\n%s", w)
	}
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"assistant.api_key":"sk-new-key"}}`, "admin", "s3cret-pass", nil)
	if code != 200 || !strings.Contains(fmt.Sprint(out["applied"]), "assistant.api_key") {
		t.Fatalf("save %d %v", code, out)
	}
	if got := srv.conf().Assistant.APIKey; got != "sk-new-key" {
		t.Errorf("key in use %q", got)
	}
	_, body = do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(body["warnings"]); strings.Contains(w, "assistant.api_key") {
		t.Errorf("health after entering it again:\n%s", w)
	}
	if srv.conf().PageSecretProblem("assistant.api_key") != "" || len(srv.conf().PageUnreadable()) != 0 {
		t.Errorf("still reported: %v", srv.conf().PageUnreadable())
	}
	// The config it replaced is left as it was.
	if before.PageSecretProblem("assistant.api_key") == "" || len(before.PageUnreadable()) != 1 {
		t.Errorf("the previous config changed: %v", before.PageUnreadable())
	}
}
