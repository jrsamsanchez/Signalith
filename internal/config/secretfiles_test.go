// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSecretFiles checks the _FILE form of each secret variable, which
// is how the Docker quick start passes secrets.
func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	put := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("auth:\n  ldap:\n    url: ldaps://dc1.example.com\n    user_base_dn: dc=example,dc=com\n    bind_dn: cn=svc,dc=example,dc=com\n    admin_groups: [cn=admins,dc=example,dc=com]\n"+
		"assistant:\n  provider: anthropic\nopensearch:\n  url: https://os.example.com:9200\n  username: signalith\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", put("admin", "file password\n"))
	t.Setenv("SIGNALITH_INGEST_TOKEN_FILE", put("token", "token-from-a-file-0123456789\r\n"))
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD_FILE", put("os", "os pass\n"))
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY_FILE", put("key", "sk-ant-from-file"))
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD_FILE", put("bind", "bind pass\n\n"))
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("admin", "file password") {
		t.Error("admin password from the file not used")
	}
	if !slices.Equal(c.Ingest.Tokens, []string{"token-from-a-file-0123456789"}) {
		t.Errorf("tokens %q", c.Ingest.Tokens)
	}
	if c.OpenSearch.Password != "os pass" || c.Assistant.APIKey != "sk-ant-from-file" {
		t.Errorf("opensearch password %q, api key %q", c.OpenSearch.Password, c.Assistant.APIKey)
	}
	// Only one newline is taken off.
	if s, err := c.LDAP(); err != nil || s.BindPassword != "bind pass\n" {
		t.Errorf("bind password %q %v", s.BindPassword, err)
	}

	// Both forms of the ingest token add a token each, the file's first:
	// it is the one new agents get, and the variable keeps an older one.
	t.Setenv("SIGNALITH_INGEST_TOKEN", "token-from-the-environment")
	if c, err := Load(path); err != nil || !slices.Equal(c.Ingest.Tokens, []string{"token-from-a-file-0123456789", "token-from-the-environment"}) {
		t.Errorf("tokens %q %v", c.Ingest.Tokens, err)
	}
	// For the others, setting both is a mistake.
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "env password")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_ADMIN_PASSWORD and SIGNALITH_ADMIN_PASSWORD_FILE are both set") {
		t.Errorf("both set: %v", err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "")

	missing := filepath.Join(dir, "no-such-file")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD_FILE", missing)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_OPENSEARCH_PASSWORD_FILE is set to "+missing+", which cannot be read") {
		t.Errorf("missing file: %v", err)
	}
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD_FILE", put("empty", "\n"))
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "which is empty") {
		t.Errorf("empty file: %v", err)
	}
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD_FILE", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", put("short", "short\n"))
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_ADMIN_PASSWORD") {
		t.Errorf("short password: %v", err)
	}
}

// TestAdminHashFile checks that a password changed with signalith passwd
// where the config file cannot hold it replaces the one from the
// environment, which then stops working.
func TestAdminHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("lookups:\n  dir: data/lookups\n"), 0o600)
	initial := filepath.Join(dir, "initial-admin-password")
	os.WriteFile(initial, []byte("generated-first-password\n"), 0o400)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", initial)
	t.Setenv("SIGNALITH_STATE_DIR", "")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "data")
	if c.StateDir() != state || StateDirFor(path) != state || c.AdminHashFile() != filepath.Join(state, "admin-password-hash") {
		t.Errorf("state dir %s / %s, hash file %s", c.StateDir(), StateDirFor(path), c.AdminHashFile())
	}
	if !c.CheckPassword("admin", "generated-first-password") || c.AdminPasswordChanged() != "" {
		t.Error("initial password not in use")
	}
	h, _ := HashPassword("the admin's own password")
	os.MkdirAll(state, 0o700)
	os.WriteFile(c.AdminHashFile(), []byte(h+"\n"), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckPassword("admin", "generated-first-password") || !c.CheckPassword("admin", "the admin's own password") {
		t.Error("the changed password does not replace the initial one")
	}
	if c.AdminPasswordChanged() != c.AdminHashFile() {
		t.Errorf("changed = %q", c.AdminPasswordChanged())
	}
	os.WriteFile(c.AdminHashFile(), []byte("not a hash"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "does not hold a password hash") {
		t.Errorf("bad hash file: %v", err)
	}
	// SIGNALITH_LOOKUPS_DIR and SIGNALITH_STATE_DIR move the state folder.
	t.Setenv("SIGNALITH_LOOKUPS_DIR", filepath.Join(dir, "elsewhere", "lookups"))
	if got := StateDirFor(path); got != filepath.Join(dir, "elsewhere") {
		t.Errorf("StateDirFor with SIGNALITH_LOOKUPS_DIR = %s", got)
	}
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	if got := StateDirFor(path); got != filepath.Join(dir, "state") {
		t.Errorf("StateDirFor with SIGNALITH_STATE_DIR = %s", got)
	}
}

// TestPublicExampleSecretsWarn checks the warnings for the admin password
// and ingest token from older docker-compose.yml files.
func TestPublicExampleSecretsWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("ingest:\n  tokens: [a-token-of-my-own-0123]\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "change-me-please")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "change-this-ingest-token")
	t.Setenv("SIGNALITH_STATE_DIR", dir)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "password is change-me-please") || !strings.Contains(w, "includes change-this-ingest-token") || strings.Contains(w, "a-token-of-my-own") {
		t.Errorf("warnings:\n%s", w)
	}
	// Once the password was changed, the example one no longer works.
	h, _ := HashPassword("a better password")
	os.WriteFile(filepath.Join(dir, "admin-password-hash"), []byte(h), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(c.Warnings(), "\n"); strings.Contains(w, "change-me-please") {
		t.Errorf("warnings after the change:\n%s", w)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "something-else")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "")
	os.Remove(filepath.Join(dir, "admin-password-hash"))
	// The token written into the file in plain text is warned about for
	// that alone.
	if c, err := Load(path); err != nil || len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "stored as plain text (ingest.tokens[0])") {
		t.Errorf("warnings %v %v", c.Warnings(), err)
	}
}

// TestPublicURLFromEnvironmentUpgrades checks that an http:// address in
// SIGNALITH_PUBLIC_URL, as older Docker examples showed, means the same
// address over HTTPS.
func TestPublicURLFromEnvironmentUpgrades(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "http://192.168.1.20:8080")
	c, err := loadYAML(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: https://localhost:8080\n  tls:\n    mode: auto\n    plaintext_ingest: deny\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "https://192.168.1.20:8080" {
		t.Errorf("public url %s", c.Server.PublicURL)
	}
	// It still works, and the warning says where to change it.
	if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "Change SIGNALITH_PUBLIC_URL to https://192.168.1.20:8080") {
		t.Errorf("warnings:\n%s", w)
	}
}
