package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The environment's files and folders and its passwords and tokens
// override signalith.yaml.
func TestEnvironmentOverrides(t *testing.T) {
	path := writeConfig(t, "")
	dir := t.TempDir()
	files := map[string]string{
		"SIGNALITH_USERS_FILE":           filepath.Join(dir, "users.json"),
		"SIGNALITH_DETECTIONS_DIR":       filepath.Join(dir, "detections"),
		"SIGNALITH_LOOKUPS_DIR":          filepath.Join(dir, "lookups"),
		"SIGNALITH_DASHBOARDS_DIR":       filepath.Join(dir, "dashboards"),
		"SIGNALITH_NOTIFY_FILE":          filepath.Join(dir, "notify.yaml"),
		"SIGNALITH_RESPONSE_FILE":        filepath.Join(dir, "response.yaml"),
		"SIGNALITH_PLAYBOOKS_FILE":       filepath.Join(dir, "playbooks.yaml"),
		"SIGNALITH_TICKETING_FILE":       filepath.Join(dir, "ticketing.yaml"),
		"SIGNALITH_RESPONSE_SCRIPTS_DIR": filepath.Join(dir, "scripts"),
		"SIGNALITH_ARCHIVE_DIR":          filepath.Join(dir, "archive"),
	}
	for k, v := range files {
		t.Setenv(k, v)
	}
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789")
	t.Setenv("SIGNALITH_INGEST_TOKEN_FILE", tokenFile)
	t.Setenv("SIGNALITH_OPENVAS_PASSWORD", "test-openvas-password")
	t.Setenv("SIGNALITH_OPENVAS_ADDRESS", "openvas.example.com:9390")
	t.Setenv("SIGNALITH_NVD_API_KEY", "test-nvd-key")
	t.Setenv("SIGNALITH_OKTA_API_TOKEN", "test-okta-token")
	t.Setenv("SIGNALITH_M365_CLIENT_SECRET", "test-m365-secret")
	t.Setenv("SIGNALITH_OIDC_CLIENT_SECRET", " test-oidc-secret ")
	t.Setenv("SIGNALITH_SYSLOG_UDP", "off")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{
		c.Auth.UsersFile: files["SIGNALITH_USERS_FILE"], c.Notify.File: files["SIGNALITH_NOTIFY_FILE"],
		c.Response.File: files["SIGNALITH_RESPONSE_FILE"], c.Playbooks.File: files["SIGNALITH_PLAYBOOKS_FILE"],
		c.Ticketing.File: files["SIGNALITH_TICKETING_FILE"], c.Response.ScriptsDir: files["SIGNALITH_RESPONSE_SCRIPTS_DIR"],
		c.Retention.ArchiveDir: files["SIGNALITH_ARCHIVE_DIR"],
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if len(c.Ingest.Tokens) < 2 || c.Ingest.Tokens[len(c.Ingest.Tokens)-2] != "file-token-0123456789" || c.Ingest.Tokens[len(c.Ingest.Tokens)-1] != "env-token-0123456789" {
		t.Errorf("tokens %q", c.Ingest.Tokens)
	}
	if c.Vulns.OpenVASPassword != "test-openvas-password" || c.Vulns.OpenVASAddress != "openvas.example.com:9390" || c.Vulns.NVDAPIKey != "test-nvd-key" ||
		c.Okta.APIToken != "test-okta-token" || c.M365.ClientSecret != "test-m365-secret" || c.Auth.OIDC.ClientSecret != "test-oidc-secret" {
		t.Errorf("secrets from the environment not used")
	}
	if c.Syslog.UDP != "" {
		t.Errorf("syslog.udp %q, want off", c.Syslog.UDP)
	}
}

// A variable and its _FILE both set, a _FILE that cannot be read or is
// empty, and values that do not parse stop the start.
func TestEnvironmentRefusals(t *testing.T) {
	path := writeConfig(t, "")
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"SIGNALITH_OKTA_API_TOKEN": "a", "SIGNALITH_OKTA_API_TOKEN_FILE": empty}, "are both set"},
		{map[string]string{"SIGNALITH_NVD_API_KEY_FILE": filepath.Join(t.TempDir(), "missing")}, "SIGNALITH_NVD_API_KEY_FILE is set to"},
		{map[string]string{"SIGNALITH_M365_CLIENT_SECRET_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_OIDC_CLIENT_SECRET_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_OKTA_PRIVATE_KEY_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_OPENVAS_PASSWORD_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_ASSISTANT_API_KEY_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_LDAP_BIND_PASSWORD_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_INGEST_TOKEN_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_OPENSEARCH_PASSWORD_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_ADMIN_PASSWORD_FILE": empty}, "which is empty"},
		{map[string]string{"SIGNALITH_PUBLIC_URL": "ftp://x"}, "SIGNALITH_PUBLIC_URL"},
		{map[string]string{"SIGNALITH_NODE_URL": "ftp://x"}, "SIGNALITH_NODE_URL"},
		{map[string]string{"SIGNALITH_LEADER_ELIGIBLE": "maybe"}, "SIGNALITH_LEADER_ELIGIBLE \"maybe\" must be true or false"},
		{map[string]string{"SIGNALITH_PROXY_PROTOCOL": "maybe"}, "SIGNALITH_PROXY_PROTOCOL"},
	} {
		t.Run(c.want, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v: %v", c.env, err)
			}
		})
	}
}
