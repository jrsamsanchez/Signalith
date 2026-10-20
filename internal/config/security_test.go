// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validConfig(t *testing.T) *Config {
	t.Helper()
	c := Default()
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	c.Auth.AdminPasswordHash = h
	return c
}

func TestOpenSearchURLCredentialsAreMoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	c := validConfig(t)
	c.OpenSearch.URL = "https://signalith:S3cr3tPass@os.internal:9200"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	o := got.OpenSearch
	if o.URL != "https://os.internal:9200" || o.Username != "signalith" || o.Password != "S3cr3tPass" {
		t.Errorf("opensearch = %+v", o)
	}
	// Separate settings win over the URL's.
	c = validConfig(t)
	c.OpenSearch.URL = "https://a:b@os.internal:9200"
	c.OpenSearch.Username, c.OpenSearch.Password = "signalith", "pw"
	if err := c.Validate(); err != nil || c.OpenSearch.URL != "https://os.internal:9200" || c.OpenSearch.Username != "signalith" || c.OpenSearch.Password != "pw" {
		t.Errorf("%v %+v", err, c.OpenSearch)
	}
}

func TestOpenSearchPlainHTTPCredentials(t *testing.T) {
	for _, tc := range []struct {
		url, user string
		allow     bool
		ok        bool
	}{
		{"http://127.0.0.1:9200", "signalith", false, true},
		{"http://localhost:9200", "signalith", false, true},
		{"http://[::1]:9200", "signalith", false, true},
		{"http://opensearch:9200", "", false, true}, // no credentials to protect
		{"https://os.internal:9200", "signalith", false, true},
		{"http://os.internal:9200", "signalith", false, false},
		{"http://10.0.0.5:9200", "signalith", false, false},
		{"http://os.internal:9200", "signalith", true, true},
	} {
		c := validConfig(t)
		c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password = tc.url, tc.user, "pw"
		if tc.user == "" {
			c.OpenSearch.Password = ""
		}
		c.OpenSearch.AllowInsecureHTTP = tc.allow
		err := c.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s user %q allow %v: %v", tc.url, tc.user, tc.allow, err)
		}
		if err != nil && (!strings.Contains(err.Error(), "unencrypted") || !strings.Contains(err.Error(), "allow_insecure_http")) {
			t.Errorf("error does not say how to fix it: %v", err)
		}
		warned := strings.Contains(strings.Join(c.Warnings(), " "), "allow_insecure_http")
		if warned != (tc.allow && tc.ok) {
			t.Errorf("%s: warnings %v", tc.url, c.Warnings())
		}
	}
}

func TestOpenSearchTLSSettings(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signalith"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "client.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "client-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	os.WriteFile(filepath.Join(dir, "junk.pem"), []byte("not a certificate"), 0o600)

	// Relative paths are relative to the config file.
	path := filepath.Join(dir, "signalith.yaml")
	c := validConfig(t)
	c.OpenSearch.URL = "https://os.internal:9200"
	c.OpenSearch.CAFile, c.OpenSearch.CertFile, c.OpenSearch.KeyFile = "ca.pem", "client.pem", "client-key.pem"
	c.OpenSearch.Proxy = "http://proxy.internal:3128"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if ca, cert, k := got.OpenSearchTLSFiles(); ca != filepath.Join(dir, "ca.pem") || cert != filepath.Join(dir, "client.pem") || k != filepath.Join(dir, "client-key.pem") {
		t.Errorf("files %s %s %s", ca, cert, k)
	}

	for _, tc := range []struct {
		change func(*OpenSearch)
		want   string
	}{
		{func(o *OpenSearch) { o.CAFile = "missing.pem" }, "opensearch.ca_file"},
		{func(o *OpenSearch) { o.CAFile = "junk.pem" }, "no PEM certificates"},
		{func(o *OpenSearch) { o.KeyFile = "" }, "set together"},
		{func(o *OpenSearch) { o.KeyFile = "ca.pem" }, "cert_file and key_file"},
		{func(o *OpenSearch) { o.Proxy = "proxy.internal:3128" }, "opensearch.proxy"},
		{func(o *OpenSearch) { o.URL = "http://127.0.0.1:9200" }, "only apply to an https://"},
	} {
		c := *got
		tc.change(&c.OpenSearch)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
}

func TestWarnings(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil || len(c.Warnings()) != 0 {
		t.Fatalf("defaults warn: %v %v", err, c.Warnings())
	}
	c.OpenSearch.URL = "https://os.internal:9200"
	c.OpenSearch.TLSSkipVerify = true
	c.Assistant = Assistant{Provider: "openai", URL: "http://ollama.lan:11434/v1", Model: "llama3.1", APIKey: "k"}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "tls_skip_verify") || !strings.Contains(w, "ca_file") || !strings.Contains(w, "AI model's API key") {
		t.Errorf("warnings: %s", w)
	}
}

const commentedConfig = `# My notes about this server.
server:
  listen: 0.0.0.0:8080   # all interfaces
opensearch:
  url: http://127.0.0.1:9200
auth:
  admin_user: admin
  admin_password_hash: '$2a$10$oldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldol'  # set by init
ingest:
  tokens:
    - file-token-0123456789
`

func TestSetAdminPasswordHashChangesOnlyTheHash(t *testing.T) {
	// Secrets supplied through the environment must stay out of the file.
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "OS-SECRET-PW")
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-ant-ENV-ONLY")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789abcdef")
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "/env/lookups")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(path, []byte(commentedConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	h, _ := HashPassword("new password with spaces")
	if err := SetAdminPasswordHash(path, h); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	want := strings.Replace(commentedConfig, `'$2a$10$oldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldoldol'`, `"`+h+`"`, 1)
	if string(out) != want {
		t.Errorf("file is now:\n%s\nwant:\n%s", out, want)
	}
	for _, secret := range []string{"OS-SECRET-PW", "sk-ant-ENV-ONLY", "env-token", "/env/lookups"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("%q from the environment was written to the file", secret)
		}
	}
	// Windows has no Unix permission bits; Stat reports 0666 for any file.
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	c, err := Load(path)
	if err != nil || !c.CheckPassword("admin", "new password with spaces") {
		t.Fatalf("load after passwd: %v", err)
	}
}

func TestSetAdminPasswordHashAddsMissingKeys(t *testing.T) {
	for name, content := range map[string]string{
		"no auth section": "# notes\nserver:\n    listen: 127.0.0.1:8080\n",
		"empty hash":      "auth:\n    admin_user: admin\n    admin_password_hash:\n",
		"plain hash":      "auth:\n    admin_password_hash: $2a$10$plainplainplainplainplainplainplainplainplainplainpl\n",
		"empty file":      "",
	} {
		path := filepath.Join(t.TempDir(), "signalith.yaml")
		os.WriteFile(path, []byte(content), 0o600)
		h, _ := HashPassword("long enough")
		if err := SetAdminPasswordHash(path, h); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, _ := os.ReadFile(path)
		if valueAt(out, []string{"auth", "admin_password_hash"}) != h {
			t.Errorf("%s: hash not set:\n%s", name, out)
		}
		if strings.HasPrefix(content, "# notes") && !strings.Contains(string(out), "# notes") {
			t.Errorf("%s: comment lost:\n%s", name, out)
		}
	}
	path := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(path, []byte("auth: [1, 2\n"), 0o600)
	if err := SetAdminPasswordHash(path, "x"); err == nil || !strings.Contains(err.Error(), "not valid YAML") {
		t.Errorf("broken file: %v", err)
	}
	if err := SetAdminPasswordHash(filepath.Join(t.TempDir(), "none.yaml"), "x"); err == nil || !strings.Contains(err.Error(), "signalith init") {
		t.Errorf("missing file: %v", err)
	}
}

// TestOpenSearchURLSecretsStayOutOfErrors covers the rest of
// authz-secrets-in-urls: a URL written without its scheme, or with a
// query string, is refused without repeating the secret in it.
func TestOpenSearchURLSecretsStayOutOfErrors(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"admin:S3CR3T@opensearch.corp:9200", `"***@opensearch.corp:9200" must be http(s)://host:port`},
		{"admin:p@ss/S3CR3T@opensearch.corp:9200/x", `"***@opensearch.corp:9200" must be http(s)://host:port`},
		{"https://opensearch.corp:9200/?token=S3CR3T", "opensearch.url https://opensearch.corp:9200 must not have a query string"},
		{"https://opensearch.corp:9200/?x=S3CR3T", "opensearch.url https://opensearch.corp:9200 must not have a query string"},
		{"https://opensearch.corp:9200/#S3CR3T", "must not have a query string (?...) or fragment"},
	} {
		c := validConfig(t)
		c.OpenSearch.URL = tc.url
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "S3CR3T") {
			t.Errorf("%s: %v", tc.url, err)
		}
	}
	// The environment variable is checked the same way.
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "admin:S3CR3T@opensearch.corp:9200")
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), "S3CR3T") {
		t.Errorf("env: %v", err)
	}
}

func TestOpenSearchProxyFromEnvironment(t *testing.T) {
	t.Setenv("SIGNALITH_OPENSEARCH_PROXY", " http://proxy.corp:3128 ")
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.OpenSearch.Proxy != "http://proxy.corp:3128" {
		t.Errorf("%v %q", err, c.OpenSearch.Proxy)
	}
}

func TestSharedAddresses(t *testing.T) {
	c := validConfig(t)
	c.Server.SharedAddresses = []string{"10.0.0.5", " 192.0.2.0/24", "2001:db8:aa::/48", "::ffff:198.51.100.7"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.Server.SharedList() {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "10.0.0.5/32 192.0.2.0/24 2001:db8:aa::/48 198.51.100.7/32" {
		t.Errorf("shared = %v", got)
	}
	c.Server.SharedAddresses = []string{"proxy.corp", "10.0.0.0/33"}
	err := c.Validate()
	for _, want := range []string{`server.shared_addresses[0] "proxy.corp" must be an IP address or a CIDR`, `server.shared_addresses[1]`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	// Saved files explain the setting.
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "server.shared_addresses") {
		t.Error("the saved file does not mention server.shared_addresses")
	}
}
