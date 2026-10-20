// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"gopkg.in/yaml.v3"
)

// sealedValues returns every enc: value in a file, decrypted with keys.
func sealedValues(t *testing.T, data []byte, keys *secrets.Keyring) map[string]string {
	t.Helper()
	out := map[string]string{}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, n := range secretNodes(&doc) {
		if secrets.IsSealed(n.node.Value) {
			v, err := keys.Open(n.field, n.node.Value)
			if err != nil {
				t.Fatalf("%s: %v", n.label, err)
			}
			out[n.label] = v
		}
	}
	return out
}

func TestStateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir() != dir {
		t.Errorf("StateDir = %s, want the folder holding lookups (%s)", c.StateDir(), dir)
	}
	t.Setenv("SIGNALITH_STATE_DIR", "/var/lib/signalith")
	if c.StateDir() != "/var/lib/signalith" {
		t.Errorf("StateDir with SIGNALITH_STATE_DIR = %s", c.StateDir())
	}
}

func TestSaveEncryptsAndLoadDecrypts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("CTI_KEY", "from-env")
	c := validConfig(t)
	c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password = "https://os.internal:9200", "signalith", "os-pass-123"
	c.Assistant.Provider, c.Assistant.APIKey = "anthropic", "sk-ant-key"
	c.Ingest.Tokens = []string{"token-0123456789abcdef", "token-fedcba9876543210"}
	c.Intel.Feeds = []IntelFeed{{Name: "otx", URL: "https://otx.example.com/feed.txt",
		Headers: map[string]string{"X-OTX-API-KEY": "otx-key", "X-Ref": "${CTI_KEY}"}, Username: "u", Password: "feed-pw"}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, plain := range []string{"os-pass-123", "sk-ant-key", "token-0123456789abcdef", "token-fedcba9876543210", "otx-key", "feed-pw"} {
		if strings.Contains(string(raw), plain) {
			t.Errorf("saved file has %q in plain text", plain)
		}
	}
	if n := len(regexp.MustCompile(`: enc:v1:|- enc:v1:`).FindAll(raw, -1)); n != 6 {
		t.Errorf("%d encrypted values, want 6:\n%s", n, raw)
	}
	if !strings.Contains(string(raw), "${CTI_KEY}") {
		t.Error("a ${ENV_VAR} reference should stay as it is")
	}
	if _, err := os.Stat(filepath.Join(dir, "keys")); err != nil {
		t.Errorf("no master key next to the config: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f := got.Intel.Feeds[0]
	if got.OpenSearch.Password != "os-pass-123" || got.Assistant.APIKey != "sk-ant-key" || got.Ingest.Tokens[1] != "token-fedcba9876543210" ||
		f.Headers["X-OTX-API-KEY"] != "otx-key" || f.Headers["X-Ref"] != "${CTI_KEY}" || f.Password != "feed-pw" {
		t.Errorf("loaded %+v %+v %v %+v", got.OpenSearch, got.Assistant, got.Ingest.Tokens, f)
	}
	if p := got.PlainSecrets(); len(p) != 0 {
		t.Errorf("PlainSecrets = %v", p)
	}
	for _, w := range got.Warnings() {
		if strings.Contains(w, "plain text") {
			t.Errorf("warning: %s", w)
		}
	}
}

// TestSaveNeverWritesEnvironmentValues is the regression test for
// "signalith passwd" copying secrets kept in environment variables into
// signalith.yaml: Save writes only what the file had.
func TestSaveNeverWritesEnvironmentValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(`# my comment
auth:
  admin_password_hash: `+validConfig(t).Auth.AdminPasswordHash+`
  ldap:
    url: ldaps://dc1.corp.example.com
    bind_dn: CN=svc,DC=corp,DC=example,DC=com
    user_base_dn: DC=corp,DC=example,DC=com
    admin_groups: [CN=Admins,DC=corp,DC=example,DC=com]
ingest:
  tokens: [file-token-0123456789]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SIGNALITH_OPENSEARCH_PASSWORD": "OS-SECRET-PW",
		"SIGNALITH_ASSISTANT_API_KEY":   "sk-ant-ENV-ONLY",
		"SIGNALITH_INGEST_TOKEN":        "env-token-0123456789abcdef",
		"SIGNALITH_LDAP_BIND_PASSWORD":  "ENV-BIND-PW",
		"SIGNALITH_LOOKUPS_DIR":         filepath.Join(dir, "env-lookups"),
		"SIGNALITH_ADMIN_PASSWORD":      "env admin password",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "OS-SECRET-PW" || len(c.Ingest.Tokens) != 2 {
		t.Fatalf("environment not applied: %+v %v", c.OpenSearch, c.Ingest.Tokens)
	}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, v := range sealedValues(t, raw, c.Keyring()) {
		for name, ev := range env {
			if v == ev {
				t.Errorf("%s was written into the file (encrypted)", name)
			}
		}
	}
	for name, v := range env {
		if strings.Contains(string(raw), v) {
			t.Errorf("%s was written into the file:\n%s", name, raw)
		}
	}
	if strings.Contains(string(raw), "env-lookups") {
		t.Error("a folder from the environment was written into the file")
	}
	// The LDAP section needs its bind password, so that one stays set.
	for _, k := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ADMIN_PASSWORD"} {
		os.Unsetenv(k)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.OpenSearch.Password != "" || back.Assistant.APIKey != "" || len(back.Ingest.Tokens) != 1 || back.Ingest.Tokens[0] != "file-token-0123456789" {
		t.Errorf("reloaded: %+v %+v %v", back.OpenSearch, back.Assistant, back.Ingest.Tokens)
	}
}

func TestPlainSecretWarnings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("CTI", "x")
	write := func(body string) {
		t.Helper()
		os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+validConfig(t).Auth.AdminPasswordHash+"\n"+body), 0o600)
	}
	write(`opensearch:
  url: https://os.internal:9200
  username: signalith
  password: plain-pw
ingest:
  tokens:
    - token-0123456789abcdef
    - token-fedcba9876543210
intel:
  feeds:
    - name: cti
      url: https://cti.example.com/list.txt
      headers: {X-Key: "${CTI}"}
`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "3 passwords or keys in signalith.yaml are stored as plain text (opensearch.password, ingest.tokens[0], ingest.tokens[1]). Run: signalith secrets encrypt"
	if !contains(c.Warnings(), want) {
		t.Errorf("warnings %q lack %q", c.Warnings(), want)
	}
	write("ingest:\n  tokens: [token-0123456789abcdef]\n")
	c, _ = Load(path)
	if !contains(c.Warnings(), "1 password or key in signalith.yaml is stored as plain text (ingest.tokens[0]). Run: signalith secrets encrypt") {
		t.Errorf("warnings %q", c.Warnings())
	}
	// A plain value from the environment is not the file's problem.
	write("")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "env")
	c, _ = Load(path)
	if len(c.Warnings()) != 0 {
		t.Errorf("warnings %q", c.Warnings())
	}
	// A master key from SIGNALITH_MASTER_KEY is flagged.
	t.Setenv("SIGNALITH_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	c, _ = Load(path)
	if len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "SIGNALITH_MASTER_KEY_FILE") {
		t.Errorf("warnings %q", c.Warnings())
	}
}

func TestLoadMixedAndWrongKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	keys := secrets.NewKeyring(dir)
	sealed, err := keys.Seal("assistant.api_key", "sk-sealed")
	if err != nil {
		t.Fatal(err)
	}
	body := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n" +
		"opensearch:\n  url: https://os.internal:9200\n  username: u\n  password: plain-pw\n" +
		"assistant:\n  provider: anthropic\n  api_key: " + sealed + "\n"
	os.WriteFile(path, []byte(body), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "plain-pw" || c.Assistant.APIKey != "sk-sealed" || len(c.Unreadable()) != 0 {
		t.Errorf("loaded %q %q %v", c.OpenSearch.Password, c.Assistant.APIKey, c.Unreadable())
	}
	if p := c.PlainSecrets(); len(p) != 1 || p[0] != "opensearch.password" {
		t.Errorf("PlainSecrets = %v", p)
	}
	// Another folder's key cannot open it. The server still starts, without
	// the value, and the warnings say which setting and what to do.
	other := filepath.Join(t.TempDir(), "signalith.yaml")
	os.WriteFile(other, []byte(body), 0o600)
	if _, err := secrets.NewKeyring(filepath.Dir(other)).Seal("x", "y"); err != nil {
		t.Fatal(err)
	}
	c, err = Load(other)
	if err != nil {
		t.Fatalf("a value that cannot be decrypted stopped Load: %v", err)
	}
	if c.Assistant.APIKey != "" {
		t.Errorf("the unreadable key was used: %q", c.Assistant.APIKey)
	}
	warnings := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"assistant.api_key is encrypted with master key " + keys.KeyID(), "signalith secrets set assistant.api_key", "never events", "runs without it"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings lack %q:\n%s", want, warnings)
		}
	}
	// A value copied into another setting is not used either, and the
	// key is not blamed for it.
	os.WriteFile(path, []byte(strings.Replace(body, "password: plain-pw", "password: "+sealed, 1)), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if u := c.Unreadable(); c.OpenSearch.Password != "" || len(u) != 1 || !strings.Contains(u[0], "opensearch.password cannot be decrypted") || strings.Contains(u[0], "Restore the master key") {
		t.Errorf("swapped value: %q %v", c.OpenSearch.Password, u)
	}
	// LoadUnchecked reads it as written, for the secrets commands.
	if c, err := LoadUnchecked(path); err != nil || c.OpenSearch.Password != sealed {
		t.Errorf("LoadUnchecked: %v", err)
	}
	// A bind password that cannot be decrypted is left empty, so directory
	// sign-in fails without trying it; the rest of the server runs.
	ldap := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n  ldap:\n    url: ldaps://dc1\n    bind_dn: CN=svc\n    bind_password: enc:v1:00000000:AAAA\n    user_base_dn: DC=x\n    admin_groups: [CN=a]\n"
	os.WriteFile(path, []byte(ldap), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatalf("a damaged bind password stopped Load: %v", err)
	}
	if c.Auth.LDAP.BindPassword != "" || len(c.Unreadable()) != 1 || !strings.Contains(c.Unreadable()[0], "auth.ldap.bind_password") {
		t.Errorf("damaged bind password: %q %v", c.Auth.LDAP.BindPassword, c.Unreadable())
	}
	// A bind password from the environment is used instead of the file's,
	// which then need not decrypt.
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "from-env")
	if c, err := Load(path); err != nil || len(c.Unreadable()) != 0 {
		t.Errorf("with the environment's bind password: %v", err)
	}
}

// With the master key lost, signalith.yaml still loads: unreadable ingest
// tokens are dropped and the others kept, and a feed whose key cannot be
// decrypted is not downloaded.
func TestLoadWithoutTheMasterKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	lost := secrets.NewKeyring(t.TempDir())
	seal := func(field, v string) string {
		s, err := lost.Seal(field, v)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	body := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n" +
		"opensearch:\n  url: https://os.internal:9200\n  username: u\n  password: " + seal("opensearch.password", "pw") + "\n" +
		"ingest:\n  tokens:\n    - " + seal("ingest.tokens", "token-from-the-lost-key") + "\n    - plain-token-0123456789\n" +
		"intel:\n  feeds:\n    - name: cti\n      url: https://cti.example.com/list.txt\n      headers:\n        X-Key: " + seal("intel.feeds.headers.x-key", "k") + "\n"
	os.WriteFile(path, []byte(body), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load without the master key: %v", err)
	}
	if c.OpenSearch.Password != "" {
		t.Errorf("opensearch.password = %q", c.OpenSearch.Password)
	}
	if len(c.Ingest.Tokens) != 1 || c.Ingest.Tokens[0] != "plain-token-0123456789" {
		t.Errorf("tokens = %v", c.Ingest.Tokens)
	}
	if p := c.FeedProblem("cti"); !strings.Contains(p, "headers.X-Key") || !strings.Contains(p, "not downloaded") {
		t.Errorf("FeedProblem = %q", p)
	}
	if len(c.Unreadable()) != 3 {
		t.Errorf("Unreadable = %v", c.Unreadable())
	}
	if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "ingest.tokens[0]") || !strings.Contains(w, "signalith secrets set ingest.tokens") {
		t.Errorf("warnings:\n%s", w)
	}
}

// A feed's encrypted values do not depend on its name, nor on the case of
// a header's name, so renaming them in the file keeps them readable.
func TestFeedValuesSurviveRenames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	keys := secrets.NewKeyring(dir)
	data := []byte("auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n" +
		"intel:\n  feeds:\n    - name: myfeed\n      url: https://cti.example.com/list.txt\n      headers:\n        X-API-Key: the-key\n")
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) })
	if err != nil || n != 1 {
		t.Fatalf("ResealFile = %d, %v", n, err)
	}
	renamed := strings.Replace(strings.Replace(string(out), "name: myfeed", "name: my-feed", 1), "X-API-Key:", "X-Api-Key:", 1)
	os.WriteFile(path, []byte(renamed), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := c.Intel.Feeds[0].Headers["X-Api-Key"]; v != "the-key" || len(c.Unreadable()) != 0 {
		t.Errorf("after renaming: %q %v", v, c.Unreadable())
	}
	// Another header name is another setting; the message says to change
	// the name back.
	os.WriteFile(path, []byte(strings.Replace(renamed, "X-Api-Key:", "X-Token:", 1)), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if u := c.Unreadable(); len(u) != 1 || !strings.Contains(u[0], "change the name back") {
		t.Errorf("Unreadable = %v", u)
	}
}

// A password written into opensearch.url counts as plain text, and
// MoveURLPassword moves it into opensearch.password, where it can be
// encrypted. Passwords in the proxy and keys in feed addresses get a
// warning of their own.
func TestPasswordsInAddresses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	body := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n" +
		"opensearch:\n  url: https://admin:Plain%20OS%20pw%231@os.internal:9200   # the cluster\n  proxy: http://me:proxypw@proxy:3128\n" +
		"intel:\n  feeds:\n    - name: cti\n      url: https://cti.example.com/list.txt?apikey=abc\n"
	os.WriteFile(path, []byte(body), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p := c.PlainSecrets(); len(p) != 1 || !strings.Contains(p[0], "opensearch.url") {
		t.Errorf("PlainSecrets = %v", p)
	}
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"SIGNALITH_OPENSEARCH_PROXY", "apikey=", "Run: signalith secrets encrypt"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if list := AddressSecrets([]byte(body)); len(list) != 3 || !list[0].Movable || list[1].Movable {
		t.Errorf("AddressSecrets = %+v", list)
	}
	out, moved, err := MoveURLPassword([]byte(body))
	if err != nil || !moved {
		t.Fatalf("MoveURLPassword = %v, %v", moved, err)
	}
	if !strings.Contains(string(out), "url: https://os.internal:9200   # the cluster") {
		t.Errorf("the address was not cleaned in place:\n%s", out)
	}
	os.WriteFile(path, out, 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Username != "admin" || c.OpenSearch.Password != "Plain OS pw#1" || c.OpenSearch.URL != "https://os.internal:9200" {
		t.Errorf("after moving: %q %q %q", c.OpenSearch.Username, c.OpenSearch.Password, c.OpenSearch.URL)
	}
	if p := c.PlainSecrets(); len(p) != 1 || p[0] != "opensearch.password" {
		t.Errorf("PlainSecrets after moving = %v", p)
	}
	if _, moved, _ := MoveURLPassword(out); moved {
		t.Error("moved twice")
	}
	// With a password set already, the address's is only removed.
	withPw := strings.Replace(body, "  proxy:", "  username: u\n  password: kept\n  proxy:", 1)
	out, moved, err = MoveURLPassword([]byte(withPw))
	if err != nil || !moved || strings.Contains(string(out), "Plain%20OS") || !strings.Contains(string(out), "password: kept") {
		t.Errorf("MoveURLPassword with a password set: %v %v\n%s", moved, err, out)
	}
}

const layoutFile = `# Signalith configuration (hand-written).
server:
  listen: 0.0.0.0:8080   # all interfaces

opensearch:
  url: https://os.internal:9200
  username: signalith
  password: "os pass"    # the OpenSearch password
assistant:
  provider: anthropic
  api_key: 'sk-ant-1'
auth:
  admin_password_hash: HASH
ingest:
  # Agents' tokens.
  tokens:
    - token-0123456789abcdef   # Windows agents
    - token-fedcba9876543210
intel:
  feeds:
    - name: otx
      url: https://otx.example.com/feed.txt
      headers: {X-OTX-API-KEY: otx-key, X-Env: "${OTX}"}
      username: me
      password: feed-pw
`

func TestResealFileKeepsCommentsAndLayout(t *testing.T) {
	keys := secrets.NewKeyring(t.TempDir())
	data := []byte(strings.Replace(layoutFile, "HASH", validConfig(t).Auth.AdminPasswordHash, 1))
	var seen []string
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) {
		seen = append(seen, s.Label)
		return keys.Seal(s.Field, s.Value)
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSeen := []string{"opensearch.password", "assistant.api_key", "ingest.tokens[0]", "ingest.tokens[1]", "intel.feeds[otx].headers.X-OTX-API-KEY", "intel.feeds[otx].password"}
	if n != 6 || strings.Join(seen, ",") != strings.Join(wantSeen, ",") {
		t.Fatalf("changed %d, saw %v", n, seen)
	}
	inLines, outLines := strings.Split(string(data), "\n"), strings.Split(string(out), "\n")
	if len(inLines) != len(outLines) {
		t.Fatalf("line count changed:\n%s", out)
	}
	secretLine := regexp.MustCompile(`os pass|sk-ant-1|token-|otx-key|feed-pw`)
	for i := range inLines {
		if secretLine.MatchString(inLines[i]) {
			if !strings.Contains(outLines[i], "enc:v1:") {
				t.Errorf("line %d not encrypted: %s", i+1, outLines[i])
			}
			continue
		}
		if inLines[i] != outLines[i] {
			t.Errorf("line %d changed:\n  %s\n  %s", i+1, inLines[i], outLines[i])
		}
	}
	for _, keep := range []string{"# the OpenSearch password", "# Windows agents", `X-Env: "${OTX}"`} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("lost %q", keep)
		}
	}
	got := sealedValues(t, out, keys)
	want := map[string]string{"opensearch.password": "os pass", "assistant.api_key": "sk-ant-1", "ingest.tokens[0]": "token-0123456789abcdef",
		"ingest.tokens[1]": "token-fedcba9876543210", "intel.feeds[otx].headers.X-OTX-API-KEY": "otx-key", "intel.feeds[otx].password": "feed-pw"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// Running it again finds nothing to do.
	if again, n, err := ResealFile(out, func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) }); err != nil || n != 0 || !bytes.Equal(again, out) {
		t.Errorf("second run changed %d: %v", n, err)
	}
	// The file loads with the encrypted values.
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, out, 0o600)
	c, err := LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	c.keys = keys
	if c.openSecrets(); len(c.Unreadable()) != 0 || c.OpenSearch.Password != "os pass" || c.Intel.Feeds[0].Headers["X-OTX-API-KEY"] != "otx-key" {
		t.Errorf("open: %v %+v", c.Unreadable(), c.OpenSearch)
	}
}

func TestResealFileFallsBackForBlockValues(t *testing.T) {
	keys := secrets.NewKeyring(t.TempDir())
	data := []byte("# keep me\nopensearch:\n  url: https://os:9200\n  password: |\n    multi\n    line\nassistant:\n  api_key: k1 # key\n")
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) })
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got := sealedValues(t, out, keys)
	if got["opensearch.password"] != "multi\nline\n" || got["assistant.api_key"] != "k1" || !strings.Contains(string(out), "# keep me") {
		t.Errorf("got %q from:\n%s", got, out)
	}
}

// SetSecret stores value, encrypted with keys, as the setting field of the
// config file at path, as "signalith secrets set" does.
func SetSecret(path, field, value string, keys *secrets.Keyring) error {
	data, err := ReadForEdit(path)
	if err != nil {
		return err
	}
	if err := CheckSecret(field, value); err != nil {
		return err
	}
	if _, err := SetSecretText(data, field, "enc:v1:00000000:AAAA"); err != nil {
		return err
	}
	sealed, err := keys.Seal(field, value)
	if err != nil {
		return err
	}
	out, err := SetSecretText(data, field, sealed)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func TestSetSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	keys := secrets.NewKeyring(dir)
	base := strings.Replace(layoutFile, "HASH", validConfig(t).Auth.AdminPasswordHash, 1)
	os.WriteFile(path, []byte(base), 0o600)
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "ENV-KEY")
	if err := SetSecret(path, "opensearch.password", "new pass", keys); err != nil {
		t.Fatal(err)
	}
	if err := SetSecret(path, "ingest.tokens", "added-token-0123456789", keys); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	inLines, outLines := strings.Split(base, "\n"), strings.Split(string(out), "\n")
	if len(outLines) != len(inLines)+1 {
		t.Fatalf("expected one added line:\n%s", out)
	}
	if !strings.Contains(outLines[18], `    - "enc:v1:`) {
		t.Errorf("new token line: %q", outLines[18])
	}
	if !strings.Contains(string(out), "# the OpenSearch password") || strings.Contains(string(out), "ENV-KEY") {
		t.Errorf("file:\n%s", out)
	}
	got := sealedValues(t, out, keys)
	if got["opensearch.password"] != "new pass" || got["ingest.tokens[2]"] != "added-token-0123456789" {
		t.Errorf("values %v", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	}
	// A missing key, a flow list and a missing list are added.
	os.WriteFile(path, []byte("server:\n  listen: 127.0.0.1:8080\ningest:\n  tokens: [a-token-0123456789abc]\n"), 0o600)
	if err := SetSecret(path, "assistant.api_key", "sk-1", keys); err != nil {
		t.Fatal(err)
	}
	if err := SetSecret(path, "ingest.tokens", "b-token-0123456789abc", keys); err != nil {
		t.Fatal(err)
	}
	out, _ = os.ReadFile(path)
	if toks := tokenList(out); len(toks) != 2 || toks[0] != "a-token-0123456789abc" {
		t.Errorf("tokens %v in:\n%s", toks, out)
	}
	if got := sealedValues(t, out, keys); got["assistant.api_key"] != "sk-1" || got["ingest.tokens[1]"] != "b-token-0123456789abc" {
		t.Errorf("values %v", got)
	}
	os.WriteFile(path, []byte("server:\n  listen: 127.0.0.1:8080\n"), 0o600)
	if err := SetSecret(path, "ingest.tokens", "c-token-0123456789abc", keys); err != nil {
		t.Fatal(err)
	}
	if out, _ = os.ReadFile(path); len(tokenList(out)) != 1 {
		t.Errorf("no tokens list made:\n%s", out)
	}
	// Refusals.
	if err := SetSecret(path, "auth.ldap.bind_password", "x", keys); err == nil || !strings.Contains(err.Error(), "Users page") {
		t.Errorf("bind password without auth.ldap: %v", err)
	}
	if err := SetSecret(path, "opensearch.username", "x", keys); err == nil || !strings.Contains(err.Error(), strings.Join(SettableSecrets, ", ")) {
		t.Errorf("unknown setting: %v", err)
	}
	if err := SetSecret(path, "ingest.tokens", "short", keys); err == nil || !strings.Contains(err.Error(), "16") {
		t.Errorf("short token: %v", err)
	}
}

func TestPlainScalar(t *testing.T) {
	for v, want := range map[string]bool{
		"enc:v1:0a1b2c3d:AbC-_xyz": true, "$2a$10$abc/def.ghi": true, "token-0123": true,
		"true": false, "123": false, "null": false, "a b": false, "x #y": false, "key:": false, "'q'": false, "": false, "-x": false,
	} {
		if got := plainScalar(v); got != want {
			t.Errorf("plainScalar(%q) = %v", v, got)
		}
	}
}

// On Linux a config in /etc is a system install: its master key goes in
// /var/lib/signalith, where the service keeps its files, not next to
// signalith.yaml, so backups of /etc do not carry the key with the values.
func TestSystemInstallKeyFolder(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", "")
	c := Default()
	c.path = "/etc/signalith/signalith.yaml"
	want := filepath.Join("/etc/signalith", "keys", "master.key")
	if runtime.GOOS == "linux" {
		want = "/var/lib/signalith/keys/master.key"
	}
	if got := c.Keyring().DefaultPath(); runtime.GOOS != "windows" && got != want {
		t.Errorf("DefaultPath = %s, want %s", got, want)
	}
	// SIGNALITH_STATE_DIR still decides when set, and other places keep
	// the key in the state folder.
	t.Setenv("SIGNALITH_STATE_DIR", "/srv/signalith")
	c = Default()
	c.path = "/etc/signalith/signalith.yaml"
	if got := c.Keyring().DefaultPath(); !strings.HasPrefix(got, filepath.Join("/srv/signalith", "keys")) {
		t.Errorf("with SIGNALITH_STATE_DIR: %s", got)
	}
	t.Setenv("SIGNALITH_STATE_DIR", "")
	c = Default()
	c.path = filepath.Join(t.TempDir(), "signalith.yaml")
	if got := c.Keyring().DefaultPath(); !strings.HasPrefix(got, filepath.Join(filepath.Dir(c.path), "keys")) {
		t.Errorf("a config elsewhere: %s", got)
	}
}
