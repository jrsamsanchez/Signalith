// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// useKeyring makes k the keyring secrets.Seal and secrets.Open use for
// the rest of the test, as the server does with its config's.
func useKeyring(t *testing.T, k *secrets.Keyring) {
	t.Helper()
	before := secrets.Default()
	secrets.SetDefault(k)
	t.Cleanup(func() { secrets.SetDefault(before) })
}

// Passwords and keys saved on the Settings page are kept encrypted in
// settings.yaml, each for its own setting, and every load decrypts them.
func TestPageSecretsAreEncrypted(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://os.example:9200\n  username: signalith\n")
	c0, err := LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	useKeyring(t, c0.Keyring())
	res, err := CheckEdit(path, Edit{By: "ann", Values: map[string]any{
		"opensearch.password": "page-pw", "assistant.provider": "anthropic", "assistant.api_key": "sk-page-key",
	}})
	if err != nil || !res.OK() {
		t.Fatalf("edit: %v %v %v", err, res.Fields, res.Problems)
	}
	file := res.Config.SettingsFile()
	if err := WritePageSettings(file, res.Page); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "page-pw") || strings.Contains(string(data), "sk-page-key") || strings.Count(string(data), "secret: enc:v1:") != 2 {
		t.Fatalf("settings file:\n%s", data)
	}
	if fi, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("settings file mode: %v %v", fi.Mode(), err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "page-pw" || c.Assistant.APIKey != "sk-page-key" || c.Source("assistant.api_key").Kind != FromPage || len(c.PageUnreadable()) != 0 {
		t.Errorf("loaded %q %q %v %v", c.OpenSearch.Password, c.Assistant.APIKey, c.Source("assistant.api_key"), c.PageUnreadable())
	}
	if got := c.OpenSearchConnection().Password; got.Reveal() != "page-pw" || got.String() != secrets.Redacted {
		t.Errorf("connection password %q", got.Reveal())
	}
	saved, err := LoadSaved(path)
	if err != nil || saved.OpenSearch.Password != "page-pw" || saved.Assistant.APIKey != "sk-page-key" {
		t.Fatalf("saved: %v", err)
	}
	// A value moved to another setting does not decrypt.
	p, err := ReadPageSettings(file)
	if err != nil {
		t.Fatal(err)
	}
	*p.Settings["assistant.api_key"].Secret = *p.Settings["opensearch.password"].Secret
	if err := WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil || c.Assistant.APIKey != "" || len(c.PageUnreadable()) != 1 || !strings.Contains(c.PageUnreadable()[0], "assistant.api_key cannot be decrypted") {
		t.Errorf("swapped: %v %q %v", err, c.Assistant.APIKey, c.PageUnreadable())
	}
}

// A secret saved on the page that cannot be decrypted (the master key was
// lost or replaced) is left out and reported; Signalith still starts, with
// the page's other settings.
func TestUnreadablePageSecretDoesNotStopSignalith(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://os.example:9200\n  username: signalith\n  password: from-file\n"+
		"assistant:\n  provider: anthropic\n  api_key: sk-from-file\n")
	other := secrets.NewKeyring(t.TempDir())
	pw, err := other.Seal("settings.opensearch.password", "lost-pw")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := other.Seal("settings.assistant.api_key", "sk-lost")
	file := writePage(t, path, "settings:\n"+
		"  opensearch.password:\n    secret: "+pw+"\n    sent_to: https://os.example:9200\n    changed_by: ann\n"+
		"  assistant.api_key:\n    secret: "+key+"\n    sent_to: https://api.anthropic.com:443\n    changed_by: ann\n"+
		"  search.max_events:\n    value: 777\n    changed_by: ann\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Left out, as if none were set: neither the lost one nor the one in
	// signalith.yaml, which the page replaced, is used.
	if c.OpenSearch.Password != "" || c.Assistant.APIKey != "" || c.Search.MaxEvents != 777 || c.SettingsProblem() != "" {
		t.Errorf("loaded %q %q %d %q", c.OpenSearch.Password, c.Assistant.APIKey, c.Search.MaxEvents, c.SettingsProblem())
	}
	if c.Source("opensearch.password").Kind != FromPage || len(c.PageUnreadable()) != 2 || len(c.Unreadable()) != 0 {
		t.Errorf("source %v, unreadable %v %v", c.Source("opensearch.password"), c.PageUnreadable(), c.Unreadable())
	}
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{
		"On the Settings page (" + file + "), opensearch.password is encrypted with master key " + other.KeyID(),
		"Enter it again on the Settings page, or remove it there or with: signalith settings reset opensearch.password. Signalith runs without it until then.",
		"assistant.api_key is encrypted with master key " + other.KeyID(),
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "lost-pw") || strings.Contains(w, "sk-lost") {
		t.Errorf("warnings show a secret:\n%s", w)
	}
	if p := c.PageSecretProblem("opensearch.password"); !strings.Contains(p, "master key "+other.KeyID()) || !strings.Contains(p, "enter it again") {
		t.Errorf("field problem %q", p)
	}
	// The page's view and a check of an edit see the same.
	saved, err := LoadSaved(path)
	if err != nil || saved.Problems != nil || saved.PageErr != nil || saved.PageSecretProblem("assistant.api_key") == "" {
		t.Fatalf("saved: %v %v %v", err, saved.Problems, saved.PageErr)
	}
	// Entering it again fixes it.
	useKeyring(t, secrets.NewKeyring(t.TempDir()))
	res, err := CheckEdit(path, Edit{By: "ann", Values: map[string]any{"opensearch.password": "new-pw"}})
	if err != nil || !res.OK() {
		t.Fatalf("edit: %v %v", err, res.Fields)
	}
	if err := WritePageSettings(file, res.Page); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || c.OpenSearch.Password != "new-pw" || len(c.PageUnreadable()) != 1 || c.PageSecretProblem("opensearch.password") != "" {
		t.Errorf("entered again: %v %q %v", err, c.OpenSearch.Password, c.PageUnreadable())
	}
}

// A value in signalith.yaml that cannot be decrypted is not reported when
// the page replaces it, as when an environment variable does.
func TestPageReplacesUnreadableFileSecret(t *testing.T) {
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("opensearch.password", "lost")
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "opensearch:\n  url: https://os.example:9200\n  username: signalith\n  password: "+sealed+"\n")
	if c, err := Load(path); err != nil || len(c.Unreadable()) != 1 {
		t.Fatalf("without the page: %v %v", err, c.Unreadable())
	}
	c0, _ := LoadUnchecked(path)
	useKeyring(t, c0.Keyring())
	p := &PageSettings{}
	if err := p.SetSecret("opensearch.password", "page-pw", "https://os.example:9200", "ann", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := WritePageSettings(c0.SettingsFile(), p); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.OpenSearch.Password != "page-pw" || len(c.Unreadable()) != 0 || len(c.PageUnreadable()) != 0 {
		t.Errorf("with the page: %v %q %v %v", err, c.OpenSearch.Password, c.Unreadable(), c.PageUnreadable())
	}
	// The config without the page still has it unreadable.
	if b := c.Base(); b.OpenSearch.Password != "" || len(b.Unreadable()) != 1 {
		t.Errorf("base %q %v", b.OpenSearch.Password, b.Unreadable())
	}
}

// Every load that gives a config the server or a command uses decrypts
// both signalith.yaml and the page.
func TestEveryLoadDecrypts(t *testing.T) {
	path := writeConfig(t, "")
	c0, err := LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	useKeyring(t, c0.Keyring())
	sealed, err := c0.Keyring().Seal("opensearch.password", "yaml-pw")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	data = append(data, []byte("opensearch:\n  url: https://os.example:9200\n  username: signalith\n  password: "+sealed+"\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &PageSettings{}
	if err := p.SetSecret("assistant.api_key", "sk-page", "https://api.anthropic.com:443", "ann", time.Now()); err != nil {
		t.Fatal(err)
	}
	p.Set("assistant.provider", "anthropic", "ann", time.Now())
	p.Set("search.max_events", 123, "ann", time.Now())
	if err := WritePageSettings(c0.SettingsFile(), p); err != nil {
		t.Fatal(err)
	}
	check := func(name string, c *Config, err error, page bool) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.OpenSearch.Password != "yaml-pw" || len(c.Unreadable()) != 0 {
			t.Errorf("%s: opensearch.password %q %v", name, c.OpenSearch.Password, c.Unreadable())
		}
		if page && c.Assistant.APIKey != "sk-page" {
			t.Errorf("%s: assistant.api_key %q", name, c.Assistant.APIKey)
		}
	}
	c, err := Load(path)
	check("Load", c, err, true)
	c, err = LoadFile(path)
	check("LoadFile", c, err, false)
	saved, err := LoadSaved(path)
	check("LoadSaved", saved.Config, err, true)
	check("LoadSaved base", saved.Base(), err, false)
	c, err = LoadSetAside(path, []string{"search.max_events"}, "a test")
	check("LoadSetAside", c, err, true)
	if err == nil && c.Search.MaxEvents == 123 {
		t.Errorf("LoadSetAside used the setting set aside")
	}
	c, err = LoadWithoutPage(path, "a test", nil)
	check("LoadWithoutPage", c, err, false)
	if err == nil && (c.Assistant.APIKey != "" || c.SettingsProblem() == "") {
		t.Errorf("LoadWithoutPage used the page: %q %q", c.Assistant.APIKey, c.SettingsProblem())
	}
	// Save writes signalith.yaml as the file has it: never the page's
	// settings nor the environment's.
	t.Setenv("SIGNALITH_OPENSEARCH_USERNAME", "from-env")
	if err := os.WriteFile(path, append(data, []byte("assistant:\n  api_key: sk-file\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err == nil {
		if err := c.Save(path + ".out"); err == nil || !strings.Contains(err.Error(), "LoadFile") {
			t.Errorf("Save with the page's settings: %v", err)
		}
	}
	c, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save(path + ".out"); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path + ".out")
	if strings.Contains(string(out), "from-env") || strings.Contains(string(out), "sk-page") || strings.Contains(string(out), "max_events: 123") || !strings.Contains(string(out), sealed) {
		t.Errorf("saved file:\n%s", out)
	}
}

// settings.yaml as Signalith kept it before it encrypted the page's
// secrets (plain text) still works, and ResealSettingsFile, which the
// server runs at startup, encrypts it.
func TestPlainPageSecretsFromBeforeAreEncrypted(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://os.example:9200\n  username: signalith\nassistant:\n  provider: anthropic\n")
	body := "# by an older version\nsettings:\n" +
		"  opensearch.password:\n    secret: old-plain-pw\n    sent_to: https://os.example:9200\n    changed_by: ann\n    changed_at: 2026-10-01T09:30:00Z\n" +
		"  assistant.api_key:\n    value: sk-by-hand\n    sent_to: https://api.anthropic.com:443\n" +
		"  search.max_events:\n    value: 50\n    changed_by: bob\n"
	file := writePage(t, path, body)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "old-plain-pw" || c.Assistant.APIKey != "sk-by-hand" || c.Search.MaxEvents != 50 {
		t.Fatalf("plain: %q %q %d %q", c.OpenSearch.Password, c.Assistant.APIKey, c.Search.MaxEvents, c.SettingsProblem())
	}
	// Listed as they are: nothing changes.
	var listed []secrets.Stored
	out, n, err := ResealSettingsFile([]byte(body), func(s secrets.Stored) (string, error) {
		listed = append(listed, s)
		return s.Value, nil
	})
	if err != nil || n != 0 || string(out) != body || len(listed) != 2 ||
		listed[0] != (secrets.Stored{Field: "settings.assistant.api_key", Label: "assistant.api_key", Value: "sk-by-hand"}) ||
		listed[1] != (secrets.Stored{Field: "settings.opensearch.password", Label: "opensearch.password", Value: "old-plain-pw"}) {
		t.Fatalf("list: %v %d %+v", err, n, listed)
	}
	c0, _ := LoadUnchecked(path)
	keys := c0.Keyring()
	out, n, err = ResealSettingsFile([]byte(body), func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) })
	if err != nil || n != 2 {
		t.Fatalf("reseal: %v %d", err, n)
	}
	if strings.Contains(string(out), "old-plain-pw") || strings.Contains(string(out), "sk-by-hand") || strings.Count(string(out), "secret: enc:v1:") != 2 ||
		!strings.Contains(string(out), "sent_to: https://os.example:9200") || !strings.Contains(string(out), "changed_by: bob") {
		t.Fatalf("resealed:\n%s", out)
	}
	if err := os.WriteFile(file, out, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil || c.OpenSearch.Password != "old-plain-pw" || c.Assistant.APIKey != "sk-by-hand" || c.Search.MaxEvents != 50 || c.Source("opensearch.password").By != "ann" {
		t.Errorf("after: %v %q %q %v", err, c.OpenSearch.Password, c.Assistant.APIKey, c.Source("opensearch.password"))
	}
	if _, _, err := ResealSettingsFile([]byte("settings: [broken"), func(s secrets.Stored) (string, error) { return s.Value, nil }); err == nil {
		t.Error("a broken file was resealed")
	}
}

// A value typed on the page that looks encrypted would be kept as it is.
func TestPageRefusesEncryptedLookingSecrets(t *testing.T) {
	path := writeConfig(t, "")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"opensearch.password": "enc:v1:00000000:AAAA"}})
	if err != nil || res.OK() || !strings.Contains(res.Fields["opensearch.password"], "how encrypted values look") {
		t.Errorf("%v %v", err, res.Fields)
	}
}
