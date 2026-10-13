package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestCAScopeSetting(t *testing.T) {
	set, ok := Lookup("server.tls.ca_scope")
	if !ok || set.Scope != ScopeServer || set.Section != "https" || set.Restart || set.Type != TypeChoice || set.EmptyMeans != CAScopeStandard {
		t.Fatalf("registry entry %+v", set)
	}
	if !slices.Contains(LeafKeys(), "server.tls.ca_scope") || ScopeOf("server.tls.ca_scope") != ScopeServer {
		t.Error("server.tls.ca_scope is not a leaf key with ScopeServer")
	}
	// The registry entry follows server.tls.names.
	i := slices.IndexFunc(Registry, func(s Setting) bool { return s.Key == "server.tls.names" })
	if i < 0 || Registry[i+1].Key != "server.tls.ca_scope" {
		t.Error("server.tls.ca_scope is not right after server.tls.names")
	}

	// Empty means standard, in a file with or without server.tls.
	for _, extra := range []string{"", "server:\n  tls:\n    mode: auto\n"} {
		c, err := Load(writeConfig(t, extra))
		if err != nil {
			t.Fatal(err)
		}
		if c.Value("server.tls.ca_scope") != CAScopeStandard || c.Server.CAScope() != CAScopeStandard {
			t.Errorf("%q: ca_scope %v", extra, c.Value("server.tls.ca_scope"))
		}
	}
	c, err := Load(writeConfig(t, "server:\n  tls:\n    ca_scope: Strict\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.CAScope() != CAScopeStrict {
		t.Errorf("scope %s", c.Server.CAScope())
	}
	// Anything else is a problem, worded like the other choices.
	_, err = Load(writeConfig(t, "server:\n  tls:\n    ca_scope: wide\n"))
	if err == nil || !strings.Contains(err.Error(), `server.tls.ca_scope "wide" must be standard`) {
		t.Errorf("bad scope: %v", err)
	}
	path := writeConfig(t, "")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"server.tls.ca_scope": "wide"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.Fields["server.tls.ca_scope"] != "Choose standard or strict." {
		t.Errorf("page problem: %v %v", res.Fields, res.Problems)
	}
	// Saved on the page, it changes only itself and applies at once.
	res, err = CheckEdit(path, Edit{Values: map[string]any{"server.tls.ca_scope": "strict"}})
	if err != nil || !res.OK() {
		t.Fatalf("%v %v", err, res.Fields)
	}
	if !slices.Equal(res.Changed, []string{"server.tls.ca_scope"}) || res.Config.Server.CAScope() != CAScopeStrict {
		t.Errorf("changed %v scope %s", res.Changed, res.Config.Server.CAScope())
	}
	// Copying it to the running config never shares server.tls.
	run, _ := Load(path)
	before := run.Server.TLS
	if err := run.CopyValue("server.tls.ca_scope", res.Config); err != nil {
		t.Fatal(err)
	}
	if run.Server.CAScope() != CAScopeStrict || (before != nil && before.CAScope != "") {
		t.Errorf("copy: %v, before %v", run.Server.TLS, before)
	}
}

func TestPublicAdminPassword(t *testing.T) {
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "change-me-please")
	c, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !c.PublicAdminPassword() {
		t.Error("the example password is not reported")
	}
	// A password set with signalith passwd replaces it.
	h, _ := HashPassword("a-better-password")
	if err := os.MkdirAll(c.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.AdminHashFile(), []byte(h), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicAdminPassword() {
		t.Error("reported after signalith passwd")
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "another-password")
	os.Remove(c.AdminHashFile())
	c, _ = Load(c.Path())
	if c.PublicAdminPassword() {
		t.Error("another password is reported")
	}
}

func TestSecretInventory(t *testing.T) {
	t.Setenv("SIGNALITH_MASTER_KEY_FILE", "")
	path := writeConfig(t, "opensearch:\n  password: plain-sentinel\nassistant:\n  provider: anthropic\n  api_key: other-sentinel\n")
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(filepath.Dir(path), "state"))
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	list, errs := c.SecretInventory()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var fields []string
	for _, s := range list {
		fields = append(fields, s.Setting)
		if s.File != path || s.State != secrets.Plain {
			t.Errorf("%+v", s)
		}
	}
	slices.Sort(fields)
	if !slices.Equal(fields, []string{"assistant.api_key", "opensearch.password"}) {
		t.Errorf("fields %v", fields)
	}
	// The files are the ones signalith secrets goes by.
	var paths []string
	for _, f := range c.SecretFiles() {
		paths = append(paths, f.Path)
	}
	if !slices.Equal(paths, []string{path, c.DirectoryFile(), c.IntelFeedsFile(), c.NotifyFile(), c.ResponseFile(), c.SettingsFile()}) {
		t.Errorf("files %v", paths)
	}
}
