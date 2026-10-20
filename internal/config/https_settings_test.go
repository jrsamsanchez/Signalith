// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The HTTPS settings on the Settings page follow the same rules as in
// signalith.yaml, and a change made there changes only itself, even in a
// file from before HTTPS was the default.
func TestHTTPSSettingsOnThePage(t *testing.T) {
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: http://siem.lan:8080\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// A file without server.tls: HTTPS auto, plain-text agents allowed,
	// the http:// address read as https:// but shown as it is set.
	for key, want := range map[string]any{
		"server.tls.mode": TLSAuto, "server.tls.plaintext_ingest": "allow", "server.public_url": "http://siem.lan:8080",
	} {
		if got := c.Value(key); got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if c.Server.PublicURL != "https://siem.lan:8080" {
		t.Errorf("public_url in use %s", c.Server.PublicURL)
	}
	proxy := netip.MustParseAddr("10.0.0.5")
	if !c.Server.LegacyProxy(proxy) {
		t.Error("a file from before HTTPS was the default trusts a proxy on the local network")
	}

	// An https:// address saved on the page does not turn HTTPS off, as
	// the same address in such a file would (a proxy added HTTPS then).
	res, err := CheckEdit(path, Edit{By: "alice", Values: map[string]any{"server.public_url": "https://siem.example.com:8080"}})
	if err != nil || !res.OK() {
		t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
	}
	if !reflect.DeepEqual(res.Changed, []string{"server.public_url"}) {
		t.Errorf("changed %v", res.Changed)
	}
	if got := res.Config.Server; got.TLSMode() != TLSAuto || !got.PlaintextIngest() || !got.LegacyProxy(proxy) {
		t.Errorf("mode %s plaintext %v legacy proxy %v", got.TLSMode(), got.PlaintextIngest(), got.LegacyProxy(proxy))
	}
	if len(res.Page.Settings) != 1 {
		t.Errorf("page holds more than the change: %v", res.Page.Settings)
	}

	// Refusing plain-text agents changes only that.
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"server.tls.plaintext_ingest": "deny"}})
	if !res.OK() || res.Config.Server.PlaintextIngest() || res.Config.Server.TLSMode() != TLSAuto {
		t.Errorf("plaintext deny: %v %v", res.Fields, res.Config.Server.TLS)
	}
	// Listing a proxy ends trusting the local network.
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"server.trusted_proxies": []any{"10.0.0.9"}}})
	if !res.OK() || res.Config.Server.LegacyProxy(proxy) || !res.Config.Server.TrustsProxy(netip.MustParseAddr("10.0.0.9")) {
		t.Errorf("trusted proxies: %v", res.Fields)
	}

	// Cross-field rules, as Validate has them, by field.
	dir := t.TempDir()
	cert, key := writeTestPair(t, dir)
	for name, tc := range map[string]struct {
		values map[string]any
		want   map[string]string
	}{
		"files without files": {map[string]any{"server.tls.mode": "files"},
			map[string]string{"server.tls.mode": "Enter your certificate and key files", "server.tls_cert": "Enter the full path"}},
		"files with auto": {map[string]any{"server.tls_cert": cert, "server.tls_key": key},
			map[string]string{"server.tls.mode": "used only with your own certificate files", "server.tls_cert": "Used only when HTTPS is set to your own certificate files"}},
		"files with off": {map[string]any{"server.tls.mode": "off", "server.tls_cert": cert, "server.tls_key": key},
			map[string]string{"server.tls_key": "Used only when HTTPS is set to your own certificate files"}},
		"missing files": {map[string]any{"server.tls.mode": "files", "server.tls_cert": dir + "/nope.pem", "server.tls_key": key},
			map[string]string{"server.tls_cert": "can't be used"}},
		"bad names": {map[string]any{"server.tls.names": []any{"siem.lan", "not a name"}},
			map[string]string{"server.tls.names": "“not a name” isn't a host name or IP address"}},
		"bad proxies": {map[string]any{"server.trusted_proxies": []any{"proxy"}},
			map[string]string{"server.trusted_proxies": "isn't an IP address"}},
		"bad choice": {map[string]any{"server.tls.mode": "sometimes"},
			map[string]string{"server.tls.mode": "Choose"}},
	} {
		res, err := CheckEdit(path, Edit{Values: tc.values})
		if err != nil {
			t.Fatal(err)
		}
		if res.OK() {
			t.Errorf("%s: accepted", name)
		}
		for k, want := range tc.want {
			if !strings.Contains(res.Fields[k], want) {
				t.Errorf("%s: %s = %q, want %q (all: %v)", name, k, res.Fields[k], want, res.Fields)
			}
		}
	}

	// Your own files, all three together.
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key}})
	if !res.OK() {
		t.Fatalf("files: %v %v", res.Fields, res.Problems)
	}
	if got := res.Config.Server.TLSMode(); got != TLSFiles {
		t.Errorf("mode %s", got)
	}
	if err := WritePageSettings(res.Config.SettingsFile(), res.Page); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil || c.SettingsProblem() != "" {
		t.Fatalf("%v %s", err, c.SettingsProblem())
	}
	if c.Server.TLSMode() != TLSFiles || c.Source("server.tls.mode").Kind != FromPage || c.Source("server.tls_cert").Kind != FromPage {
		t.Errorf("mode %s from %v", c.Server.TLSMode(), c.Source("server.tls.mode"))
	}
	// Off with a listen address others reach is allowed, with a warning.
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"server.tls.mode": "off"}, Reset: []string{"server.tls_cert", "server.tls_key"}})
	if !res.OK() || res.Config.Server.HTTPS() {
		t.Fatalf("off: %v %v", res.Fields, res.Problems)
	}
	if !slices.ContainsFunc(res.Config.Warnings(), func(w string) bool { return strings.Contains(w, "HTTPS is off") }) {
		t.Errorf("no warning for HTTPS off: %v", res.Config.Warnings())
	}
}

// An http:// public address saved on the page while HTTPS is on is read
// as https://, and the warning says to change it there.
func TestHTTPPublicURLFromThePage(t *testing.T) {
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8443\n  tls:\n    mode: auto\n")
	writePage(t, path, "settings:\n  server.public_url:\n    value: http://siem.lan:8443\n")
	c, err := Load(path)
	if err != nil || c.SettingsProblem() != "" {
		t.Fatalf("%v %s", err, c.SettingsProblem())
	}
	if c.Server.PublicURL != "https://siem.lan:8443" || c.Value("server.public_url") != "http://siem.lan:8443" {
		t.Errorf("in use %s, shown %v", c.Server.PublicURL, c.Value("server.public_url"))
	}
	if !slices.ContainsFunc(c.Warnings(), func(w string) bool {
		return strings.Contains(w, "Change it to https://siem.lan:8443 on the Settings page")
	}) {
		t.Errorf("warnings %v", c.Warnings())
	}
	// Validating again changes nothing.
	before, warnings := c.Server.PublicURL, c.Warnings()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != before || !reflect.DeepEqual(c.Warnings(), warnings) || c.Value("server.public_url") != "http://siem.lan:8443" {
		t.Errorf("second Validate: %s %v", c.Server.PublicURL, c.Warnings())
	}
	// HTTPS off: the http:// address is used as it is.
	res, _ := CheckEdit(path, Edit{Values: map[string]any{"server.tls.mode": "off", "server.trusted_proxies": []any{"127.0.0.1"}}})
	if !res.OK() || res.Config.Server.PublicURL != "http://siem.lan:8443" {
		t.Errorf("off: %v %s", res.Fields, res.Config.Server.PublicURL)
	}
}

// Copying an HTTPS setting into a copy of a config, as applying settings
// at once does, leaves the original alone.
func TestCopyValueDoesNotShareTLS(t *testing.T) {
	path := writeConfig(t, "server:\n  tls:\n    mode: auto\n    plaintext_ingest: deny\n    names: [a.lan]\n")
	cur, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	writePage(t, path, "settings:\n  server.tls.plaintext_ingest:\n    value: allow\n  server.tls.names:\n    value: [b.lan]\n")
	saved, err := Load(path)
	if err != nil || saved.SettingsProblem() != "" {
		t.Fatal(err, saved.SettingsProblem())
	}
	next := *cur
	for _, k := range []string{"server.tls.plaintext_ingest", "server.tls.names"} {
		if err := next.CopyValue(k, saved); err != nil {
			t.Fatal(err)
		}
	}
	if !next.Server.PlaintextIngest() || !reflect.DeepEqual(next.Server.TLSNames(), []string{"b.lan"}) {
		t.Errorf("copy: %v %v", next.Server.PlaintextIngest(), next.Server.TLSNames())
	}
	if cur.Server.PlaintextIngest() || !reflect.DeepEqual(cur.Server.TLSNames(), []string{"a.lan"}) {
		t.Errorf("the original changed: %v %v", cur.Server.PlaintextIngest(), cur.Server.TLSNames())
	}
	if !SameValue(saved, &next, "server.tls.plaintext_ingest") || SameValue(cur, &next, "server.tls.plaintext_ingest") {
		t.Error("SameValue")
	}
}

// A secret read from a file named in the environment (the Docker quick
// start's way) is set by the environment: the page shows it locked, with
// the variable that sets it, and cannot change it.
func TestSecretFilesLockTheirSettings(t *testing.T) {
	dir := t.TempDir()
	put := func(name, text string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	path := writeConfig(t, "opensearch:\n  url: https://os.example:9200\nassistant:\n  provider: anthropic\n")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD_FILE", put("os", "os pass\n"))
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY_FILE", put("key", "sk-ant-from-file\n"))
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for key, env := range map[string]string{"opensearch.password": "SIGNALITH_OPENSEARCH_PASSWORD_FILE", "assistant.api_key": "SIGNALITH_ASSISTANT_API_KEY_FILE"} {
		if got := c.Source(key); got.Kind != FromEnv || got.Env != env {
			t.Errorf("%s source %+v", key, got)
		}
		res, err := CheckEdit(path, Edit{Values: map[string]any{key: "typed on the page"}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Fields[key], env) {
			t.Errorf("%s on the page: %q", key, res.Fields[key])
		}
	}
	if c.OpenSearch.Password != "os pass" {
		t.Errorf("password %q", c.OpenSearch.Password)
	}
}

// Setting the HTTPS mode aside takes the certificate files saved with it
// along, so what is left still validates and the next start uses the
// page's other settings.
func TestSetAsideAlong(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir())
	save := func(path string, values map[string]any) {
		t.Helper()
		res, err := CheckEdit(path, Edit{By: "alice", Values: values})
		if err != nil || !res.OK() {
			t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
		}
		if err := WritePageSettings(res.Config.SettingsFile(), res.Page); err != nil {
			t.Fatal(err)
		}
	}
	setAside := func(path string, keys []string) *Config {
		t.Helper()
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarkRefused(c.SettingsFile(), keys, "nobody confirmed it"); err != nil {
			t.Fatal(err)
		}
		c, err = Load(path)
		if err != nil || c.SettingsProblem() != "" {
			t.Fatalf("after setting %v aside: %v %s", keys, err, c.SettingsProblem())
		}
		return c
	}

	// signalith.yaml says off; the page says files, with the files.
	path := writeConfig(t, "server:\n  tls:\n    mode: off\n")
	save(path, map[string]any{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key, "search.max_events": float64(777)})
	got := SetAsideAlong(path, []string{"server.tls.mode"})
	slices.Sort(got)
	if !reflect.DeepEqual(got, []string{"server.tls.mode", "server.tls_cert", "server.tls_key"}) {
		t.Errorf("off, files on the page: %v", got)
	}
	if c := setAside(path, got); c.Server.HTTPS() || c.Search.MaxEvents != 777 {
		t.Errorf("https %v, max_events %d", c.Server.HTTPS(), c.Search.MaxEvents)
	}
	// Nothing to take along.
	if got := SetAsideAlong(path, []string{"search.max_events"}); !reflect.DeepEqual(got, []string{"search.max_events"}) {
		t.Errorf("max_events: %v", got)
	}

	// The other way: files in signalith.yaml, auto on the page with the
	// files cleared, and a certificate that cannot be made.
	path = writeConfig(t, "server:\n  tls_cert: '"+cert+"'\n  tls_key: '"+key+"'\n  tls:\n    mode: files\n")
	save(path, map[string]any{"server.tls.mode": "auto", "server.tls_cert": "", "server.tls_key": "", "search.max_events": float64(778)})
	got = SetAsideAlong(path, []string{"server.tls.mode", "server.tls.names"})
	slices.Sort(got)
	if !reflect.DeepEqual(got, []string{"server.tls.mode", "server.tls.names", "server.tls_cert", "server.tls_key"}) {
		t.Errorf("files, auto on the page: %v", got)
	}
	if c := setAside(path, got); c.Server.TLSMode() != TLSFiles || c.Search.MaxEvents != 778 {
		t.Errorf("mode %s, max_events %d", c.Server.TLSMode(), c.Search.MaxEvents)
	}
}

// A settings file from before the HTTPS mode existed, where setting your
// own certificate on the page was how HTTPS was turned on, still loads on
// a signalith.yaml from then: as files mode, the way the same settings in
// signalith.yaml are read, and with the page's other settings.
func TestOlderPageCertificateMeansFiles(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir())
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n")
	quoted := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	writePage(t, path, "settings:\n"+
		"  server.tls_cert:\n    value: "+quoted(cert)+"\n    changed_by: alice\n"+
		"  server.tls_key:\n    value: "+quoted(key)+"\n    changed_by: alice\n"+
		"  search.max_events:\n    value: 777\n    changed_by: alice\n")
	c, err := Load(path)
	if err != nil || c.SettingsProblem() != "" {
		t.Fatalf("%v %s", err, c.SettingsProblem())
	}
	if c.Server.TLSMode() != TLSFiles || c.Server.PlaintextIngest() || c.Search.MaxEvents != 777 {
		t.Errorf("mode %s, plain-text agents %v, max_events %d", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Search.MaxEvents)
	}
	if got, _ := c.TLSFiles(); got != cert {
		t.Errorf("certificate %s", got)
	}
	// Changing another HTTPS setting on the page keeps it so.
	res, err := CheckEdit(path, Edit{Values: map[string]any{"server.tls.names": []any{"siem.lan"}}})
	if err != nil || !res.OK() || res.Config.Server.TLSMode() != TLSFiles {
		t.Errorf("edit: %v %v %s", err, res.Fields, res.Config.Server.TLSMode())
	}
	// A mode saved on the page with them decides, as before.
	writePage(t, path, "settings:\n"+
		"  server.tls.mode:\n    value: off\n"+
		"  server.tls_cert:\n    value: "+quoted(cert)+"\n"+
		"  server.tls_key:\n    value: "+quoted(key)+"\n")
	if c, err := Load(path); err != nil || !strings.Contains(c.SettingsProblem(), "server.tls.mode is off") {
		t.Errorf("mode off with files: %v %q", err, c.SettingsProblem())
	}
}
