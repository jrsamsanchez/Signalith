// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
)

// The page's own checks of single values, per setting.
func TestSettingChecks(t *testing.T) {
	for _, c := range []struct {
		key string
		v   any
		err string
	}{
		{"backup.snapshot_repository", "signalith-snapshots", ""},
		{"backup.snapshot_repository", "Bad Repo!", "repository"},
		{"backup.snapshot_at", "02:30", ""},
		{"backup.snapshot_at", "25:99", "must be a time of day"},
		{"backup.snapshot_timezone", "Europe/Berlin", ""},
		{"backup.snapshot_timezone", "Mars/Olympus", "time zone"},
		{"vulns.nvd_url", "https://nvd.internal/rest/json/cves/2.0", ""},
		{"vulns.nvd_url", "https://user:pw@nvd.internal/", "leave passwords and keys out of the address"},
		{"vulns.kev_url", "https://kev.internal/kev.json", ""},
		{"vulns.epss_url", "https://epss.internal/epss.csv.gz", ""},
		{"vulns.osv_url", "off", ""},
		{"assistant.url", "https://key:secret@api.example.com/v1", "leave passwords and keys out"},
		{"m365.tenant_id", "contoso.onmicrosoft.com", ""},
		{"m365.tenant_id", "not a guid", "or the tenant's domain"},
		{"m365.client_id", "11111111-2222-3333-4444-555555555555", ""},
		{"m365.client_id", "contoso.onmicrosoft.com", "is a GUID such as"},
		{"okta.key_id", "key_1-a", ""},
		{"okta.key_id", "bad key!", "the key ID is letters"},
		{"okta.client_id", "bad id!", "the client ID is letters and digits"},
		{"server.tls.names", []string{"siem.corp.local"}, ""},
		{"server.tls.names", []string{"bad name!"}, "isn't a host name"},
		{"server.tls.names", []string{"a b", "c d"}, "and “c d” aren't host names"},
		{"search.max_events", 10, ""}, // no check of its own
	} {
		err := mustLookup(t, c.key).Check(c.v)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s %v: %v, want %q", c.key, c.v, err, c.err)
		}
	}
}

func TestSentToAndCloudAddresses(t *testing.T) {
	c := Default()
	c.M365.TenantID, c.M365.ClientID = "contoso.onmicrosoft.com", "app"
	if got := mustLookup(t, "m365.client_secret").SentTo(c); got != "https://login.microsoftonline.com:443" {
		t.Errorf("m365 secret sent to %q", got)
	}
	if got := c.M365TokenURL(); got != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" {
		t.Errorf("M365TokenURL = %q", got)
	}
	c.M365.Cloud = "gcc_high"
	if got := c.M365APIURL(); got != "https://manage.office365.us" {
		t.Errorf("GCC High API = %q", got)
	}
	c.M365.Cloud = "mars"
	if got := c.M365APIURL(); got != "https://manage.office.com" {
		t.Errorf("unknown cloud API = %q", got)
	}
	if got := mustLookup(t, "vulns.nvd_api_key").SentTo(c); got != Origin(DefaultNVDURL) {
		t.Errorf("NVD key sent to %q", got)
	}
	c.Vulns.NVDURL = "https://nvd.internal:8443/x"
	if got := c.NVDURL(); got != "https://nvd.internal:8443/x" {
		t.Errorf("NVDURL = %q", got)
	}
	c.Okta.Domain = "example.okta.com"
	if got := mustLookup(t, "okta.private_key").SentTo(c); got != "https://example.okta.com:443" {
		t.Errorf("okta key sent to %q", got)
	}
	if got := mustLookup(t, "search.max_events").SentTo(c); got != "" {
		t.Errorf("a plain setting is sent to %q", got)
	}
}

func TestAddressSecrets(t *testing.T) {
	for _, c := range []struct {
		key  string
		v    any
		want bool
	}{
		{"vulns.nvd_url", "https://u:p@nvd/", true},
		{"vulns.nvd_url", "https://nvd/?apiKey=x", true},
		{"vulns.nvd_url", "https://nvd/?page=2", false},
		{"vulns.nvd_url", "%zz@", true},
		{"vulns.nvd_url", "user@host", true},
		{"vulns.nvd_url", "", false},
		{"search.max_events", "u:p@x", false},
		{"no.such.key", "u:p@x", false},
	} {
		if got := AddressHasSecret(c.key, c.v); got != c.want {
			t.Errorf("AddressHasSecret(%s, %v) = %v, want %v", c.key, c.v, got, c.want)
		}
	}
}

func TestWordingHelpers(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a and b"}, {[]string{"a", "b", "c"}, "a, b and c"},
	} {
		if got := joinWords(c.in); got != c.want {
			t.Errorf("joinWords(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if deref(nil, 7) != 7 || deref(intp(3), 7) != 3 {
		t.Error("deref")
	}
	// A problem that names only its own key, quoted value and all, is
	// worded for its field; one that is only the key keeps its words.
	if got := PlainProblem("server.listen", `server.listen "x" must be host:port`); got != "Must be host:port" {
		t.Errorf("PlainProblem = %q", got)
	}
	if got := PlainProblem("server.listen", "server.listen"); got != "server.listen" {
		t.Errorf("PlainProblem of only the key = %q", got)
	}
	if got := PlainProblem("x", "see search.max_events and no.such.key"); !strings.Contains(got, "“") {
		t.Errorf("PlainProblem naming another setting = %q", got)
	}
}

func TestFieldProblems(t *testing.T) {
	c := Default()
	if caScopeProblem(c) != "" && c.Server.TLS == nil {
		t.Error("no TLS section has a CA scope problem")
	}
	c.Server.TLS = &ServerTLS{CAScope: "loose"}
	if got := caScopeProblem(c); got != "Choose standard or strict." {
		t.Errorf("caScopeProblem = %q", got)
	}
	c.Server.TLS.CAScope = CAScopeStrict
	if got := caScopeProblem(c); got != "" {
		t.Errorf("strict = %q", got)
	}
	c.Assistant.Provider = assistant.OpenAI
	if got := modelProblem(c); !strings.Contains(got, "Enter the model's name") {
		t.Errorf("modelProblem = %q", got)
	}
	c.Assistant.Model = "gpt-4.1"
	if got := modelProblem(c); got != "" {
		t.Errorf("modelProblem with a model = %q", got)
	}
}

func TestValueOfUnknownKeys(t *testing.T) {
	c := Default()
	for _, k := range []string{"no.such", "server.listen.deeper", "server"} {
		if v := c.Value(k); v != nil && k != "server" {
			t.Errorf("Value(%q) = %v", k, v)
		}
	}
	if err := c.SetValue("no.such.key", "x"); err == nil {
		t.Error("SetValue of an unknown key")
	}
}

func TestConfiguredAdminPassword(t *testing.T) {
	c, err := loadYAML(t, "server:\n  listen: 127.0.0.1:8443\n")
	if err != nil {
		t.Fatal(err)
	}
	if m, k := c.ConfiguredAdminPassword(c.Auth.AdminPasswordHash); !m || !k {
		t.Errorf("the config's own hash = %v %v", m, k)
	}
	same, err := HashPassword("long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if m, k := c.ConfiguredAdminPassword(same); !m || !k {
		t.Errorf("another hash of the environment's password = %v %v", m, k)
	}
	other, err := HashPassword("another-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if m, k := c.ConfiguredAdminPassword(other); m || !k {
		t.Errorf("a hash of another password = %v %v", m, k)
	}
	// A config this process did not hash the password of cannot tell.
	plain := validConfig(t)
	if m, k := plain.ConfiguredAdminPassword(other); m || k {
		t.Errorf("a config's own hash only = %v %v", m, k)
	}
}

func TestLoadFileOnlyAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SettingsFileProblem() {
		t.Error("a file alone has a settings page problem")
	}
	if got := c.SettingsProblemKeys(); got == nil || len(got) != 0 {
		t.Errorf("SettingsProblemKeys = %#v, want an empty list", got)
	}
	if _, err := LoadFileOnly(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("LoadFileOnly of a missing file")
	}
}
