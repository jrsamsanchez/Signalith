// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// More of the settings Validate checks, each named with how to fix it.
func TestValidateMoreRefusals(t *testing.T) {
	for _, c := range []struct {
		change func(c *Config)
		want   string
	}{
		{func(c *Config) { c.Auth.Notice.Text = strings.Repeat("x", NoticeTextMax+1) }, "auth.notice.text: keep the notice"},
		{func(c *Config) {
			c.Auth.Notice.Text = "ok"
			c.Auth.Notice.Title = strings.Repeat("t", NoticeTitleMax+1)
		}, "auth.notice.title: keep the title"},
		{func(c *Config) { c.Auth.Notice.Agree = true }, "auth.notice.agree: write the notice"},
		{func(c *Config) { c.Metrics.TokenSHA256 = "nothex" }, "metrics.token_sha256: must be the SHA-256"},
		{func(c *Config) { c.Metrics.Enabled = true }, "metrics.token_sha256: create a scrape token"},
		{func(c *Config) { c.Metrics.Allow = []string{"not-an-address"} }, "metrics.allow: "},
		{func(c *Config) { c.Syslog.SpoolMB = -1 }, "syslog.spool_mb -1 must be"},
		{func(c *Config) { c.Server.ClientHeader = "x-real-ip" }, "server.client_header \"x-real-ip\""},
		{func(c *Config) { c.Dashboards.StaleAfter = "1m" }, "dashboards.stale_after"},
		{func(c *Config) {
			c.Auth.LDAP = &users.LDAPSettings{URL: "ldaps://dc", CACert: "x", CACertFile: "ca.pem"}
		}, "set ca_cert or ca_cert_file, not both"},
	} {
		cfg := validConfig(t)
		c.change(cfg)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Validate = %v, want %q", err, c.want)
		}
	}
	// No stale_after is the default, 2h.
	cfg := validConfig(t)
	cfg.Dashboards.StaleAfter = ""
	if err := cfg.Validate(); err != nil || cfg.Dashboards.StaleAfter != "2h" {
		t.Errorf("no stale_after = %q %v", cfg.Dashboards.StaleAfter, err)
	}
}

func TestMoreWarnings(t *testing.T) {
	has := func(w []string, s string) bool {
		for _, x := range w {
			if strings.Contains(x, s) {
				return true
			}
		}
		return false
	}
	c := validConfig(t)
	c.Vulns.NVDURL, c.Vulns.NVDAPIKey = "http://nvd.internal/", "key"
	c.Vulns.OpenVASAddress = "openvas:9390"
	c.Server.ProxyProtocol = true
	w := c.Warnings()
	for _, want := range []string{"vulns.nvd_url is plain http", "vulns.openvas_address is set without a user name",
		"PROXY protocol is on"} {
		if !has(w, want) {
			t.Errorf("no warning %q in %v", want, w)
		}
	}
	c = validConfig(t)
	c.Server.TrustedProxies = []string{"0.0.0.0/0"}
	c.Server.ClientHeader = ClientHeaderXFF
	if w := c.Warnings(); !has(w, "which trusts every address") {
		t.Errorf("trusting every address: %v", w)
	}
	c.Vulns.NVDURL = "http://127.0.0.1:8080/"
	c.Vulns.NVDAPIKey = "key"
	if w := c.Warnings(); has(w, "vulns.nvd_url is plain http") {
		t.Errorf("a loopback NVD warns: %v", w)
	}
	// OpenSearch's problems, with the address's password moved out.
	c = validConfig(t)
	c.OpenSearch.URL = "https://u:p@os:9200"
	_ = c.OpenSearchProblems()
	if c.OpenSearch.URL != "https://u:p@os:9200" {
		t.Error("OpenSearchProblems changed the config")
	}
	c.OpenSearch.URL = "ftp://os"
	if p := c.OpenSearchProblems(); len(p) == 0 {
		t.Error("an ftp OpenSearch address has no problem")
	}
}

func TestDeepCopyShares(t *testing.T) {
	type inner struct {
		List []string
		Map  map[string]int
		Ptr  *int
		Nil  []int
		NilM map[string]int
		NilP *int
	}
	n := 1
	src := inner{List: []string{"a"}, Map: map[string]int{"k": 1}, Ptr: &n}
	cp := deepCopy(reflect.ValueOf(src)).Interface().(inner)
	cp.List[0], cp.Map["k"], *cp.Ptr = "b", 2, 3
	if src.List[0] != "a" || src.Map["k"] != 1 || n != 1 {
		t.Errorf("the copy shares with the source: %+v %d", src, n)
	}
	if cp.Nil != nil || cp.NilM != nil || cp.NilP != nil {
		t.Errorf("nil fields copied as values: %+v", cp)
	}
}

func TestRecordFirstPasswordNextTo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := RecordFirstPasswordNextTo(path, "hash-one"); err != nil {
		t.Fatal(err)
	}
	fp, err := ReadFirstPassword(dir)
	if err != nil || fp.Hash != "hash-one" {
		t.Fatalf("ReadFirstPassword = %+v %v", fp, err)
	}
	// The same hash again keeps the note.
	if err := RecordFirstPasswordNextTo(path, "hash-one"); err != nil {
		t.Fatal(err)
	}
	if err := RecordFirstPasswordNextTo(path, "hash-two"); err != nil {
		t.Fatal(err)
	}
	if fp, _ := ReadFirstPassword(dir); fp.Hash != "hash-two" {
		t.Errorf("the note was not replaced: %+v", fp)
	}
	c := DefaultFor(path)
	if file, _ := c.InitialPasswordFile(); file == "" {
		t.Error("no initial password file")
	}
	if !c.FirstPasswordChanged().IsZero() {
		t.Error("a new config's first password changed")
	}
}
