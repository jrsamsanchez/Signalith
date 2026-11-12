// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

func boolp(b bool) *bool { return &b }

func TestSmallAccessors(t *testing.T) {
	c := Default()
	if !c.ArchiveEncryption() || !c.KeepSignedInOn() || !c.Detections.RequireDispositionOn() {
		t.Error("the defaults: archives encrypted, keep signed in and dispositions required")
	}
	c.Retention.EncryptArchives, c.Auth.KeepSignedIn, c.Detections.RequireDisposition = boolp(false), boolp(false), boolp(false)
	if c.ArchiveEncryption() || c.KeepSignedInOn() || c.Detections.RequireDispositionOn() {
		t.Error("turned off, they stay on")
	}
	for in, want := range map[string]string{"": "off", " Admins ": "admins", "everyone": "everyone", "nobody": "off"} {
		c.Auth.MFARequired = in
		if got := c.MFARequiredMode(); got != want {
			t.Errorf("MFARequiredMode(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "keep", "REDACT": "redact", "drop": "drop", "other": "keep"} {
		c.Ingest.URLQuery = in
		if got := c.URLQueryMode(); got != want {
			t.Errorf("URLQueryMode(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"x-forwarded-for": "X-Forwarded-For", " Forwarded ": "Forwarded", "": ""} {
		if got := (Server{ClientHeader: in}).ClientAddressHeader(); got != want {
			t.Errorf("ClientAddressHeader(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (Syslog{}).SpoolBytes(); got != DefaultSyslogSpoolMB<<20 {
		t.Errorf("default spool = %d", got)
	}
	if got := (Syslog{SpoolMB: 3}).SpoolBytes(); got != 3<<20 {
		t.Errorf("3 MB spool = %d", got)
	}
	if got := (Detections{}).ContentUpdateURL(); got != DefaultContentURL {
		t.Errorf("default content URL = %q", got)
	}
	if got := (Detections{ContentURL: " https://mirror.example/c "}).ContentUpdateURL(); got != "https://mirror.example/c" {
		t.Errorf("content URL = %q", got)
	}
	c.Dashboards.StaleAfter = "nonsense"
	if c.StaleAfter() != 2*time.Hour {
		t.Errorf("StaleAfter of nonsense = %v", c.StaleAfter())
	}
	c.Dashboards.StaleAfter = "30m"
	if c.StaleAfter() != 30*time.Minute {
		t.Errorf("StaleAfter 30m = %v", c.StaleAfter())
	}
	if c.PublicURLDerived() {
		t.Error("a default config's public URL is derived before Validate")
	}
	if c.AdminHashFromFile() != "" {
		t.Error("no admin hash file, yet a hash from it")
	}
	if got := c.LDAPBindPasswordFromEnv(); got != "" {
		t.Errorf("LDAPBindPasswordFromEnv = %q", got)
	}
}

func TestFilesNextToTheConfig(t *testing.T) {
	dir := t.TempDir()
	c := DefaultFor(filepath.Join(dir, "signalith.yaml"))
	c.Lookups.Dir = "lookups"
	if got, want := c.GeoIPDir(), filepath.Join(dir, "lookups", "geoip"); got != want {
		t.Errorf("GeoIPDir = %q, want %q", got, want)
	}
	for _, f := range []struct {
		name string
		set  func(string)
		get  func() string
		def  string
	}{
		{"intel", func(s string) { c.Intel.FeedsFile = s }, c.IntelFeedsFile, "intel_feeds.yaml"},
		{"notify", func(s string) { c.Notify.File = s }, c.NotifyFile, "notifications.yaml"},
		{"response", func(s string) { c.Response.File = s }, c.ResponseFile, "response.yaml"},
		{"playbooks", func(s string) { c.Playbooks.File = s }, c.PlaybooksFile, "playbooks.yaml"},
	} {
		f.set("")
		if got, want := f.get(), filepath.Join(dir, "lookups", f.def); got != want {
			t.Errorf("%s default = %q, want %q", f.name, got, want)
		}
		f.set("custom.yaml")
		if got, want := f.get(), filepath.Join(dir, "custom.yaml"); got != want {
			t.Errorf("%s set = %q, want %q", f.name, got, want)
		}
	}
	c.OpenSearch.CRLFile = "os.crl"
	if got, want := c.OpenSearchCRLFile(), filepath.Join(dir, "os.crl"); got != want {
		t.Errorf("OpenSearchCRLFile = %q, want %q", got, want)
	}
	if got := c.SignInKeyFile(); filepath.Base(got) != "signin.key" {
		t.Errorf("SignInKeyFile = %q", got)
	}
}

func TestFindingSLATargets(t *testing.T) {
	c := Default()
	def := c.FindingSLA()
	if def.Respond["critical"] != 15*time.Minute || def.Resolve["low"] != 7*24*time.Hour {
		t.Errorf("default SLA = %+v", def)
	}
	c.Detections.SLA.CriticalRespond = "0"
	c.Detections.SLA.HighRespond = "2h"
	c.Detections.SLA.MediumResolve = "nonsense"
	c.Detections.SLA.LowResolve = "1000d"
	got := c.FindingSLA()
	if _, ok := got.Respond["critical"]; ok {
		t.Errorf("critical respond 0 still has a target: %v", got.Respond["critical"])
	}
	if got.Respond["high"] != 2*time.Hour {
		t.Errorf("high respond = %v", got.Respond["high"])
	}
	if got.Resolve["medium"] != 72*time.Hour || got.Resolve["low"] != 7*24*time.Hour {
		t.Errorf("invalid targets did not keep the default: %v", got.Resolve)
	}
	// Validate refuses the invalid ones by key.
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "detections.sla.medium_resolve") || !strings.Contains(err.Error(), "detections.sla.low_resolve") {
		t.Errorf("Validate = %v", err)
	}
}

func TestMetricsToken(t *testing.T) {
	c := Default()
	sum := sha256.Sum256([]byte("scrape-me"))
	c.Metrics.TokenSHA256 = hex.EncodeToString(sum[:])
	if !c.MetricsToken("scrape-me") {
		t.Error("the right token was refused")
	}
	if c.MetricsToken("wrong") || c.MetricsToken("") {
		t.Error("a wrong or empty token was taken")
	}
	c.Metrics.TokenSHA256 = "zz"
	if c.MetricsToken("scrape-me") {
		t.Error("a bad hash took a token")
	}
	c.Metrics.Allow = []string{"10.0.0.0/8", "nonsense", "192.0.2.1"}
	if l := c.MetricsAllowList(); len(l) != 2 || l[0].String() != "10.0.0.0/8" || l[1].String() != "192.0.2.1/32" {
		t.Errorf("MetricsAllowList = %v", l)
	}
}

func TestNotice(t *testing.T) {
	c := Default()
	if c.NoticeOn() || c.NoticeAgree() || c.NoticeTitle() != "Notice" {
		t.Error("a default config has a notice")
	}
	c.Auth.Notice.Text = " Authorized use only.\r\nUse is monitored. "
	c.Auth.Notice.Title = " Warning "
	c.Auth.Notice.Agree = true
	if !c.NoticeOn() || !c.NoticeAgree() || c.NoticeTitle() != "Warning" {
		t.Error("the notice is not on")
	}
	if got := c.NoticeText(); got != "Authorized use only.\nUse is monitored." {
		t.Errorf("NoticeText = %q", got)
	}
	for _, c := range []struct {
		s         string
		multiline bool
		err       string
	}{
		{"line\nbreak\ttab", true, ""},
		{"line\nbreak", false, "line break"},
		{"bell\a", true, "control character"},
		{"bad \xff", true, "isn't valid text"},
		{"rtl ‮", true, "direction"},
		{"zero​width", true, "invisible character U+200B"},
		{"emoji ‍ joiner", false, ""},
	} {
		err := noticeChars(c.s, c.multiline)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("noticeChars(%q, %v) = %v, want %q", c.s, c.multiline, err, c.err)
		}
	}
	if err := checkNoticeText(strings.Repeat("x", NoticeTextMax+1)); err == nil || !strings.Contains(err.Error(), "keep the notice") {
		t.Errorf("a long notice = %v", err)
	}
}

func TestCheckPasswordUser(t *testing.T) {
	c := validConfig(t)
	if c.CheckPassword("someone-else", "correct horse") {
		t.Error("another user name signed in")
	}
	if !c.CheckPassword(" "+strings.ToUpper(c.Auth.AdminUser)+" ", "correct horse") {
		t.Error("the admin, in capitals, was refused")
	}
}

func TestHTTPSForHTTP(t *testing.T) {
	for in, want := range map[string]string{
		"http://siem.example.com":      "https://siem.example.com:80",
		"http://siem.example.com:8080": "https://siem.example.com:8080",
		"http://[::1":                  "http://[::1",
	} {
		if got := httpsForHTTP(in); got != want {
			t.Errorf("httpsForHTTP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLDAPCACertFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	c := DefaultFor(path)
	c.Auth.LDAP = &users.LDAPSettings{URL: "ldaps://dc.example.com", CACertFile: "ca.pem"}
	s, err := c.LDAPFromFile()
	if err != nil {
		t.Fatalf("LDAPFromFile: %v", err)
	}
	if s == nil || s.CACert != pem {
		t.Errorf("CA cert = %+v", s)
	}
	c.Auth.LDAP.CACert = pem
	if _, err := c.LDAPFromFile(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both CA settings = %v", err)
	}
	c.Auth.LDAP.CACert = ""
	c.Auth.LDAP.CACertFile = "missing.pem"
	if _, err := c.LDAPFromFile(); err == nil || !strings.Contains(err.Error(), "auth.ldap.ca_cert_file") {
		t.Errorf("a missing CA file = %v", err)
	}
}
