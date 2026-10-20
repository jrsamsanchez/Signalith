// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The install line names a new address for the certificate to add, the
// new certificate authority while one is being switched to, and "dev"
// for a build without a version; an address that is not one is refused.
func TestManagedAgentInstallLineMore(t *testing.T) {
	ts, s := newSensorServer(t)
	install := func(server string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "GET", "/api/agent/install?"+url.Values{"server": {server}}.Encode(), "", "admin", adminPass, nil)
		return code, out
	}
	if code, out := install("https://exa mple.com"); code != http.StatusBadRequest || out["field"] != "server" {
		t.Errorf("not an address: %d %v", code, out)
	}
	// Its own CA signs only this server's names and private addresses.
	if code, out := install("https://agents.example.org:8443"); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "can't include agents.example.org") {
		t.Errorf("a name the CA may not sign: %d %v", code, out)
	}
	if err := s.TLS.Prepare(s.conf().Server.CAScope()); err != nil {
		t.Fatal(err)
	}
	s.Version = ""
	code, out := install("https://10.1.2.3:8443")
	if code != http.StatusOK {
		t.Fatalf("install: %d %v", code, out)
	}
	if out["add_name"] != "10.1.2.3" {
		t.Errorf("add_name %v", out["add_name"])
	}
	if out["next_ca_sha256"] != sha256Hex(s.TLS.Next().Fingerprint) {
		t.Errorf("next CA %v", out["next_ca_sha256"])
	}
	if line, _ := out["linux"].(string); !strings.Contains(line, "--version dev") {
		t.Errorf("version: %s", line)
	}
}

// With HTTPS off here (a proxy in front serves it), the line pins no
// certificate authority of this server's.
func TestManagedAgentInstallLineWithoutHTTPS(t *testing.T) {
	ts, s := newSensorServer(t)
	s.Config.Server.TLS.Mode = "off"
	code, out, _ := call(t, ts, "GET", "/api/agent/install?server=https://siem.example.com:8443", "", "admin", adminPass, nil)
	line, _ := out["linux"].(string)
	if code != http.StatusOK || strings.Contains(line, "--ca-sha256") || (out["ca_sha256"] != nil && out["ca_sha256"] != "") ||
		!strings.Contains(line, "--from https://siem.example.com:7779") {
		t.Errorf("without HTTPS: %d %v", code, out)
	}
}
