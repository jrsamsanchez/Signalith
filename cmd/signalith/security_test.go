// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// securityConfig writes a config file for a server whose OpenSearch is
// fake, with its folders in a temporary one, and returns its path.
func securityConfig(t *testing.T, extra string) string {
	t.Helper()
	saved, savedBL := readServiceSettings, saveBitLocker
	t.Cleanup(func() { readServiceSettings, saveBitLocker = saved, savedBL })
	readServiceSettings = func() *serviceSettings { return nil }
	// A test run as Administrator on Windows would otherwise ask BitLocker
	// and save its answer in the test's state folder.
	saveBitLocker = func(context.Context, string, io.Writer) {}
	for _, k := range []string{"SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_INGEST_TOKEN_FILE", "SIGNALITH_NODE_NAME"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	fake := ostest.New(t)
	fake.Secure(&ostest.Account{User: "signalith", Password: "os-pass-0123456789", Roles: []string{"signalith_server"}})
	h, _ := config.HashPassword("s3cret-pass-for-tests")
	body := "auth:\n  admin_password_hash: " + h + "\ningest:\n  tokens: [tok-0123456789abcdef]\n" +
		"opensearch:\n  url: " + fake.URL + "\n  username: signalith\n  password: os-pass-0123456789\n" + extra
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecurityCommand(t *testing.T) {
	// HTTPS off: at risk.
	path := securityConfig(t, "server:\n  listen: 0.0.0.0:18960\n  tls:\n    mode: \"off\"\n")
	var out, note bytes.Buffer
	code, err := runSecurity(path, false, &out, &note)
	if err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if code != exitAtRisk || !strings.HasPrefix(text, "Signalith security report for ") || !strings.Contains(text, "\nFix first\n1. At risk: HTTPS\n") {
		t.Errorf("exit %d:\n%s", code, text)
	}
	for _, secret := range []string{"os-pass-0123456789", "tok-0123456789abcdef", "s3cret-pass-for-tests"} {
		if strings.Contains(text, secret) {
			t.Errorf("the report holds %q", secret)
		}
	}
	// The CLI never claims what only the server sees: no sign-ins over
	// plain HTTP is not "none".
	if strings.Contains(text, "No one signed in") {
		t.Error(text)
	}

	// As JSON: the same report, without what only the server sees.
	out.Reset()
	code, err = runSecurity(path, true, &out, &note)
	if err != nil || code != exitAtRisk {
		t.Fatalf("json: %d %v", code, err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if m["checks"] == nil || m["fix_first"].([]any)[0] != "transit.https" {
		t.Errorf("json %v", m["fix_first"])
	}
	for _, k := range []string{"others", "seen_names", "refusals"} {
		if strings.Contains(out.String(), `"`+k+`"`) {
			t.Errorf("the CLI's JSON has %s", k)
		}
	}
}

func TestSecurityCommandNothingAtRisk(t *testing.T) {
	path := securityConfig(t, "")
	var out, note bytes.Buffer
	code, err := runSecurity(path, false, &out, &note)
	if err != nil {
		t.Fatal(err)
	}
	if code != exitNothingAtRisk {
		t.Errorf("exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "Summary: ") || strings.Contains(out.String(), "At risk:") {
		t.Error(out.String())
	}
}

func TestSecurityCommandReadsTheCertificate(t *testing.T) {
	path := securityConfig(t, "server:\n  tls:\n    mode: auto\n    ca_scope: strict\n")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// The server made its certificate authority, strict as set.
	o, _ := certOptions(c)
	if o.Scope != "strict" {
		t.Fatalf("scope %q", o.Scope)
	}
	if _, err := tlsauto.New(o); err != nil {
		t.Fatal(err)
	}
	var out, note bytes.Buffer
	if _, err := runSecurity(path, true, &out, &note); err != nil {
		t.Fatal(err)
	}
	var m struct {
		CA struct {
			Current struct{ Scope string } `json:"current"`
		} `json:"ca"`
	}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || m.CA.Current.Scope != "strict" {
		t.Errorf("%v %+v\n%s", err, m, out.String())
	}
	// The CLI changes nothing in the certificate folder.
	before, _ := os.ReadDir(c.TLSDir())
	runSecurity(path, false, &out, &note)
	after, _ := os.ReadDir(c.TLSDir())
	if len(before) != len(after) {
		t.Errorf("%d files before, %d after", len(before), len(after))
	}
}

// The scope is for a certificate authority made on first start only, so
// it leaves the certificate in use alone at a restart in place.
func TestCertKeyLeavesOutTheScope(t *testing.T) {
	a := tlsauto.Options{Dir: "/x", Names: []string{"siem"}, Scope: "standard"}
	b := a
	b.Scope = "strict"
	if certKey(a) != certKey(b) {
		t.Error("a change of scope would make a new certificate")
	}
}

func TestSecurityCommandNeedsRights(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs an account that can be refused a file")
	}
	path := securityConfig(t, "")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	var out, note bytes.Buffer
	code, err := runSecurity(path, false, &out, &note)
	if code != 1 || err == nil || !strings.HasSuffix(err.Error(), needAdmin) {
		t.Errorf("%d %v", code, err)
	}
}
