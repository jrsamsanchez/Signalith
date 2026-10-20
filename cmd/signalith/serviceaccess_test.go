// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// The Windows service account is given what the Settings page names too:
// the certificate and key files set there, those signalith.yaml names
// (used when the page's settings cannot start), and the folder of a
// settings file moved with SIGNALITH_SETTINGS_FILE, which it rewrites.
func TestServiceAccessCoversTheSettingsPage(t *testing.T) {
	for _, k := range []string{"SIGNALITH_STATE_DIR", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_USERS_FILE", "SIGNALITH_LISTEN"} {
		t.Setenv(k, "")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "Signalith")
	certs := filepath.Join(root, "certs")
	moved := filepath.Join(root, "settings")
	for _, d := range []string{dir, certs, moved} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	file := func(name string) string {
		p := filepath.Join(certs, name)
		if err := os.WriteFile(p, []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	yamlCert, yamlKey := file("yaml-cert.pem"), file("yaml-key.pem")
	pageCert, pageKey, pageCA := file("page-cert.pem"), file("page-key.pem"), file("page-ca.pem")
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	// Single-quoted, so Windows paths are taken as they are.
	body := "server:\n  tls_cert: '" + yamlCert + "'\n  tls_key: '" + yamlKey + "'\n" +
		"opensearch:\n  url: https://127.0.0.1:9200\nauth:\n  admin_password_hash: " + h + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(moved, "settings.yaml")
	t.Setenv("SIGNALITH_SETTINGS_FILE", settings)
	p := &config.PageSettings{}
	for k, v := range map[string]string{"server.tls_cert": pageCert, "server.tls_key": pageKey, "opensearch.ca_file": pageCA} {
		if err := p.Set(k, v, "admin", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.WritePageSettings(settings, p); err != nil {
		t.Fatal(err)
	}

	got := serviceAccess(path)
	for _, f := range []string{yamlCert, yamlKey, pageCert, pageKey, pageCA} {
		if !slices.Contains(got.read, f) {
			t.Errorf("read lacks %s: %v", f, got.read)
		}
	}
	if !slices.Contains(got.write, moved) || !slices.Contains(got.shown, moved) {
		t.Errorf("write lacks the settings file's folder %s: %v (shown %v)", moved, got.write, got.shown)
	}

	// Without the environment variable, the file is in the lookups folder,
	// inside the config folder: nothing more to grant.
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	got = serviceAccess(path)
	if slices.Contains(got.write, moved) || slices.Contains(got.read, pageCert) {
		t.Errorf("without the moved settings file: write %v read %v", got.write, got.read)
	}
}
