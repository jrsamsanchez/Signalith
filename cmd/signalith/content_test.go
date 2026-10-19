// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/content"
)

// contentConfig writes a signalith.yaml whose detections folder is in a
// temporary folder, and returns its path and the content folder.
func contentConfig(t *testing.T) (path, dir string) {
	t.Helper()
	noServiceSettings(t)
	t.Setenv("SIGNALITH_DETECTIONS_DIR", "")
	d := t.TempDir()
	path = filepath.Join(d, "signalith.yaml")
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	body := "auth:\n  admin_password_hash: " + h + "\ndetections:\n  dir: " + filepath.ToSlash(filepath.Join(d, "detections")) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(d, "detections", "content")
}

// noServiceSettings makes commands see no signalith service here.
func noServiceSettings(t *testing.T) {
	t.Helper()
	saved := readServiceSettings
	readServiceSettings = func() *serviceSettings { return nil }
	t.Cleanup(func() { readServiceSettings = saved })
}

// writePacks writes a packs folder with one pack of two rules.
func writePacks(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "packs")
	pack := filepath.Join(dir, "demo")
	if err := os.MkdirAll(filepath.Join(pack, "rules"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "pack.yaml"), []byte("version: \"7\"\nrules:\n  - {}\n  - {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "rules", "a.yml"), []byte("title: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file at the top is not a pack.
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestContentUsage(t *testing.T) {
	var out strings.Builder
	if err := runContent(nil, &out); err == nil || !strings.Contains(out.String(), "signalith content status") {
		t.Errorf("no command: %v\n%s", err, out.String())
	}
	if err := runContent([]string{"bogus"}, &out); err == nil || !strings.Contains(err.Error(), `unknown content command "bogus"`) {
		t.Errorf("unknown command: %v", err)
	}
	if err := runContent([]string{"bundle"}, &out); err == nil || !strings.Contains(err.Error(), "-o is required") {
		t.Errorf("bundle without -o: %v", err)
	}
	if err := runContent([]string{"sign"}, &out); err == nil || !strings.Contains(err.Error(), "name the bundle") {
		t.Errorf("sign without a file: %v", err)
	}
	if err := runContent([]string{"install"}, &out); err == nil || !strings.Contains(err.Error(), "name the bundle to install") {
		t.Errorf("install without a file: %v", err)
	}
}

// keygen, bundle, sign and pubkey make a signed bundle the way the
// content workflow does.
func TestContentKeygenBundleSign(t *testing.T) {
	var out strings.Builder
	if err := runContent([]string{"keygen"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 5 || !strings.HasPrefix(lines[0], "Private key") || !strings.HasPrefix(lines[3], "Public key") {
		t.Fatalf("keygen:\n%s", out.String())
	}
	priv, pub := lines[1], lines[4]
	keys, err := content.ParseKeys(pub)
	if err != nil || len(keys) != 1 {
		t.Fatalf("public key %q: %v", pub, err)
	}

	t.Setenv("SIGNALITH_CONTENT_KEY", priv)
	out.Reset()
	if err := runContent([]string{"pubkey"}, &out); err != nil || strings.TrimSpace(out.String()) != pub {
		t.Errorf("pubkey %q, want %q: %v", out.String(), pub, err)
	}

	bundle := filepath.Join(t.TempDir(), "content.tar.gz")
	out.Reset()
	if err := runContent([]string{"bundle", "-packs", writePacks(t), "-o", bundle}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), bundle+": version ") || !strings.Contains(out.String(), "  demo: 2 rules (7)") {
		t.Errorf("bundle:\n%s", out.String())
	}

	out.Reset()
	if err := runContent([]string{"sign", bundle}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), bundle+".sig written with key "+content.KeyID(keys[0])) {
		t.Errorf("sign: %s", out.String())
	}
	data, _ := os.ReadFile(bundle)
	sig, _ := os.ReadFile(bundle + ".sig")
	if id, err := content.Verify(keys, data, sig); err != nil || id != content.KeyID(keys[0]) {
		t.Errorf("signature does not verify: %q %v", id, err)
	}
	b, err := content.Read(keys, data, sig)
	if err != nil || len(b.Manifest.Packs) != 1 || b.Manifest.Packs[0].Rules != 2 {
		t.Errorf("bundle read back: %+v %v", b, err)
	}

	// Signing what is not there fails.
	if err := runContent([]string{"sign", bundle + ".missing"}, &out); !os.IsNotExist(err) {
		t.Errorf("sign a missing file: %v", err)
	}
}

func TestContentKeyErrors(t *testing.T) {
	var out strings.Builder
	t.Setenv("SIGNALITH_CONTENT_KEY", "")
	if err := runContent([]string{"sign", "x"}, &out); err == nil || !strings.Contains(err.Error(), "SIGNALITH_CONTENT_KEY is not set") {
		t.Errorf("sign with no key: %v", err)
	}
	if err := runContent([]string{"pubkey"}, &out); err == nil {
		t.Error("pubkey with no key")
	}
	t.Setenv("SIGNALITH_CONTENT_KEY", "not-a-key")
	if err := runContent([]string{"sign", "x"}, &out); err == nil {
		t.Error("sign with a bad key")
	}
	if err := runContent([]string{"bundle", "-packs", t.TempDir(), "-o", filepath.Join(t.TempDir(), "b")}, &out); err == nil || !strings.Contains(err.Error(), "no packs") {
		t.Errorf("bundle of an empty folder: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("printed:\n%s", out.String())
	}
}

func TestContentStatusInstallRemove(t *testing.T) {
	path, dir := contentConfig(t)
	var out strings.Builder
	if err := runContent([]string{"status", "-c", path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Rules built into this Signalith: ") || !strings.Contains(out.String(), "No content update installed.") {
		t.Errorf("status:\n%s", out.String())
	}

	// A bundle signed with a key this build does not trust is refused,
	// and nothing is installed.
	priv, _, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_CONTENT_KEY", priv)
	bundle := filepath.Join(t.TempDir(), "content.tar.gz")
	if err := runContent([]string{"bundle", "-packs", writePacks(t), "-o", bundle}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runContent([]string{"install", "-c", path, bundle}, &out); err == nil || !strings.Contains(err.Error(), "the signature") {
		t.Errorf("install without a signature: %v", err)
	}
	if err := runContent([]string{"sign", bundle}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runContent([]string{"install", "-c", path, bundle}, &out); err == nil {
		t.Errorf("an untrusted bundle was installed:\n%s", out.String())
	}
	if b, err := content.Installed(dir, content.TrustedKeys()); err != nil || b != nil {
		t.Errorf("installed after a refused bundle: %v %v", b, err)
	}
	if err := runContent([]string{"install", "-c", path, bundle + ".missing"}, &out); !os.IsNotExist(err) {
		t.Errorf("install a missing file: %v", err)
	}

	out.Reset()
	if err := runContent([]string{"remove", "-c", path}, &out); err != nil || !strings.Contains(out.String(), "Content update removed.") {
		t.Errorf("remove: %v\n%s", err, out.String())
	}

	// A config file that cannot be read stops the commands that use it.
	bad := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(bad, []byte("server: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"status", "remove"} {
		if err := runContent([]string{cmd, "-c", bad}, &out); err == nil {
			t.Errorf("%s with a broken config file", cmd)
		}
	}
	if err := runContent([]string{"install", "-c", bad, bundle}, &out); err == nil {
		t.Error("install with a broken config file")
	}
}
