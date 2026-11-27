// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/keytrust"
)

// The content commands' errors: missing files and signatures, a bad root
// key, and a kept revocation list that cannot be read.
func TestContentCommandErrors(t *testing.T) {
	path, _ := contentConfig(t)
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	priv, pub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rootPub, _ := base64.StdEncoding.DecodeString(pub)
	old := keytrust.Roots
	keytrust.Roots = []ed25519.PublicKey{rootPub}
	t.Cleanup(func() { keytrust.Roots = old })

	dir := t.TempDir()
	list := filepath.Join(dir, keytrust.ListFile)
	noSig := filepath.Join(dir, "nosig.json")
	os.WriteFile(noSig, []byte("{}"), 0o600)
	badSig := filepath.Join(dir, "badsig.json")
	os.WriteFile(badSig, []byte("{}"), 0o600)
	os.WriteFile(badSig+".sig", []byte("nope"), 0o600)
	missing := filepath.Join(dir, "missing.json")
	brokenCfg := filepath.Join(dir, "broken.yaml")
	os.WriteFile(brokenCfg, []byte("server: [\n"), 0o600)

	var out strings.Builder
	t.Setenv("SIGNALITH_ROOT_KEY", "not a key")
	if err := runContent([]string{"revoke", "-o", list, "a1b2c3d4e5f6"}, &out); err == nil || !strings.Contains(err.Error(), "SIGNALITH_ROOT_KEY") {
		t.Errorf("bad root key: %v", err)
	}
	t.Setenv("SIGNALITH_ROOT_KEY", priv)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"revoke", "-o", list, "-from", missing, "a1b2c3d4e5f6"}, "missing.json"},
		{[]string{"revoke", "-o", list, "-from", noSig, "a1b2c3d4e5f6"}, "the signature of"},
		{[]string{"revoke", "-o", list, "-from", badSig, "a1b2c3d4e5f6"}, "badsig.json"},
		{[]string{"revoke", "-o", filepath.Join(dir, "no", "such", "dir", "l.json"), "a1b2c3d4e5f6"}, ""},
		{[]string{"import-revocations", "-c", path, missing}, "missing.json"},
		{[]string{"import-revocations", "-c", path, noSig}, "the signature"},
		{[]string{"import-revocations", "-c", brokenCfg, noSig}, ""},
		{[]string{"revocations", "-c", brokenCfg}, ""},
		{[]string{"install", "-c", path, noSig}, "the signature"},
	} {
		if err := runContent(c.args, &out); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	// A key named twice is listed once.
	if err := runContent([]string{"revoke", "-o", list, "-note", "leaked", "a1b2c3d4e5f6"}, &out); err != nil {
		t.Fatal(err)
	}
	list2 := filepath.Join(dir, "list2.json")
	if err := runContent([]string{"revoke", "-o", list2, "-from", list, "a1b2c3d4e5f6", "a1b2c3d4e5f6"}, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(list2); strings.Count(string(b), "a1b2c3d4e5f6") != 1 {
		t.Errorf("list:\n%s", b)
	}

	// With no revocation list kept, nothing is revoked but the built-in ones.
	out.Reset()
	keytrust.Roots = nil
	if err := runContent([]string{"revocations", "-c", path}, &out); err != nil || !strings.Contains(out.String(), "This build has no root key") {
		t.Errorf("no roots: %v\n%s", err, out.String())
	}
	keytrust.Roots = []ed25519.PublicKey{rootPub}

	// A kept list that cannot be read: status says no update is used, and
	// revocations fails.
	kt := filepath.Join(state, "keytrust")
	os.MkdirAll(kt, 0o700)
	os.WriteFile(filepath.Join(kt, "kept-revocations"), []byte("not json"), 0o600)
	out.Reset()
	if err := runContent([]string{"status", "-c", path}, &out); err != nil || !strings.Contains(out.String(), "No content update is used or taken") {
		t.Errorf("status with a broken list: %v\n%s", err, out.String())
	}
	if err := runContent([]string{"revocations", "-c", path}, &out); err == nil {
		t.Error("revocations read a broken list")
	}
}

// status says when the installed update cannot be used.
func TestContentStatusBrokenUpdate(t *testing.T) {
	path, dir := contentConfig(t)
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A bundle and signature that are not one cannot be used.
	for _, name := range []string{"content.tar.gz", "content.tar.gz.sig"} {
		os.WriteFile(filepath.Join(dir, name), []byte("garbage"), 0o600)
	}
	var out strings.Builder
	if err := runContent([]string{"status", "-c", path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "cannot be used") {
		t.Errorf("status:\n%s", out.String())
	}
}
