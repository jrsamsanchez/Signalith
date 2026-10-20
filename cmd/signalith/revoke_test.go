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

func TestContentRevoke(t *testing.T) {
	path, _ := contentConfig(t)
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	priv, pub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rootPub, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	old := keytrust.Roots
	keytrust.Roots = []ed25519.PublicKey{rootPub}
	t.Cleanup(func() { keytrust.Roots = old })
	t.Setenv("SIGNALITH_ROOT_KEY", priv)

	list := filepath.Join(t.TempDir(), keytrust.ListFile)
	var out strings.Builder
	for args, want := range map[string]string{
		"revoke a1b2c3d4e5f6":                               "-o is required",
		"revoke -o " + list:                                 "name the key IDs",
		"revoke -o " + list + " nothex":                     "not a key ID",
		"revoke -o " + list + " " + keytrust.KeyID(rootPub): "a root key cannot be revoked",
		"import-revocations":                                "name the revocation list",
	} {
		if err := runContent(strings.Fields(args), &out); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", args, err, want)
		}
	}

	if err := runContent([]string{"revoke", "-o", list, "-note", "leaked 2026-10-20", "a1b2c3d4e5f6"}, &out); err != nil {
		t.Fatal(err)
	}
	// A second list adds to the first and is newer.
	list2 := filepath.Join(t.TempDir(), keytrust.ListFile)
	if err := runContent([]string{"revoke", "-o", list2, "-from", list, "0123456789ab"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runContent([]string{"import-revocations", "-c", path, list2}, &out); err != nil || !strings.Contains(out.String(), "Revocation list kept.") {
		t.Fatalf("import: %v\n%s", err, out.String())
	}
	for _, want := range []string{"a1b2c3d4e5f6  leaked 2026-10-20", "0123456789ab"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("import output lacks %q:\n%s", want, out.String())
		}
	}
	// The older list is not taken.
	out.Reset()
	if err := runContent([]string{"import-revocations", "-c", path, list}, &out); err != nil || !strings.Contains(out.String(), "Nothing to do") {
		t.Fatalf("older import: %v\n%s", err, out.String())
	}
	// A list changed after signing is refused.
	b, _ := os.ReadFile(list2)
	if err := os.WriteFile(list2, []byte(strings.Replace(string(b), "0123456789ab", "ffffffffffff", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContent([]string{"import-revocations", "-c", path, list2}, &out); err == nil {
		t.Fatal("a changed list was imported")
	}
	out.Reset()
	if err := runContent([]string{"revocations", "-c", path}, &out); err != nil || !strings.Contains(out.String(), "0123456789ab") {
		t.Fatalf("revocations: %v\n%s", err, out.String())
	}
	if l, _, _, err := (&keytrust.Store{Dir: filepath.Join(state, "keytrust")}).Load(); err != nil || l == nil {
		t.Fatalf("kept list: %+v %v", l, err)
	}
}
