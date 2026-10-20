// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// A second root key, not the one signing, cannot be revoked either.
	otherRoot, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	old := keytrust.Roots
	keytrust.Roots = []ed25519.PublicKey{rootPub, otherRoot}
	t.Cleanup(func() { keytrust.Roots = old })
	t.Setenv("SIGNALITH_ROOT_KEY", priv)

	list := filepath.Join(t.TempDir(), keytrust.ListFile)
	var out strings.Builder
	for args, want := range map[string]string{
		"revoke a1b2c3d4e5f6":                                 "-o is required",
		"revoke -o " + list:                                   "name the key IDs",
		"revoke -o " + list + " nothex":                       "not a key ID",
		"revoke -o " + list + " " + keytrust.KeyID(rootPub):   "is a root key",
		"revoke -o " + list + " " + keytrust.KeyID(otherRoot): "is a root key",
		"import-revocations":                                  "name the revocation list",
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

// A list made -from one issued in the future carries that time, with a
// warning.
func TestContentRevokeFutureList(t *testing.T) {
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
	rootPriv, err := content.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	from := filepath.Join(t.TempDir(), keytrust.ListFile)
	data, err := json.Marshal(keytrust.List{Format: keytrust.Format, Issued: time.Now().Add(48 * time.Hour).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(from, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(from+".sig", keytrust.Sign(rootPriv, data), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	list := filepath.Join(t.TempDir(), keytrust.ListFile)
	if err := runContent([]string{"revoke", "-o", list, "-from", from, "a1b2c3d4e5f6"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "in the future") {
		t.Fatalf("no warning:\n%s", out.String())
	}
	out.Reset()
	if err := runContent([]string{"revoke", "-o", list, "a1b2c3d4e5f6"}, &out); err != nil || strings.Contains(out.String(), "in the future") {
		t.Fatalf("a list issued now: %v\n%s", err, out.String())
	}
}

// A list can be signed again with a new root key, -from the list the old
// root key signed, before a release drops the old one.
func TestContentRevokeResignWithNewRoot(t *testing.T) {
	oldPriv, oldPub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	newPriv, newPub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var roots []ed25519.PublicKey
	for _, p := range []string{oldPub, newPub} {
		k, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, k)
	}
	old := keytrust.Roots
	keytrust.Roots = roots
	t.Cleanup(func() { keytrust.Roots = old })
	var out strings.Builder
	list := filepath.Join(t.TempDir(), keytrust.ListFile)
	t.Setenv("SIGNALITH_ROOT_KEY", oldPriv)
	if err := runContent([]string{"revoke", "-o", list, "a1b2c3d4e5f6"}, &out); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ROOT_KEY", newPriv)
	list2 := filepath.Join(t.TempDir(), keytrust.ListFile)
	if err := runContent([]string{"revoke", "-o", list2, "-from", list, "0123456789ab"}, &out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(list2)
	sig, _ := os.ReadFile(list2 + ".sig")
	l, err := keytrust.Verify(roots[1:], data, sig)
	if err != nil || len(l.Revoked) != 2 {
		t.Fatalf("re-signed list: %+v %v", l, err)
	}
}

// With a kept revocation list that cannot be read, status trusts no key.
func TestContentStatusUnreadableList(t *testing.T) {
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
	rootPriv, err := content.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "keytrust")
	data := []byte(`{"format":1,"issued":"2026-10-20T00:00:00Z"}`)
	if _, err := (&keytrust.Store{Dir: dir}).Offer(data, keytrust.Sign(rootPriv, data)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("kept files: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := runContent([]string{"status", "-c", path}, &out); err != nil || !strings.Contains(out.String(), "No content update is used or taken") {
		t.Fatalf("status: %v\n%s", err, out.String())
	}
}
