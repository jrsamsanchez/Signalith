// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

// Run as root, a link made by another account is not followed: the
// account the server runs as could point one of its files at a system
// file for root to replace.
func TestRootRefusesOthersLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "passwd")
	os.WriteFile(target, []byte("root:x:0:0"), 0o644)
	link := filepath.Join(dir, "master.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, 4242, 4242); err != nil {
		t.Skip("cannot change a link's owner here:", err)
	}
	if err := WriteFile(link, []byte("a new key")); err == nil {
		t.Fatal("followed another account's link as root")
	}
	if b, _ := os.ReadFile(target); string(b) != "root:x:0:0" {
		t.Errorf("the file the link points to was changed: %q", b)
	}
	// Root's own links are followed.
	os.Lchown(link, 0, 0)
	if err := WriteFile(link, []byte("changed")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "changed" {
		t.Errorf("root's own link was not followed: %q", b)
	}
}
