// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package securefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func owner(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys := st.Sys().(*syscall.Stat_t)
	return sys.Uid, sys.Gid
}

// Run as root, files keep the owner of the file they replace, and new
// files and folders take the owner of the folder they are made in.
func TestRootKeepsOwners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	svc := filepath.Join(dir, "svc")
	if err := os.Mkdir(svc, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(svc, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}

	// A new file in the service's folder is the service's.
	newFile := filepath.Join(svc, "new.yaml")
	if err := WriteFile(newFile, []byte("a: 1\n")); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(t, newFile); u != 4242 || g != 4343 {
		t.Errorf("new file owner = %d:%d", u, g)
	}

	// Replacing a file another account owns keeps it theirs.
	old := filepath.Join(dir, "old.yaml")
	os.WriteFile(old, []byte("old"), 0o640)
	os.Chown(old, 5151, 5252)
	if err := WriteFile(old, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(t, old); u != 5151 || g != 5252 {
		t.Errorf("replaced file owner = %d:%d", u, g)
	}

	// A new private folder in the service's folder is the service's.
	sub := filepath.Join(svc, "keys")
	if err := MkdirPrivate(sub); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(t, sub); u != 4242 || g != 4343 {
		t.Errorf("new folder owner = %d:%d", u, g)
	}
}

// A link that points at itself cannot be looked at; the temporary file
// is removed.
func TestPrepareLinkLoop(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop.yaml")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAt(loop, []byte("x"), false, true); err == nil {
		t.Error("prepared a looping link")
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// Writing in place reports a device that is full or cannot be synced.
func TestWriteInPlaceDeviceErrors(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	if err := writeInPlace("/dev/full", []byte("x")); err == nil {
		t.Error("wrote to a full device")
	}
	if err := writeInPlace("/dev/null", []byte("x")); err == nil {
		t.Skip("this system syncs /dev/null")
	}
}

func TestOtherLinksOfMissingFile(t *testing.T) {
	if n := OtherLinks(filepath.Join(t.TempDir(), "missing")); n != 0 {
		t.Errorf("OtherLinks = %d", n)
	}
}
