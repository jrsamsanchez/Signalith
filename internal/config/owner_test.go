// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSettingsFileKeepsItsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files away")
	}
	dir := filepath.Join(t.TempDir(), "lookups")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// The service's account owns the folder; root runs the command line.
	if err := os.Chown(dir, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}
	path := filepath.Join(dir, "settings.yaml")
	p := &PageSettings{}
	p.Set("search.max_events", 10, "root", time.Now())
	owner := func() (uint32, uint32) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return st.Uid, st.Gid
	}
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(); u != 4242 || g != 4343 {
		t.Errorf("new file owned by %d:%d", u, g)
	}
	// Rewriting keeps the file's own owner.
	if err := os.Chown(path, 5151, 5252); err != nil {
		t.Fatal(err)
	}
	p.Set("search.max_events", 20, "root", time.Now())
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(); u != 5151 || g != 5252 {
		t.Errorf("rewritten file owned by %d:%d", u, g)
	}
}

// A link put in place of the settings file must not get its target given
// away: the new file replaces the link, and the target keeps its owner.
func TestSettingsFileOwnerIgnoresALink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files away")
	}
	dir := filepath.Join(t.TempDir(), "lookups")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	p := &PageSettings{}
	p.Set("search.max_events", 10, "root", time.Now())
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
		t.Errorf("the link's target was given to %d:%d", st.Uid, st.Gid)
	}
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the settings file is still a link")
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 || st.Gid != 4343 {
		t.Errorf("new file owned by %d:%d, want the folder's owner", st.Uid, st.Gid)
	}
}

// A note root writes in a fallback state folder belongs to the folder's
// owner, so the server's own account can read it and add to it.
func TestStateDirNoteKeepsTheFolderOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files away")
	}
	def, fallback := t.TempDir(), t.TempDir()
	if err := os.Chown(fallback, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}
	badFolders(t, def)
	if dir, _ := pickStateDir(def, []string{fallback}); dir != fallback {
		t.Fatalf("got %q", dir)
	}
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(fallback, insteadOfFile))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 4242 || st.Gid != 4343 || fi.Mode().Perm() != 0o644 {
		t.Errorf("note owned by %d:%d, mode %v", st.Uid, st.Gid, fi.Mode().Perm())
	}
}

// The note is readable by every account whatever the umask (the systemd
// unit's is 0077), and a link put in its place is not followed.
func TestStateDirNoteModeAndLinks(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	def, fallback := t.TempDir(), t.TempDir()
	badFolders(t, def)
	if dir, _ := pickStateDir(def, []string{fallback}); dir != fallback {
		t.Fatalf("got %q", dir)
	}
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(fallback, insteadOfFile)); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("note: %v %v", fi.Mode(), err)
	}
	other := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(other, insteadOfFile)); err != nil {
		t.Fatal(err)
	}
	if err := noteInsteadOf(other, def); err == nil {
		t.Error("a link was followed")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Errorf("the linked file changed: %q", b)
	}
}
