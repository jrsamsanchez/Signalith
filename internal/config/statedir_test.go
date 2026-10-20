// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// badFolders makes the state folder check fail for the folders listed,
// as on a network share or a folder the service's user cannot write.
func badFolders(t *testing.T, bad ...string) {
	t.Helper()
	forgetStateDirs()
	saved := stateDirProblem
	stateDirProblem = func(dir string) string {
		for _, b := range bad {
			if samePath(dir, b) {
				return "this user cannot write in " + dir
			}
		}
		return ""
	}
	t.Cleanup(func() {
		stateDirProblem = saved
		forgetStateDirs()
	})
}

// A usable folder that holds lookups.dir is the state folder.
func TestStateDirIsNextToLookups(t *testing.T) {
	badFolders(t)
	def, fallback := t.TempDir(), t.TempDir()
	if dir, why := pickStateDir(def, []string{fallback}); dir != def || why != "" {
		t.Errorf("usable folder: %q %q", dir, why)
	}
	if _, err := os.Stat(filepath.Join(fallback, insteadOfFile)); err == nil {
		t.Error("the fallback was marked")
	}
}

// When the folder that holds lookups.dir cannot be used and holds none of
// Signalith's files, a local fallback is used and says why. Choosing it
// writes nothing (validate and other commands only read); the server
// records it, and then it stays the state folder after the usual one can
// be used again, also for commands run by hand (as another user, for whom
// it may be writable).
func TestStateDirFallback(t *testing.T) {
	def, other := t.TempDir(), t.TempDir()
	fallback := filepath.Join(t.TempDir(), "state")
	badFolders(t, def, other)
	dir, why := pickStateDir(def, []string{other, fallback})
	if dir != fallback || !strings.Contains(why, "cannot write in") || !strings.Contains(why, "SIGNALITH_STATE_DIR") {
		t.Fatalf("fallback: %q %q", dir, why)
	}
	if _, err := os.Stat(fallback); !os.IsNotExist(err) {
		t.Fatalf("choosing made the fallback folder: %v", err)
	}
	// Kept for the life of the process.
	if again, _ := pickStateDir(def, []string{other, fallback}); again != fallback {
		t.Errorf("second answer %q", again)
	}
	// The server records it before using it: the folder is made private
	// and the note can be read by every account.
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(fallback, insteadOfFile)
	fi, err := os.Stat(note)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("note mode %v", fi.Mode().Perm())
		}
		if st, _ := os.Stat(fallback); st.Mode().Perm() != 0o700 {
			t.Errorf("folder mode %v", st.Mode().Perm())
		}
	}
	// Recording again, or another folder, changes nothing.
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	if err := RecordStateDir(def); err != nil {
		t.Fatal(err)
	}
	if got := notedFolders(fallback); len(got) != 1 || !samePath(got[0], def) {
		t.Errorf("noted %v", got)
	}
	// A later start, or a command run as root, for whom def is fine.
	badFolders(t)
	dir, why = pickStateDir(def, []string{other, fallback})
	if dir != fallback || !strings.Contains(why, "used instead of "+def) {
		t.Errorf("after def works again: %q %q", dir, why)
	}
}

// A fallback folder that is already another install's state folder is
// never taken, so a second install whose usual folder cannot be used does
// not take over the first one's identity, certificate and keys. A folder
// that holds only a master key may be taken (signalith init makes the
// key of a config in /etc in /var/lib/signalith).
func TestStateDirFallbackOfAnotherInstall(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	fallback := t.TempDir()
	badFolders(t, first, second)
	if dir, _ := pickStateDir(first, []string{fallback}); dir != fallback {
		t.Fatalf("first install: %q", dir)
	}
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	dir, why := pickStateDir(second, []string{fallback})
	if dir != second || !strings.Contains(why, fallback+" already holds another Signalith install's files") || !strings.Contains(why, "SIGNALITH_STATE_DIR") {
		t.Errorf("second install: %q %q", dir, why)
	}
	// The first one still gets it.
	forgetStateDirs()
	if dir, _ := pickStateDir(first, []string{fallback}); dir != fallback {
		t.Errorf("first install again: %q", dir)
	}
	// A folder some install uses without a note, as the systemd unit's
	// /var/lib/signalith (set with SIGNALITH_STATE_DIR) is.
	for _, f := range []string{"node.id", "tls", "admin-password-hash", "keys"} {
		t.Run(f, func(t *testing.T) {
			def, used, next := t.TempDir(), t.TempDir(), t.TempDir()
			badFolders(t, def)
			if err := os.WriteFile(filepath.Join(used, f), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			dir, _ := pickStateDir(def, []string{used, next})
			if want := next; f == "keys" {
				want = used
				if dir != want {
					t.Errorf("a folder with only a master key: %q", dir)
				}
			} else if dir != want {
				t.Errorf("got %q, want the next fallback %q", dir, want)
			}
		})
	}
}

// Files that appear in the usual folder after a fallback was recorded,
// such as a master key made by a command run by hand without the
// service's settings, do not move the server back: it keeps its identity
// and certificate, and the reason names the files it does not use.
func TestStateDirNoteBeforeStrayFiles(t *testing.T) {
	def, fallback := t.TempDir(), t.TempDir()
	badFolders(t, def)
	if dir, _ := pickStateDir(def, []string{fallback}); dir != fallback {
		t.Fatalf("got %q", dir)
	}
	if err := RecordStateDir(fallback); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(def, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	forgetStateDirs()
	dir, why := pickStateDir(def, []string{fallback})
	if dir != fallback || !strings.Contains(why, def+" also holds keys, which Signalith does not use") {
		t.Errorf("got %q %q", dir, why)
	}
}

// An install whose master key, HTTPS certificate or admin password file is
// already in the folder that holds lookups.dir keeps that folder, even
// where a fallback would now be chosen: an upgrade leaves nothing behind.
func TestStateDirKeepsExistingFiles(t *testing.T) {
	for _, f := range []string{"keys", "tls", "admin-password-hash", "node.id"} {
		t.Run(f, func(t *testing.T) {
			def, fallback := t.TempDir(), t.TempDir()
			badFolders(t, def)
			if f == "keys" || f == "tls" {
				os.MkdirAll(filepath.Join(def, f), 0o700)
			} else if err := os.WriteFile(filepath.Join(def, f), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !HoldsState(def) {
				t.Fatal("HoldsState is false")
			}
			if dir, why := pickStateDir(def, []string{fallback}); dir != def || why != "" {
				t.Errorf("got %q %q", dir, why)
			}
		})
	}
}

// With nowhere better, the usual folder is kept, and the reason says
// what is wrong.
func TestStateDirNoFallback(t *testing.T) {
	def, fallback := t.TempDir(), t.TempDir()
	badFolders(t, def, fallback)
	if dir, why := pickStateDir(def, []string{fallback}); dir != def || !strings.Contains(why, "cannot write in "+def) || strings.Contains(why, "another") {
		t.Errorf("got %q %q", dir, why)
	}
}

// SIGNALITH_STATE_DIR always wins, and the master key, the HTTPS
// certificate, the admin password file and StateDirFor all use the one
// folder StateDir picks.
func TestStateDirOneFolder(t *testing.T) {
	badFolders(t)
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	t.Setenv("SIGNALITH_STATE_DIR", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("lookups:\n  dir: data/lookups\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.path = path
	c.Lookups.Dir = "data/lookups"
	want := filepath.Join(dir, "data")
	if got := c.StateDir(); got != want {
		t.Fatalf("StateDir = %q, want %q", got, want)
	}
	if got := StateDirFor(path); got != want {
		t.Errorf("StateDirFor = %q", got)
	}
	if got := c.TLSDir(); got != filepath.Join(want, "tls") {
		t.Errorf("TLSDir = %q", got)
	}
	if got := c.AdminHashFile(); got != filepath.Join(want, "admin-password-hash") {
		t.Errorf("AdminHashFile = %q", got)
	}
	if got := c.Keyring().DefaultPath(); !strings.HasPrefix(got, filepath.Join(want, "keys")+string(filepath.Separator)) {
		t.Errorf("master key %q", got)
	}
	env := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", env)
	if got, why := c.StateDirChoice(); got != env || why != "" {
		t.Errorf("SIGNALITH_STATE_DIR: %q %q", got, why)
	}
	if got := StateDirFor(path); got != env {
		t.Errorf("StateDirFor with SIGNALITH_STATE_DIR = %q", got)
	}
}

// The real check: a folder below a file cannot be made, so it cannot be a
// state folder; a temporary folder can.
func TestStateDirProblem(t *testing.T) {
	if p := StateDirProblem(t.TempDir()); p != "" {
		t.Errorf("a usable folder: %s", p)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if p := StateDirProblem(filepath.Join(file, "state")); !strings.Contains(p, "cannot write in") {
		t.Errorf("below a file: %q", p)
	}
	// A config whose usual folder is below a file falls back to the
	// platform's folder.
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	forgetStateDirs()
	t.Cleanup(forgetStateDirs)
	fallback := t.TempDir()
	if runtime.GOOS == "linux" {
		t.Setenv("STATE_DIRECTORY", fallback)
	} else {
		t.Setenv("ProgramData", fallback)
		fallback = filepath.Join(fallback, "Signalith")
	}
	t.Setenv("SIGNALITH_STATE_DIR", "")
	c := Default()
	c.Lookups.Dir = filepath.Join(file, "state", "lookups")
	if dir, why := c.StateDirChoice(); dir != fallback || !strings.Contains(why, "cannot write in") {
		t.Errorf("fallback: %q %q", dir, why)
	}
}
