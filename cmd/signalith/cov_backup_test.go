// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signalith backup's options, and what it says about the master key.
func TestBackupCommandOptions(t *testing.T) {
	noServiceSettings(t)
	src := backupInstall(t, map[string]string{"state/keys/master.key": "the key", "data/lookups/a.csv": "x\n"})
	if err := cmdBackup([]string{"-c", src, "extra"}); err == nil || !strings.Contains(err.Error(), "signalith backup") {
		t.Errorf("an extra argument: %v", err)
	}
	if err := cmdBackup([]string{"-c", src, "-include-master-key", "-no-master-key"}); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both key options: %v", err)
	}
	dir := t.TempDir()
	for _, c := range []struct {
		flag, want string
		key        bool
	}{
		{"-include-master-key", "holds the master key", true},
		{"-no-master-key", "The master key was left out", false},
	} {
		name := filepath.Join(dir, strings.TrimPrefix(c.flag, "-")+".zip")
		var err error
		out := captureStdout(t, func() { err = cmdBackup([]string{"-c", src, c.flag, "-o", name}) })
		if err != nil || !strings.Contains(out, c.want) || !strings.Contains(out, "Wrote "+name) {
			t.Errorf("%s: %v\n%s", c.flag, err, out)
		}
		_, has := zipEntries(t, name)["state/keys/master.key"]
		if has != c.key {
			t.Errorf("%s: master key in the zip %v", c.flag, has)
		}
		if _, err := os.Stat(masterKeyFileName(name)); err == nil {
			t.Errorf("%s: a master key file was written", c.flag)
		}
	}
	// The same name again is refused, and the key file made for it goes.
	name := filepath.Join(dir, "include-master-key.zip")
	if err := cmdBackup([]string{"-c", src, "-o", name}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("same name: %v", err)
	}
	if _, err := os.Stat(masterKeyFileName(name)); err == nil {
		t.Error("the master key file of a failed backup was kept")
	}

	// With no -o, the zip is named after the server, in this folder.
	t.Chdir(t.TempDir())
	var err error
	out := captureStdout(t, func() { err = cmdBackup([]string{"-c", src}) })
	if err != nil || !strings.Contains(out, "The master key is in") {
		t.Errorf("default name: %v\n%s", err, out)
	}
	made, _ := filepath.Glob("signalith-backup-*.zip")
	if len(made) != 2 { // the backup and its master key
		t.Errorf("wrote %v", made)
	}
}

// With no master key to copy, no key file is left behind.
func TestBackupCommandWithoutMasterKey(t *testing.T) {
	noServiceSettings(t)
	src := backupInstall(t, map[string]string{"data/lookups/a.csv": "x\n"})
	name := filepath.Join(t.TempDir(), "b.zip")
	var err error
	out := captureStdout(t, func() { err = cmdBackup([]string{"-c", src, "-o", name}) })
	if err != nil || !strings.Contains(out, "The master key was left out") {
		t.Errorf("%v\n%s", err, out)
	}
	if _, err := os.Stat(masterKeyFileName(name)); err == nil {
		t.Error("an empty master key file was kept")
	}
}

func TestRestoreCommand(t *testing.T) {
	noServiceSettings(t)
	src := backupInstall(t, map[string]string{"state/keys/master.key": "the key", "data/lookups/a.csv": "x\n"})
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	keyFile := masterKeyFileName(zipFile)
	if _, err := writeBackup(zipFile, loadForBackup(t, src), false, true, filepath.Base(keyFile)); err != nil {
		t.Fatal(err)
	}
	dst := backupInstall(t, map[string]string{"state/keys/master.key": "here"})
	if err := cmdRestore([]string{"-c", dst}); err == nil || !strings.Contains(err.Error(), "signalith backup") {
		t.Errorf("no file: %v", err)
	}
	// Without -yes and not at a terminal, nothing is written.
	in, _ := os.Open(src)
	defer in.Close()
	var out bytes.Buffer
	err := restoreBackup(zipFile, "", loadForBackup(t, dst), false, in, &out)
	if err == nil || !strings.Contains(err.Error(), "add -yes") || !strings.Contains(out.String(), "its key was written to "+filepath.Base(keyFile)) {
		t.Errorf("no -yes: %v\n%s", err, out.String())
	}
	// A master key file that is missing, or holds no key.
	if err := restoreBackup(zipFile, filepath.Join(t.TempDir(), "none.zip"), loadForBackup(t, dst), true, in, io.Discard); err == nil || !strings.Contains(err.Error(), "could not open") {
		t.Errorf("missing key file: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.zip")
	f, _ := os.Create(empty)
	zip.NewWriter(f).Close()
	f.Close()
	if err := restoreBackup(zipFile, empty, loadForBackup(t, dst), true, in, io.Discard); err == nil || !strings.Contains(err.Error(), "holds no master key") {
		t.Errorf("empty key file: %v", err)
	}
	if err := restoreBackup(filepath.Join(t.TempDir(), "none.zip"), "", loadForBackup(t, dst), true, in, io.Discard); err == nil || !strings.Contains(err.Error(), "could not open") {
		t.Errorf("missing backup: %v", err)
	}
	// The command restores with -yes.
	var cerr error
	got := captureStdout(t, func() { cerr = cmdRestore([]string{"-c", dst, "-yes", zipFile}) })
	if cerr != nil || !strings.Contains(got, "Restored") || !strings.Contains(got, "accept-restore") {
		t.Errorf("restore: %v\n%s", cerr, got)
	}
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(dst)), "data", "lookups", "a.csv"))
	if string(b) != "x\n" {
		t.Errorf("a.csv = %q", b)
	}
}

// Entries for a folder this install does not have are listed, not written,
// and a backup with no master key and no key file says so.
func TestRestoreUnknownRoles(t *testing.T) {
	dst := backupInstall(t, map[string]string{})
	bad := filepath.Join(t.TempDir(), "odd.zip")
	f, _ := os.Create(bad)
	zw := zip.NewWriter(f)
	w, _ := zw.Create(manifestName)
	io.WriteString(w, `{"format":1,"host":"siem-z","no_master_key":true,"roots":[{"role":"elsewhere","dir":true},{"role":"state","dir":true}]}`)
	w, _ = zw.Create("elsewhere/a.txt")
	io.WriteString(w, "a")
	w, _ = zw.Create("state/note.txt")
	io.WriteString(w, "b")
	zw.Close()
	f.Close()
	var out bytes.Buffer
	if err := restoreBackup(bad, "", loadForBackup(t, dst), true, os.Stdin, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"not restored (this install has no place for it): elsewhere/a.txt", "The backup has no master key: put the key", "Restored 1 files."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}
}
