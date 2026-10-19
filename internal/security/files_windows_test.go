// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

func TestProbePermWindows(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "master.key.dpapi")
	if err := securefile.WriteFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// As the account that made it, as the server checks its own files.
	me := CurrentAccount()
	p, err := probePerm(file, me)
	if err != nil {
		t.Fatal(err)
	}
	if p.OtherRead || p.OtherWrite || p.SomeRead || p.SomeWrite {
		t.Errorf("a private file: %+v", p)
	}
	// Let every user read it.
	if out, err := exec.Command("icacls", file, "/grant", "*S-1-5-32-545:(R)").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	p, err = probePerm(file, me)
	if err != nil {
		t.Fatal(err)
	}
	if !p.OtherRead || p.OtherWrite {
		t.Errorf("readable by users: %+v", p)
	}
	if _, err := probePerm(filepath.Join(dir, "none"), Account{}); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

// A file a signalith command made, checked as the service checks it: an
// administrator who ran the command is not another account that can read
// it.
func TestProbePermAsService(t *testing.T) {
	file := filepath.Join(t.TempDir(), "admin-password-hash")
	if err := securefile.WriteFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	p, err := probePerm(file, Account{UID: -1, GID: -1, SID: securefile.ServiceSID(securefile.ServiceName)})
	if err != nil {
		t.Fatal(err)
	}
	if p.OtherRead || p.OtherWrite || p.SomeRead || p.SomeWrite {
		t.Errorf("a private file, as the service: %+v", p)
	}
}
