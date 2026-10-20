// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package tlsauto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allowed returns the SIDs path's access list allows, and whether it is
// protected from inheriting the folder's.
func allowed(t *testing.T, path string) (map[string]bool, bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			out[(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()] = true
		}
	}
	return out, ctrl&windows.SE_DACL_PROTECTED != 0
}

// The CA and server keys get the protected access list of Signalith's
// other secrets (SYSTEM, Administrators, NT SERVICE\Signalith and the
// account that made them), not the state folder's, which here lets every
// user read what it holds, as C:\ does for a folder made at its top.
func TestKeysArePrivateOnWindows(t *testing.T) {
	fakeMachine(t)
	state := t.TempDir()
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	const users = "S-1-5-32-545" // BUILTIN\Users
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + self.User.Sid.String() + ")(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(state, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := allowed(t, state); !got[users] {
		t.Fatalf("the test folder does not let Users read: %v", got)
	}

	dir := filepath.Join(state, "tls")
	newAuto(t, dir, &clock{time.Now()}, "siem.example.com")
	for _, p := range []string{dir, filepath.Join(dir, "ca.key"), filepath.Join(dir, "server.key")} {
		got, protected := allowed(t, p)
		if got[users] || got["S-1-1-0"] || got["S-1-5-11"] { // Users, Everyone, Authenticated Users
			t.Errorf("%s: other users may read it: %v", p, got)
		}
		if !got["S-1-5-18"] || !got["S-1-5-32-544"] {
			t.Errorf("%s: SYSTEM or Administrators are missing: %v", p, got)
		}
		if p == dir && !protected {
			t.Errorf("%s inherits the state folder's access list", p)
		}
	}
	// The keys still load.
	if _, err := os.ReadFile(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	newAuto(t, dir, &clock{time.Now()}, "siem.example.com")
}
