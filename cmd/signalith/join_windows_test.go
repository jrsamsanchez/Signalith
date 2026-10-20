// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// allowedSIDs returns the SIDs path's access list allows, and whether it
// is protected from inheriting the folder's.
func allowedSIDs(t *testing.T, path string) (map[string]bool, bool) {
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

// On Windows the keys and settings join writes get the protected access
// list of Signalith's other secrets (SYSTEM, Administrators and NT
// SERVICE\Signalith), not the state folder's, even when that folder lets
// every user read, and the cluster key is stored sealed.
func TestJoinFilesArePrivateOnWindows(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	m.env.goos = "windows"
	// A state folder every user may read, as one made at the top of C:\.
	if err := os.MkdirAll(m.state, 0o700); err != nil {
		t.Fatal(err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + self.User.Sid.String() + ")(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(m.state, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if code := m.join(t, f.tok, "--no-start"); code != joinExitOK {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	c, err := config.Load(m.config)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := shared.ClusterKeyPath(m.state, f.key.ID())
	paths := []string{filepath.Join(m.state, "keys"), keyFile, filepath.Join(m.state, "opensearch"),
		filepath.Join(m.state, "opensearch", "ca.pem"), c.SettingsFile(), filepath.Join(c.TLSDir(), "server.key")}
	service := securefile.ServiceSID(securefile.ServiceName)
	for _, p := range paths {
		got, protected := allowedSIDs(t, p)
		if got["S-1-5-32-545"] || got["S-1-1-0"] || got["S-1-5-11"] { // Users, Everyone, Authenticated Users
			t.Errorf("%s: other users may read it: %v", p, got)
		}
		if !got["S-1-5-18"] || !got["S-1-5-32-544"] || !got[service] {
			t.Errorf("%s: SYSTEM, Administrators or the service are missing: %v", p, got)
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() && !protected {
			t.Errorf("%s inherits the state folder's access list", p)
		}
	}
	// The cluster key is sealed with the master key, not kept in clear.
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), f.key.Text()) {
		t.Error("the cluster key is stored in clear")
	}
	if held, err := (shared.KeyStore{Dir: m.state, Master: c.Keyring()}).ClusterKeys(); err != nil || len(held) != 1 {
		t.Errorf("the cluster key does not open: %v %v", held, err)
	}
}
