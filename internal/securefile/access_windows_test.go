// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, what "FA" (full control) grants.
const fileAllAccess windows.ACCESS_MASK = 0x001F01FF

// aces returns the SIDs a path's access list allows and whether it is
// protected from inheriting.
func aces(t *testing.T, path string) (map[string]windows.ACCESS_MASK, bool) {
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
	out := map[string]windows.ACCESS_MASK{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("unexpected ACE type %d", ace.Header.AceType)
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out[sid.String()] |= ace.Mask
	}
	return out, ctrl&windows.SE_DACL_PROTECTED != 0
}

func checkPrivate(t *testing.T, path string) {
	t.Helper()
	got, protected := aces(t, path)
	if !protected {
		t.Errorf("%s: access list is not protected from inheritance", path)
	}
	for _, sid := range []string{sidSystem, sidAdmins, ServiceSID(ServiceName)} {
		if got[sid]&fileAllAccess != fileAllAccess {
			t.Errorf("%s: %s lacks full control: %v", path, sid, got)
		}
	}
	for _, sid := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545"} { // Everyone, Authenticated Users, Users
		if _, ok := got[sid]; ok {
			t.Errorf("%s: %s may access it: %v", path, sid, got)
		}
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{sidSystem: true, sidAdmins: true, ServiceSID(ServiceName): true, self.User.Sid.String(): true}
	for sid := range got {
		if !allowed[sid] {
			t.Errorf("%s: unexpected entry for %s", path, sid)
		}
	}
}

func TestPrivateAccessList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, dir)
	f := filepath.Join(dir, "master.key.dpapi")
	if err := WriteFile(f, []byte("x")); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, f)
	// A file outside a private folder gets the list too.
	g := filepath.Join(t.TempDir(), "directory.json")
	if err := WriteFile(g, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, g)
	// Replacing it keeps it.
	if err := WriteFile(g, []byte("{ }")); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, g)
	if b, _ := os.ReadFile(g); string(b) != "{ }" {
		t.Errorf("content %q", b)
	}
	// Replace makes a file private whatever its list allowed, such as one
	// that inherits its folder's.
	h := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(h, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(h, []byte("y")); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, h)
}

// TestAdminOnlyAccessList: a folder made with MkdirAdminOnly, and what is
// already inside it, may be used by SYSTEM and Administrators only, also
// when it was a private folder before (an install made by an older
// version).
func TestAdminOnlyAccessList(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("giving a folder to Administrators needs an elevated test")
	}
	dir := filepath.Join(t.TempDir(), "SignalithOpenSearch")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "ca")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(sub, "root-ca-key.pem")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := aces(t, key); got[ServiceSID(ServiceName)] == 0 {
		t.Fatalf("test setup: the key does not inherit the service's entry: %v", got)
	}
	if err := MkdirAdminOnly(dir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, sub, key} {
		got, _ := aces(t, p)
		for _, sid := range []string{sidSystem, sidAdmins} {
			if got[sid]&fileAllAccess != fileAllAccess {
				t.Errorf("%s: %s lacks full control: %v", p, sid, got)
			}
		}
		for sid := range got {
			if sid != sidSystem && sid != sidAdmins {
				t.Errorf("%s: unexpected entry for %s", p, sid)
			}
		}
	}
	if _, protected := aces(t, dir); !protected {
		t.Errorf("%s: access list is not protected from inheritance", dir)
	}
}
