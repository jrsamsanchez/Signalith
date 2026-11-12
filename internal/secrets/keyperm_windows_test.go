// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// setACL replaces path's access list with the one in sddl.
func setACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// CRYPTO-06: a master key file that Everyone or Users may read is
// reported; one only SYSTEM, Administrators and its owner may use is not.
func TestKeyFileWarningReadsTheAccessList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	setACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if w := keyFileWarning(path, st); w != "" {
		t.Errorf("a private key file: %s", w)
	}
	for _, sddl := range []string{"D:P(A;;FA;;;SY)(A;;FA;;;OW)(A;;FR;;;WD)", "D:P(A;;FA;;;SY)(A;;FA;;;OW)(A;;FR;;;BU)"} {
		setACL(t, path, sddl)
		if w := keyFileWarning(path, st); !strings.Contains(w, "not private") {
			t.Errorf("%s: warning %q", sddl, w)
		}
	}
}
