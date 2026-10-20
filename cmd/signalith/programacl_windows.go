// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Accounts that may change the program the service runs: SYSTEM,
// Administrators and TrustedInstaller (which owns Windows' own files).
var programTrustees = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
}

// changeRights are the rights that let an account replace a file or
// what's in a folder: write or append (add files and folders), delete,
// delete what's inside, change permissions or the owner, and the generic
// write and full-control rights.
const changeRights = windows.ACCESS_MASK(0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000)

// inheritOnlyAce marks an entry that applies only to what is created
// inside a folder, not to the folder itself.
const inheritOnlyAce = 0x08

// checkProgramFolder refuses to run the service from a program, or a
// folder, that an account other than SYSTEM, Administrators or
// TrustedInstaller may change: that account could replace signalith.exe
// and have its own program run as NT SERVICE\Signalith, which can read
// the master key and every stored secret.
func checkProgramFolder(exe string) error {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	for _, path := range []string{filepath.Dir(exe), exe} {
		who, err := whoCanChange(path)
		if err != nil {
			return fmt.Errorf("could not check who may change %s: %w", path, err)
		}
		if who != "" {
			return fmt.Errorf("%s may be changed by %s, so the service would run a program someone other than an administrator could replace. "+
				"Put signalith.exe in a folder only administrators can change, such as C:\\Program Files\\Signalith (deploy\\windows\\install.ps1 does this), "+
				"and run service install from there", path, who)
		}
	}
	return nil
}

// whoCanChange names an account other than programTrustees that owns
// path or may change it, or returns "" when there is none.
func whoCanChange(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	if owner, _, err := sd.Owner(); err != nil || owner == nil {
		return "", fmt.Errorf("no owner: %v", err)
	} else if !programTrustees[owner.String()] {
		return sidName(owner) + " (its owner)", nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dacl == nil {
		return "everyone (it has no access list)", nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnlyAce != 0 || ace.Mask&changeRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !programTrustees[sid.String()] {
			return sidName(sid), nil
		}
	}
	return "", nil
}

func sidName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}
