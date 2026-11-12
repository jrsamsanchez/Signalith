// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secrets

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// keyFileWarning says when a master key file's access list lets accounts
// beyond the computer's administrators read or change it: Everyone,
// Users, Authenticated Users, Guests, Interactive, Anonymous or Domain
// Users (CRYPTO-06). The access list Signalith sets when it makes the
// file (see package securefile) allows only SYSTEM, Administrators and
// the service account; a key copied in from elsewhere may carry a wider
// one inherited from its folder. The default key is also protected with
// DPAPI for the computer, which any program on it can undo, so the access
// list is what keeps other accounts out.
func keyFileWarning(path string, st os.FileInfo) string {
	return fileWarning("The master key", path, st)
}

// fileWarning is keyFileWarning for any key file; what names it.
func fileWarning(what, path string, _ os.FileInfo) string {
	broad, err := broadAccess(path)
	if err != nil || len(broad) == 0 {
		// An access list that cannot be read is not reported: the
		// key file itself was readable, and a false alarm here would
		// stop the server.
		return ""
	}
	return fmt.Sprintf("%s %s is not private: %s can read or change it; remove them from the file's access list "+
		"(in a PowerShell opened as Administrator: icacls \"%s\" /inheritance:r /grant:r SYSTEM:F Administrators:F \"NT SERVICE\\Signalith:R\")",
		what, path, strings.Join(broad, ", "), path)
}

// broadSIDs are the well-known groups that stand for accounts beyond the
// computer's administrators.
var broadSIDs = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinWorldSid, windows.WinAuthenticatedUserSid, windows.WinBuiltinUsersSid, windows.WinBuiltinGuestsSid,
	windows.WinInteractiveSid, windows.WinAnonymousSid,
}

// keyRights are the rights that let an account read or replace a key
// file, or give itself those rights.
const keyRights = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.GENERIC_READ |
	windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE

// broadAccess names the broad groups path's access list allows to read or
// change it; "everyone" for a file with no access list at all.
func broadAccess(path string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return []string{"everyone (the file has no access list)"}, nil
	}
	var broad []*windows.SID
	for _, t := range broadSIDs {
		if s, err := windows.CreateWellKnownSid(t); err == nil {
			broad = append(broad, s)
		}
	}
	var out []string
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&keyRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if isBroad(sid, broad) {
			out = append(out, sidName(sid))
		}
	}
	return out, nil
}

// isBroad reports whether sid is one of broad, or a domain's Domain Users
// group (S-1-5-21-...-513).
func isBroad(sid *windows.SID, broad []*windows.SID) bool {
	for _, b := range broad {
		if sid.Equals(b) {
			return true
		}
	}
	s := sid.String()
	return strings.HasPrefix(s, "S-1-5-21-") && strings.HasSuffix(s, "-513")
}

// sidName is an account's name for a message, or its SID.
func sidName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

// accessHint says how to let Signalith read a key file it may not.
func accessHint(string) string {
	return "Run this in a PowerShell opened as Administrator; the service reads it as NT SERVICE\\Signalith"
}
