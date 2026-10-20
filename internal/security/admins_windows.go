// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package security

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sidAdmins is the local Administrators group.
const sidAdmins = "S-1-5-32-544"

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserGetLocalGroups   = netapi32.NewProc("NetUserGetLocalGroups")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
)

const (
	lgIncludeIndirect  = 1          // LG_INCLUDE_INDIRECT: groups through other groups too
	maxPreferredLength = 0xFFFFFFFF // MAX_PREFERRED_LENGTH
)

// adminsName is the name of the local Administrators group, which
// Windows translates.
func adminsName() (string, bool) {
	sid, err := windows.StringToSid(sidAdmins)
	if err != nil {
		return "", false
	}
	name, _, _, err := sid.LookupAccount("")
	return name, err == nil && name != ""
}

// inAdministrators reports whether the account sid is in the local
// Administrators group, directly or through other groups. known is false
// when Windows couldn't say, such as for a domain account while the
// domain can't be reached.
func inAdministrators(sid string) (admin, known bool) {
	// The built-in Administrator account (RID 500) always is.
	if strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-500") {
		return true, true
	}
	s, err := windows.StringToSid(sid)
	if err != nil {
		return false, false
	}
	account, domain, _, err := s.LookupAccount("")
	if err != nil {
		return false, false
	}
	user := account
	if host, err := windows.ComputerName(); domain != "" && (err != nil || !strings.EqualFold(domain, host)) {
		user = domain + `\` + account
	}
	admins, ok := adminsName()
	if !ok || procNetUserGetLocalGroups.Find() != nil {
		return false, false
	}
	name, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return false, false
	}
	var buf *byte
	var read, total uint32
	r, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(name)), 0, lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if buf != nil {
		defer windows.NetApiBufferFree(buf)
	}
	if r != 0 || read != total {
		return false, false
	}
	if read == 0 {
		return false, true
	}
	// LOCALGROUP_USERS_INFO_0: one name per group.
	for _, g := range unsafe.Slice((**uint16)(unsafe.Pointer(buf)), read) {
		if strings.EqualFold(windows.UTF16PtrToString(g), admins) {
			return true, true
		}
	}
	return false, true
}

// adminMembers lists the accounts and groups in the local Administrators
// group itself, by SID; nil when Windows couldn't say.
func adminMembers() map[string]bool {
	admins, ok := adminsName()
	if !ok || procNetLocalGroupGetMembers.Find() != nil {
		return nil
	}
	group, err := windows.UTF16PtrFromString(admins)
	if err != nil {
		return nil
	}
	var buf *byte
	var read, total uint32
	var resume uintptr
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if buf != nil {
		defer windows.NetApiBufferFree(buf)
	}
	if r != 0 {
		return nil
	}
	out := map[string]bool{}
	if read == 0 {
		return out
	}
	// LOCALGROUP_MEMBERS_INFO_0: one SID per member.
	for _, sid := range unsafe.Slice((**windows.SID)(unsafe.Pointer(buf)), read) {
		if sid != nil {
			out[sid.String()] = true
		}
	}
	return out
}
