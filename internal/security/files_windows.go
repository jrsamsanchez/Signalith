// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package security

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Account is the account Signalith runs as, whose files are its own.
type Account struct {
	UID, GID int
	SID      string
}

// Access rights that let an account read or change a file.
const (
	readRights  = windows.ACCESS_MASK(0x1 | 0x80000000 | 0x10000000)                           // FILE_READ_DATA, GENERIC_READ, GENERIC_ALL
	writeRights = windows.ACCESS_MASK(0x2 | 0x4 | 0x40000000 | 0x10000000 | 0x40000 | 0x80000) // FILE_WRITE_DATA, FILE_APPEND_DATA, GENERIC_WRITE, GENERIC_ALL, WRITE_DAC, WRITE_OWNER
	inheritOnly = 0x08
)

// everyoneSIDs stand for every account on the computer.
var everyoneSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-32-545": true, // Users
	"S-1-5-4":      true, // Interactive
	"S-1-2-0":      true, // Local
}

// trustedInstaller is NT SERVICE\TrustedInstaller, which owns Windows'
// own files.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// trustedSID reports whether sid may use Signalith's files: SYSTEM,
// Administrators, Signalith's and TrustedInstaller's service accounts,
// the file's owner, or acct. Any other service's account is another
// account.
func trustedSID(sid, owner string, acct Account) bool {
	switch {
	case sid == "S-1-5-18", sid == sidAdmins, sid == "S-1-3-0",
		strings.EqualFold(sid, securefile.ServiceSID(securefile.ServiceName)), sid == trustedInstaller,
		sid == owner, acct.SID != "" && strings.EqualFold(sid, acct.SID):
		return true
	}
	return false
}

// probePerm reads who other than Signalith and administrators may read
// or change path, from its access list. Mode bits are never used here:
// Windows shows every file as 0666.
func probePerm(path string, acct Account) (*Perm, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	p := &Perm{}
	owner := ""
	if o, _, err := sd.Owner(); err == nil && o != nil {
		owner = o.String()
		p.Owner = accountName(o)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		// No access list at all: everyone may do anything.
		p.OtherRead, p.OtherWrite = true, true
		return p, nil
	}
	var admins map[string]bool // members of Administrators, read when needed
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnly != 0 {
			continue
		}
		sidp := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sid := sidp.String()
		if trustedSID(sid, owner, acct) {
			continue
		}
		read, write := ace.Mask&readRights != 0, ace.Mask&writeRights != 0
		if everyoneSIDs[sid] {
			p.OtherRead = p.OtherRead || read
			p.OtherWrite = p.OtherWrite || write
			continue
		}
		if !read && !write {
			continue
		}
		// An administrator's own entry, which signalith commands run as
		// Administrator used to add, gives nothing the Administrators
		// entry doesn't.
		if admins == nil {
			if admins = adminMembers(); admins == nil {
				admins = map[string]bool{}
			}
		}
		if admins[sid] {
			continue
		}
		if read || write {
			p.SomeRead = p.SomeRead || read
			p.SomeWrite = p.SomeWrite || write
			if p.Group == "" {
				p.Group = accountName(sidp)
			}
		}
	}
	return p, nil
}

func accountName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

// CurrentAccount is the account this process runs as.
func CurrentAccount() Account {
	a := Account{UID: -1, GID: -1}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		a.SID = u.User.Sid.String()
	}
	return a
}

// isService reports whether this process runs as a Windows service.
func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
