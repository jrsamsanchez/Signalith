// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package security

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Account is the account Signalith runs as, whose files are its own.
type Account struct {
	UID, GID int    // Unix; -1 when unknown
	SID      string // Windows
}

// probePerm reads who other than acct may use path, from its mode bits
// and owner. Its own group counts only when that group is not the
// account's own. A link is followed: what counts is the file it points
// to (Let's Encrypt's live/ folder and Kubernetes secrets are links).
func probePerm(path string, acct Account) (*Perm, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	mode := st.Mode().Perm()
	p := &Perm{OtherRead: mode&0o004 != 0, OtherWrite: mode&0o002 != 0}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return p, nil
	}
	uid, gid := int(sys.Uid), int(sys.Gid)
	if gid != acct.GID || acct.GID < 0 {
		p.GroupRead, p.GroupWrite = mode&0o040 != 0, mode&0o020 != 0
	}
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		p.Group = g.Name
	} else {
		p.Group = "gid " + strconv.Itoa(gid)
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		p.Owner = u.Username
	} else {
		p.Owner = "uid " + strconv.Itoa(uid)
	}
	p.WrongOwner = acct.UID >= 0 && uid != acct.UID && uid != 0
	return p, nil
}

// CurrentAccount is the account this process runs as.
func CurrentAccount() Account { return Account{UID: os.Geteuid(), GID: os.Getegid()} }

// isService reports whether this process runs as a Windows service;
// never here.
func isService() bool { return false }

// ownerOf is the account that owns path.
func ownerOf(path string) (Account, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return Account{}, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return Account{}, false
	}
	return Account{UID: int(sys.Uid), GID: int(sys.Gid)}, true
}
