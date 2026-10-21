// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// runningAsAdmin reports whether this process runs as root.
func runningAsAdmin() bool { return os.Geteuid() == 0 }

// serviceOwner is the uid and gid of the signalith account the packages
// make for the service; ok is false when there is none.
func serviceOwner() (uid, gid int, ok bool) {
	u, err := user.Lookup("signalith")
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	return uid, gid, err1 == nil && err2 == nil
}

// asServiceUser refuses to run command as root when the state folder
// belongs to another user: that user could have put links in it that root
// would follow. A missing folder, or one root owns, is fine.
func asServiceUser(state, command string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(state)
	if err != nil {
		return nil
	}
	uid, _, ok := ownerOf(fi)
	if !ok || uid == 0 {
		return nil
	}
	name := strconv.Itoa(uid)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	return fmt.Errorf("%s belongs to %s, so this is not run as root: run it as the user Signalith runs as, e.g. sudo -u %s signalith %s", state, name, name, command)
}

// ownerOf returns the owner of the file info describes.
func ownerOf(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
