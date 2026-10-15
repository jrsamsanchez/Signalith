//go:build unix

package main

import (
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

// ownerOf returns the owner of the file info describes.
func ownerOf(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
