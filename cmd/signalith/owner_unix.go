//go:build unix

package main

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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

// giveTree gives dir, or the file dir, and everything in it to uid:gid
// with chown, not following links. A missing path is skipped.
func giveTree(dir string, uid, gid int, chown func(string, int, int) error) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return chown(p, uid, gid)
	})
}
