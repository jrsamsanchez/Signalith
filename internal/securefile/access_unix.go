// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package securefile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// keepAccess gives tmp the mode and owner of the file it replaces. A
// command run as root (sudo signalith secrets encrypt) thus leaves the
// service's files owned by the service.
func keepAccess(_ string, old os.FileInfo, tmp *os.File) error {
	if err := tmp.Chmod(old.Mode().Perm()); err != nil {
		return err
	}
	st, ok := old.Sys().(*syscall.Stat_t)
	if ok && (int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid()) {
		// Only root, or an owner changing the group to one of its own,
		// may do this; otherwise the new file stays this account's.
		_ = tmp.Chown(int(st.Uid), int(st.Gid))
	}
	return nil
}

// makePrivate makes tmp readable and writable by its owner only.
func makePrivate(tmp *os.File) error { return tmp.Chmod(0o600) }

// newFileAccess keeps a new file at mode 0600 (os.CreateTemp's) and, when
// running as root, gives it the owner of the folder it is in: the
// service's own folder stays the service's.
func newFileAccess(tmp *os.File, dir string) error {
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if st, err := os.Stat(dir); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (sys.Uid != 0 || sys.Gid != 0) {
				return tmp.Chown(int(sys.Uid), int(sys.Gid))
			}
		}
	}
	return nil
}

// adminDir is privateDir: on Unix a private folder is already its
// owner's only.
func adminDir(dir, parent string, created bool) error { return privateDir(dir, parent, created) }

// privateDir sets dir to mode 0700 and, for a folder root just made, the
// owner of the folder above it. It works on the folder opened without
// following links, so a link put in its place meanwhile is not followed.
func privateDir(dir, parent string, created bool) error {
	f, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o700); err != nil {
		return err
	}
	if created && os.Geteuid() == 0 {
		if st, err := os.Stat(parent); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (sys.Uid != 0 || sys.Gid != 0) {
				return f.Chown(int(sys.Uid), int(sys.Gid))
			}
		}
	}
	return nil
}

// linkAllowed refuses, when running as root, a link that another account
// made.
func linkAllowed(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if os.Geteuid() != 0 || !ok || st.Uid == 0 {
		return nil
	}
	target, _ := os.Readlink(path)
	return fmt.Errorf("%s is a link to %s, made by another account (uid %d). Run as root, Signalith does not follow such a link, "+
		"since that account could point it at any file; use the file it points to, or replace the link with that file", path, target, st.Uid)
}

func otherLinks(path string) int {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink > 1 {
		return int(sys.Nlink - 1)
	}
	return 0
}

func isBusy(err error) bool { return errors.Is(err, syscall.EBUSY) }

// inUse is for Windows: here a file that is open can be replaced.
func inUse(error) bool { return false }
