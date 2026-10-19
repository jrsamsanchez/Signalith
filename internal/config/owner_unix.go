// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"syscall"
)

// noFollow makes opening a file fail when it is a symbolic link.
const noFollow = syscall.O_NOFOLLOW

// giveToFolderOwner gives the open file f the owner of dir when running
// as root, so a file root makes in the server's folder stays the
// server's.
func giveToFolderOwner(f *os.File, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 && st.Gid == 0 {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}
