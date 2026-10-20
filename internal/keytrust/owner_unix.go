// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package keytrust

import (
	"os"
	"syscall"
)

// ownLike gives paths the owner and group of ref when run as root, so
// files root writes for the service stay readable by it. Run as anyone
// else it does nothing: their files are already theirs.
func ownLike(ref string, paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(ref)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	return nil
}
