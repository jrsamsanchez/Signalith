// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"os"
	"syscall"
)

// shareWithGroup gives the file at path to the group of the folder dir,
// which may read it. It changes the file it opened, never one a link
// points to.
func shareWithGroup(path, dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chown(-1, int(st.Gid)); err != nil {
		return err
	}
	return f.Chmod(0o640)
}
