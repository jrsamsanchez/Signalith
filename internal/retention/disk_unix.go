// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package retention

import (
	"os"

	"golang.org/x/sys/unix"
)

// diskSpace returns the bytes free for this process and the size of the
// disk that holds dir, or of its nearest existing parent.
func diskSpace(dir string) (free, total int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(existing(dir), &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}

// restrictDir makes a folder readable by its owner only.
func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }
