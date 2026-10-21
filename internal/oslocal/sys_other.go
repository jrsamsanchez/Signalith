// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package oslocal

import (
	"net/url"
	"os"

	"golang.org/x/sys/unix"
)

var osStat = os.Stat

func freeBytes(dir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// systemProxy: other systems have no machine-wide setting beyond
// HTTPS_PROXY, which the client reads.
func systemProxy() *url.URL { return nil }
