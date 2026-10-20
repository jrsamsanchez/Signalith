// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package retention

import (
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"golang.org/x/sys/windows"
)

// diskSpace returns the bytes free for this process and the size of the
// disk that holds dir, or of its nearest existing parent.
func diskSpace(dir string) (free, total int64, err error) {
	p, err := windows.UTF16PtrFromString(existing(dir))
	if err != nil {
		return 0, 0, err
	}
	var f, t, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &f, &t, &totalFree); err != nil {
		return 0, 0, err
	}
	return int64(f), int64(t), nil
}

// restrictDir gives a folder an access list of its own, not inherited
// from the drive or its parent: full control for SYSTEM, Administrators,
// the Signalith service account (NT SERVICE\Signalith) and the account
// the server runs as, and nobody else. Files created in it inherit the
// list. Unix file modes do not do this on Windows.
func restrictDir(dir string) error { return securefile.MkdirPrivate(dir) }
