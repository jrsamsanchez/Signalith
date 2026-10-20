// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// FolderFilesystem reports a state folder on a network share: a UNC path
// (\\server\share) or a mapped network drive.
func FolderFilesystem(dir string) (network, shared string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(abs, `\\`) && !strings.HasPrefix(abs, `\\?\`) && !strings.HasPrefix(abs, `\\.\`) {
		return "SMB", "", nil
	}
	vol := filepath.VolumeName(abs)
	if vol == "" {
		return "", "", nil
	}
	root, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return "", "", err
	}
	if windows.GetDriveType(root) == windows.DRIVE_REMOTE {
		return "SMB", "", nil
	}
	return "", "", nil
}

// fallbackStateDirs are local folders for the state folder when the one
// that holds lookups.dir cannot be used.
func fallbackStateDirs() []string {
	if d := os.Getenv("ProgramData"); d != "" {
		return []string{filepath.Join(d, "Signalith")}
	}
	return nil
}
