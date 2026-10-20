// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Filesystem types from statfs, as in linux/magic.h and the CIFS client.
const (
	nfsMagic      = 0x6969
	smbMagic      = 0x517B
	cifsMagic     = 0xFF534D42
	smb2Magic     = 0xFE534D42
	fuseMagic     = 0x65735546
	v9fsMagic     = 0x01021997
	virtiofsMagic = 0x6A656A63
)

// FolderFilesystem names the filesystem dir is on when it matters for a
// state folder: a network one (network), or one that bind mounts from
// Docker Desktop and WSL use, where file locks may not work (shared).
func FolderFilesystem(dir string) (network, shared string, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", "", err
	}
	switch uint32(st.Type) {
	case nfsMagic:
		return "NFS", "", nil
	case smbMagic, cifsMagic, smb2Magic:
		return "SMB", "", nil
	case fuseMagic:
		return "", "FUSE", nil
	case v9fsMagic:
		return "", "9p", nil
	case virtiofsMagic:
		return "", "virtiofs", nil
	}
	return "", "", nil
}

// fallbackStateDirs are local folders for the state folder when the one
// that holds lookups.dir cannot be used: systemd's StateDirectory, then
// the usual place.
func fallbackStateDirs() []string {
	var out []string
	if d, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":"); d != "" {
		out = append(out, d)
	}
	return append(out, systemdStateDir)
}
