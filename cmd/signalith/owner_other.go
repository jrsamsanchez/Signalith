// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import (
	"io/fs"

	"github.com/jrsamsanchez/signalith/internal/security"
)

// runningAsAdmin reports whether this process runs as an elevated
// Administrator.
func runningAsAdmin() bool { return security.Elevated() }

// serviceOwner: outside Unix the service's access comes from the folders'
// access lists (securefile and signalith service install).
func serviceOwner() (uid, gid int, ok bool) { return 0, 0, false }

// ownerOf: outside Unix a file's access is its access list, which
// securefile sets.
func ownerOf(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
