// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "os"

// fileOwner reports no owner where files have no Unix owner.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
