// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package content

// giveToFolderOwner does nothing where files inherit their folder's
// permissions.
func giveToFolderOwner(path, dir string) error { return nil }
