// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

import "os"

// noFollow: links in Signalith's folders are refused by a check before
// opening instead.
const noFollow = 0

// giveToFolderOwner does nothing where files have no Unix owner: on
// Windows a new file takes its folder's access list.
func giveToFolderOwner(*os.File, string) error { return nil }
