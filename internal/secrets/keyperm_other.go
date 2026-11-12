// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package secrets

import "os"

// keyFileWarning has nothing to check here.
func keyFileWarning(string, os.FileInfo) string { return "" }

// fileWarning is keyFileWarning for any key file.
func fileWarning(string, string, os.FileInfo) string { return "" }

// accessHint says how to let Signalith read a key file it may not.
func accessHint(string) string {
	return "Run this as the account the server runs as"
}
