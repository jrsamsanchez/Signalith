// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package assets

import (
	"errors"

	"golang.org/x/sys/windows"
)

// inUse reports whether a rename failed because the file is open
// elsewhere for a moment: Windows does not replace a file that is open
// without delete sharing, as Go opens files to read. Depending on how it
// was opened, that is access denied or a sharing violation.
func inUse(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
