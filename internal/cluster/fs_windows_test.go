// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cluster

import (
	"strings"
	"testing"
)

// A state folder on a UNC path is a network share, refused; a local one
// is not.
func TestCheckFolderRefusesUNCPaths(t *testing.T) {
	if _, err := CheckFolder(`\\localhost\signalith-test-missing\state`); err == nil || !strings.Contains(err.Error(), "network share") {
		t.Errorf("UNC path: %v", err)
	}
	if w, err := CheckFolder(t.TempDir()); err != nil || len(w) != 0 {
		t.Errorf("local folder: %v %v", w, err)
	}
}
