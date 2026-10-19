// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"strings"
	"testing"
)

func TestFolderProblem(t *testing.T) {
	for _, owner := range safeOwners {
		if err := folderProblem(`C:\ProgramData`, owner, false); err != nil {
			t.Errorf("%s: %v", owner, err)
		}
	}
	if err := folderProblem(`C:\ProgramData\Signalith Agent`, "S-1-5-32-544", true); err == nil || !strings.Contains(err.Error(), "link or junction") {
		t.Errorf("link: %v", err)
	}
	// A standard user who made the folder first.
	if err := folderProblem(`C:\ProgramData\Signalith Agent`, "S-1-5-21-1-2-3-1001", false); err == nil || !strings.Contains(err.Error(), "belongs to S-1-5-21-1-2-3-1001") {
		t.Errorf("user's folder: %v", err)
	}
}
