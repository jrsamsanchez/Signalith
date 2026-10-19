// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"fmt"
	"slices"
)

// Windows accounts that may own the agent's folder and the one above it:
// SYSTEM, Administrators and TrustedInstaller. Any user may create
// folders in ProgramData; one who owned the agent's folder, or the one
// above it, could swap in settings of their own (another server, another
// certificate authority), and the agent, which runs as SYSTEM, would run
// the Fluent Bit configuration that server sends.
var safeOwners = []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}

// folderProblem says what is wrong with a folder owned by owner (a SID),
// which is a link or junction when link; nil when nothing is.
func folderProblem(path, owner string, link bool) error {
	if link {
		return fmt.Errorf("%s is a link or junction, so the agent does not use it; remove it and run the line from Add data > Signalith Agent again", path)
	}
	if !slices.Contains(safeOwners, owner) {
		return fmt.Errorf("%s belongs to %s, not to SYSTEM or Administrators, so the agent does not use it; make Administrators its owner (icacls %q /setowner *S-1-5-32-544) or run the line from Add data > Signalith Agent again", path, owner, path)
	}
	return nil
}
