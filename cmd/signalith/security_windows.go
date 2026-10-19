// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/jrsamsanchez/signalith/internal/security"
)

// saveBitLocker asks BitLocker about every drive, when run as
// Administrator, and saves the answer in the state folder: the service's
// account can't ask, so the Security page shows this answer. Tests
// replace it.
var saveBitLocker = func(ctx context.Context, stateDir string, out io.Writer) {
	if !security.Elevated() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	vols, err := security.QueryBitLocker(ctx)
	if err != nil {
		fmt.Fprintln(out, "Couldn't ask BitLocker about the drives:", err)
		return
	}
	if err := security.SaveDisks(stateDir, security.SavedDisks{CheckedAt: time.Now().UTC(), Volumes: vols}); err != nil {
		fmt.Fprintln(out, "Couldn't save the disk encryption result:", err)
		return
	}
	fmt.Fprintln(out, "Saved the disk encryption result for the Security page.")
}
