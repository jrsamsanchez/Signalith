// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package respond

import "os/exec"

// setProcessGroup leaves the program as exec starts it: it is stopped
// when it runs out of time.
func setProcessGroup(cmd *exec.Cmd) {}
