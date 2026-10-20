// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agentd

// CheckFolders does nothing here: on Linux the agent's folders are under
// /etc and /var/lib, which only root may change.
func CheckFolders(Paths) error { return nil }
