// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

// startUpdater does nothing here: a path unit starts the updater's
// service when the agent writes the ready file.
func (a *Agent) startUpdater() error { return nil }
