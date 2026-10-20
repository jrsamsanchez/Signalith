// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "log/slog"

// hardenProcess does nothing here. On Windows only administrators and the
// SYSTEM account can read another account's process memory, and the
// service runs as its own account (NT SERVICE\Signalith).
func hardenProcess(*slog.Logger) {}
