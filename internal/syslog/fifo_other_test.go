// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package syslog

import "testing"

// makeFIFO makes nothing: Windows has no named pipes in a folder.
func makeFIFO(*testing.T, string) int { return 0 }
