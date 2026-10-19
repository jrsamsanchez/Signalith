// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

// makeFIFO does nothing on Windows, which has no FIFOs in folders.
func makeFIFO(path string) error { return nil }
