// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package keytrust

// ownLike does nothing where files have no Unix owner.
func ownLike(ref string, paths ...string) error { return nil }
