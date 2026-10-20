// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package secrets

// defaultName is the key file Signalith makes in its keys folder, readable
// only by its own account (mode 0600, in a 0700 folder).
const defaultName = "master.key"

// defaultNote is added when describing the default key file.
const defaultNote = ""

func readDefault(path string) ([]byte, error) { return readKeyFile(path) }

func encodeDefault(raw []byte) ([]byte, error) { return keyText(raw), nil }
