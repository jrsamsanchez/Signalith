// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package config

// FolderFilesystem cannot tell network filesystems apart here.
func FolderFilesystem(string) (network, shared string, err error) { return "", "", nil }

// fallbackStateDirs: none here.
func fallbackStateDirs() []string { return nil }
