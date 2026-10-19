// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package securefile

import "os"

func keepAccess(_ string, old os.FileInfo, tmp *os.File) error { return tmp.Chmod(old.Mode().Perm()) }

func makePrivate(tmp *os.File) error { return tmp.Chmod(0o600) }

func newFileAccess(tmp *os.File, _ string) error { return tmp.Chmod(0o600) }

func privateDir(dir, _ string, _ bool) error { return os.Chmod(dir, 0o700) }

func linkAllowed(string, os.FileInfo) error { return nil }

func otherLinks(string) int { return 0 }

func isBusy(error) bool { return false }

func inUse(error) bool { return false }
