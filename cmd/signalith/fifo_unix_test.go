// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "syscall"

func makeFIFO(path string) error { return syscall.Mkfifo(path, 0o600) }
