// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"context"
	"io"
)

// saveBitLocker is for Windows, where the service can't ask BitLocker.
var saveBitLocker = func(context.Context, string, io.Writer) {}
