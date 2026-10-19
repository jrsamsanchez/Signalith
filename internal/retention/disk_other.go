// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package retention

import (
	"errors"
	"os"
)

func diskSpace(string) (int64, int64, error) { return 0, 0, errors.ErrUnsupported }

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }
