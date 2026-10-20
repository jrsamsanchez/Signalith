// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cluster

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive lock on path, creating it if needed, and
// returns what releases it. It returns errLocked when another open file
// holds the lock, even one in this process: flock locks belong to one
// open file, so the same process cannot take it twice.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		switch {
		case errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN):
			return nil, errLocked
		case errors.Is(err, unix.ENOLCK) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL):
			return nil, fmt.Errorf("%w: %w", errLockUnsupported, err)
		}
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}
