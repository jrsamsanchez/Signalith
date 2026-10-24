// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package reportkeys

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive lock for path, waiting at most lockWait,
// and returns what releases it. It locks the folder path is in rather
// than a file of its own: nothing is created, so a command run as root
// leaves no file the service cannot open, and there is no file a link
// could be put in place of. A filesystem without locks gets none: the
// in-process mutex still holds.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			if time.Now().Before(deadline) {
				time.Sleep(lockPoll)
				continue
			}
			err = errBusy
		}
		break
	}
	if err != nil {
		f.Close()
		if errors.Is(err, unix.ENOLCK) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return func() {}, nil
		}
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}
