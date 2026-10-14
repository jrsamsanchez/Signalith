//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

// giveToOwnerOf gives path the owner and group of the folder dir, when
// running as root: a restore run with sudo writes files the service's
// account must read. Elsewhere new files already belong to whoever runs.
func giveToOwnerOf(path, dir string) {
	if os.Geteuid() != 0 {
		return
	}
	st, err := os.Stat(dir)
	if err != nil {
		return
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(path, int(s.Uid), int(s.Gid))
	}
}

func isReadOnly(err error) bool { return errors.Is(err, syscall.EROFS) }
