//go:build !windows

package config

import (
	"os"
	"syscall"
)

// shareWithGroup gives the file at path to the group of the folder dir,
// which may read it.
func shareWithGroup(path, dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Lchown(path, -1, int(st.Gid)); err != nil {
		return err
	}
	return os.Chmod(path, 0o640)
}
