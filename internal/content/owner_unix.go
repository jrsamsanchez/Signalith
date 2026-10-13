//go:build unix

package content

import (
	"os"
	"syscall"
)

// giveToFolderOwner gives path the owner of dir when running as root, so
// an update root installs from the command line stays readable by the
// server.
func giveToFolderOwner(path, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 && st.Gid == 0 {
		return nil
	}
	return os.Lchown(path, int(st.Uid), int(st.Gid))
}
