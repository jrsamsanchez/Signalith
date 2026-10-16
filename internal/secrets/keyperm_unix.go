//go:build unix

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// keyFileWarning says what is wrong with who may use a master key file:
// other accounts may read or change it, or it belongs to an account that
// is neither this one nor root. A command run as root may use the
// service's key, which belongs to the service.
func keyFileWarning(path string, st os.FileInfo) string {
	return fileWarning("The master key", path, st)
}

// fileWarning is keyFileWarning for any key file; what names it.
func fileWarning(what, path string, st os.FileInfo) string {
	var w []string
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		w = append(w, fmt.Sprintf("other accounts on this computer can read or change it (mode %04o); make it private with: chmod 600 %s", perm, path))
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if euid := os.Geteuid(); euid != 0 && int(sys.Uid) != 0 && int(sys.Uid) != euid {
			w = append(w, fmt.Sprintf("it belongs to another account (uid %d), which could replace it; make it this account's own", sys.Uid))
		}
	}
	if len(w) == 0 {
		return ""
	}
	return what + " " + path + " is not private: " + strings.Join(w, "; and ")
}

// accessHint says how to let Signalith read a key file it may not.
func accessHint(path string) string {
	return fmt.Sprintf("Run this as the account the server runs as, or as root (sudo); the service's own account must own the key: sudo chown -R signalith %s", filepath.Dir(path))
}
