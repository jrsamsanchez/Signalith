//go:build windows

package agentd

import (
	"fmt"
	"os"
	"path/filepath"
)

// updateFolder is the update folder as the updater sees it. On Windows
// the agent runs as SYSTEM, as the updater does, so the folder is no
// boundary; links are refused all the same.
type updateFolder struct {
	state, dir string
}

func openUpdateFolder(p Paths) (*updateFolder, error) {
	for _, d := range []string{p.State, p.updateDir()} {
		st, err := os.Lstat(d)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return nil, fmt.Errorf("the folder %s is not a plain folder", d)
		}
	}
	return &updateFolder{state: p.State, dir: p.updateDir()}, nil
}

func (f *updateFolder) Close() {}

func (f *updateFolder) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(f.dir, name))
	return err == nil
}

func (f *updateFolder) open(name string, state bool) (*os.File, error) {
	dir := f.dir
	if state {
		dir = f.state
	}
	return openNoFollow(filepath.Join(dir, name))
}

func (f *updateFolder) remove(name string) error {
	if err := os.Remove(filepath.Join(f.dir, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (f *updateFolder) write(name string, b []byte) error {
	return writeNoFollow(filepath.Join(f.dir, name), b)
}

// writeNoFollow writes a file in a folder the agent's sandbox can write:
// to a new file (never through a link someone left), whose mode is set on
// the open file, then renamed into place.
func writeNoFollow(path string, b []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
