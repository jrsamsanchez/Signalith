//go:build !windows

package agentd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// updateFolder is the update folder as the updater sees it. The agent's
// sandbox can write the folder and the one it is in, so the updater opens
// both once, refusing links and folders anyone but it owns or can write,
// and does every read, write and delete relative to what it opened: a
// link swapped in later leads nowhere.
type updateFolder struct {
	state, dir int
}

func openUpdateFolder(p Paths) (*updateFolder, error) {
	open := func(at int, path string) (int, error) {
		fd, err := unix.Openat(at, path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, fmt.Errorf("the folder %s: %w (a link is refused)", path, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, err
		}
		if int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
			unix.Close(fd)
			return -1, fmt.Errorf("the folder %s is not the updater's own: it is owned by someone else, or others can write it", path)
		}
		return fd, nil
	}
	state, err := open(unix.AT_FDCWD, p.State)
	if err != nil {
		return nil, err
	}
	dir, err := open(state, filepath.Base(p.updateDir()))
	if err != nil {
		unix.Close(state)
		return nil, err
	}
	return &updateFolder{state: state, dir: dir}, nil
}

func (f *updateFolder) Close() {
	unix.Close(f.dir)
	unix.Close(f.state)
}

// exists says whether name is in the folder, as anything.
func (f *updateFolder) exists(name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(f.dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}

// open opens the plain file name in the folder (or, with state, in the
// folder above it) for reading.
func (f *updateFolder) open(name string, state bool) (*os.File, error) {
	at := f.dir
	if state {
		at = f.state
	}
	fd, err := unix.Openat(at, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	if st, err := file.Stat(); err != nil || !st.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a plain file", name)
	}
	return file, nil
}

func (f *updateFolder) remove(name string) error {
	if err := unix.Unlinkat(f.dir, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}
	return nil
}

// write writes name in the folder: to a new file, never through a link
// someone left, renamed into place.
func (f *updateFolder) write(name string, b []byte) error {
	tmp := name + ".tmp"
	_ = f.remove(tmp)
	fd, err := unix.Openat(f.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: tmp, Err: err}
	}
	file := os.NewFile(uintptr(fd), tmp)
	_, err = file.Write(b)
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(f.dir, tmp, f.dir, name)
	}
	if err != nil {
		_ = f.remove(tmp)
	}
	return err
}
