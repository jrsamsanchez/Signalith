// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// giveTree gives path, and when it is a folder what is in it, to uid:gid
// (signalith join, as root, giving the service's account what join made).
// The folders the service's account can write are never trusted:
//   - the folders above path are opened one at a time without following a
//     link, except a link in a folder only root can write, which nobody
//     else could have made;
//   - each entry is opened without following a link (O_PATH|O_NOFOLLOW)
//     and changed through that descriptor (change), so what changes is
//     the file that was checked, whatever is renamed meanwhile;
//   - only what this process's user owns changes (what join made; the
//     service's own files stay as they are), never a link, a file with
//     more than one name, or anything but files and folders, and only
//     folders this user or uid owns are entered;
//   - a folder changes after what is in it, so the service's account
//     cannot change it while it is read.
//
// A missing path is skipped.
func giveTree(path string, uid, gid int, change func(fd int, path string, uid, gid int) error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, name := filepath.Split(abs)
	if name == "" {
		return fmt.Errorf("will not give %s away", abs)
	}
	dfd, err := openDirNoUserLinks(dir, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	defer unix.Close(dfd)
	return giveAt(dfd, name, abs, os.Geteuid(), uid, gid, change, 0)
}

// chownFD changes the owner of the file open as fd (O_PATH).
func chownFD(fd int, _ string, uid, gid int) error {
	return unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH)
}

// giveAt gives the entry name of the folder dfd (at path) and what is in
// it from the user from to uid:gid; see giveTree.
func giveAt(dfd int, name, path string, from, uid, gid int, change func(int, string, int, int) error, depth int) error {
	fd, err := unix.Openat(dfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if st.Nlink > 1 {
			return nil
		}
	case unix.S_IFDIR:
		if (int(st.Uid) == from || int(st.Uid) == uid) && depth < 32 {
			if err := giveIn(fd, path, from, uid, gid, change, depth); err != nil {
				return err
			}
		}
	default:
		// A link, a device, a socket: never followed, never changed.
		return nil
	}
	if int(st.Uid) != from {
		return nil
	}
	if err := change(fd, path, uid, gid); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// giveIn gives what is in the folder open as fd (O_PATH) at path.
func giveIn(fd int, path string, from, uid, gid int, change func(int, string, int, int) error, depth int) error {
	rfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f := os.NewFile(uintptr(rfd), path)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, n := range names {
		if err := giveAt(int(f.Fd()), n, filepath.Join(path, n), from, uid, gid, change, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// rootOnly reports whether only root can add or rename entries in the
// folder st.
func rootOnly(st *unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&0o022 == 0
}

// openDirNoUserLinks opens the absolute folder dir (O_PATH), one part at
// a time without following a link, except a link in a folder only root
// can write.
func openDirNoUserLinks(dir string, hops int) (int, error) {
	if hops > 40 {
		return -1, unix.ELOOP
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.Trim(filepath.Clean(dir), "/"), "/")
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(fd)
			return -1, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			unix.Close(fd)
			unix.Close(next)
			return -1, err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			unix.Close(fd)
			fd = next
			continue
		case unix.S_IFLNK:
			unix.Close(next)
			var pst unix.Stat_t
			if err := unix.Fstat(fd, &pst); err != nil || !rootOnly(&pst) {
				unix.Close(fd)
				return -1, fmt.Errorf("%s is a link in a folder others than root can write, which is not followed", "/"+filepath.Join(parts[:i+1]...))
			}
			buf := make([]byte, 4096)
			n, err := unix.Readlinkat(fd, part, buf)
			unix.Close(fd)
			if err != nil {
				return -1, err
			}
			target := string(buf[:n])
			if !filepath.IsAbs(target) {
				target = filepath.Join("/"+filepath.Join(parts[:i]...), target)
			}
			return openDirNoUserLinks(filepath.Join(append([]string{target}, parts[i+1:]...)...), hops+1)
		default:
			unix.Close(fd)
			unix.Close(next)
			return -1, unix.ENOTDIR
		}
	}
	return fd, nil
}
