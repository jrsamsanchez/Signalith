// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package securefile writes files that hold passwords and keys: whole or
// not at all, and readable only by Signalith's own account.
//
// A new file is readable and writable by its owner only (mode 0600), and a
// new private folder only by its owner (0700). Windows ignores those
// modes, so there a new file or private folder gets an access list of its
// own instead, not inherited from the folder above: full control for
// SYSTEM, Administrators, the Signalith service account (NT
// SERVICE\Signalith) and the account that made it, and nobody else. A file
// that is replaced keeps its mode, owner and access list (Replace and
// PreparePrivate make it private all the same). A symbolic link
// is followed: the file it points to is replaced and the link stays. Run
// as root, a link made by another account is refused instead, since the
// account the server runs as could otherwise point one of its own files
// at a system file for root to overwrite.
package securefile

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// ServiceName is the Windows service, whose virtual account NT
// SERVICE\Signalith the server runs as.
const ServiceName = "Signalith"

// WriteFile replaces path with data, through a temporary file in the same
// folder that is then renamed into place, so a crash never leaves half a
// file. Missing folders above it are created. When path is a symbolic
// link, the file it points to is replaced and the link stays.
func WriteFile(path string, data []byte) error {
	p, err := Prepare(path, data)
	if err != nil {
		return err
	}
	return p.Commit()
}

// Pending is a file written next to its destination but not yet in place,
// so several files can be written before any of them changes: Commit puts
// it in place, Discard throws it away.
type Pending struct {
	path string
	tmp  string
	// data is a copy of the content, for a file that can only be written
	// in place (see Commit); it is cleared when the write is done, and
	// the caller may clear its own as soon as Prepare returns.
	data []byte
}

// Path returns the file the pending write replaces: the path given to
// Prepare, or the file a link there points to.
func (p *Pending) Path() string { return p.path }

// Prepare writes data to a temporary file next to path, with the access
// path has (or a new file's), and returns it without replacing path.
func Prepare(path string, data []byte) (*Pending, error) { return prepare(path, data, false) }

// PreparePrivate is Prepare for a file that must be private whatever the
// file it replaces allowed, such as a key: readable and writable by its
// owner only (mode 0600, keeping the owner), or on Windows the protected
// access list of a new file.
func PreparePrivate(path string, data []byte) (*Pending, error) { return prepare(path, data, true) }

// Replace is WriteFile for a file Signalith keeps for itself in a folder
// of its own, such as the Settings page's settings.yaml: a symbolic link
// at path is replaced by the new file instead of followed, so the file it
// points to is left as it is, and the new file is made as a new one is
// (private, and run as root, owned by the folder's owner). A file it
// replaces keeps its owner but is made private whatever it allowed, as
// PreparePrivate does: mode 0600, or on Windows the protected access list
// of a new file.
func Replace(path string, data []byte) error {
	p, err := PrepareReplace(path, data)
	if err != nil {
		return err
	}
	return p.Commit()
}

// PrepareReplace is Prepare for Replace: a symbolic link at path is
// replaced, not followed, and the new file is private.
func PrepareReplace(path string, data []byte) (*Pending, error) {
	return prepareAt(path, data, true, false)
}

func prepare(path string, data []byte, private bool) (*Pending, error) {
	path, err := resolveLink(path)
	if err != nil {
		return nil, err
	}
	return prepareAt(path, data, private, true)
}

// prepareAt writes the temporary file for path. When follow is false, a
// symbolic link at path counts as no file: the new one replaces the link.
func prepareAt(path string, data []byte, private, follow bool) (*Pending, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Pending, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	stat := os.Stat
	if !follow {
		stat = os.Lstat
	}
	if st, err := stat(path); err == nil && st.Mode()&fs.ModeSymlink == 0 {
		if err := keepAccess(path, st, tmp); err != nil {
			return fail(fmt.Errorf("could not give the new %s the same permissions as the old one: %w", path, err))
		}
		if private {
			if err := makePrivate(tmp); err != nil {
				return fail(fmt.Errorf("could not make %s private: %w", path, err))
			}
		}
	} else if err == nil || errors.Is(err, os.ErrNotExist) {
		if err := newFileAccess(tmp, dir); err != nil {
			return fail(fmt.Errorf("could not make %s private: %w", path, err))
		}
	} else {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	return &Pending{path: path, tmp: tmp.Name(), data: bytes.Clone(data)}, nil
}

// resolveLink returns the file to replace for path: path itself, or, when
// path is a symbolic link, the file it points to. Replacing the link with
// a file instead would leave the old content, such as plain-text
// passwords, in the file it pointed to, and later changes there would be
// ignored.
func resolveLink(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return path, nil
	}
	if err := linkAllowed(path, fi); err != nil {
		return "", err
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s is a link to a file that cannot be found: %w", path, err)
	}
	return target, nil
}

// rename puts a file in place; tests replace it, and fileInUse.
var (
	rename    = os.Rename
	fileInUse = inUse
)

// renameWait is how long a rename is tried again while the file is open
// elsewhere for a moment (Windows).
const renameWait = 2 * time.Second

// renameRetry renames old to new, trying again for up to renameWait while
// the file is in use: on Windows, a reader that has the old file open
// keeps it from being replaced until it closes it.
func renameRetry(old, new string) error {
	deadline := time.Now().Add(renameWait)
	pause := 5 * time.Millisecond
	for {
		err := rename(old, new)
		if err == nil || !fileInUse(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(pause)
		pause = min(2*pause, 100*time.Millisecond)
	}
}

// Commit puts the file in place.
func (p *Pending) Commit() error {
	defer p.done()
	err := renameRetry(p.tmp, p.path)
	if err != nil && isBusy(err) {
		// A file mounted into a container on its own (a Docker bind mount
		// of one file) cannot be replaced, only written in place.
		err = writeInPlace(p.path, p.data)
		os.Remove(p.tmp)
		return err
	}
	if err != nil {
		os.Remove(p.tmp)
	}
	return err
}

// CommitNew puts the file in place only if nothing is there yet, and
// returns an error wrapping fs.ErrExist otherwise, so two programs making
// the same file at once cannot both win.
func (p *Pending) CommitNew() error {
	defer p.done()
	defer os.Remove(p.tmp)
	err := os.Link(p.tmp, p.path)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return err
	}
	// The file system has no hard links: check, then rename.
	if _, serr := os.Lstat(p.path); serr == nil {
		return &fs.PathError{Op: "create", Path: p.path, Err: fs.ErrExist}
	}
	return renameRetry(p.tmp, p.path)
}

// Discard removes the temporary file.
func (p *Pending) Discard() {
	p.done()
	os.Remove(p.tmp)
}

// done clears the copy of the content.
func (p *Pending) done() {
	clear(p.data)
	p.data = nil
}

func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// MakePrivateFile makes the open file f private (see the package
// comment): mode 0600, and on Windows an access list of its own instead of
// the folder's. Call it on a file just created, before writing to it.
func MakePrivateFile(f *os.File) error { return makePrivate(f) }

// OtherLinks returns how many other names (hard links) the file at path
// has. Replacing the file gives path new content, but those names keep
// the old, so a caller encrypting passwords in it should say so. It is 0
// when there are none, the file does not exist, or on Windows.
func OtherLinks(path string) int { return otherLinks(path) }

// MkdirPrivate creates dir, and any missing folders above it, and makes
// dir private (see the package comment). A dir that already exists is
// made private too when this account may change it, but it must be a
// folder itself, not a link to one: following a link someone else made
// could change the permissions of any folder.
func MkdirPrivate(dir string) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	created := err == nil
	if !created {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if fi.Mode().Type() != fs.ModeDir {
			return fmt.Errorf("%s is not a folder of its own (it is a link or another kind of file); move it away so Signalith can make the folder", dir)
		}
	}
	if perr := privateDir(dir, parent, created); perr != nil && created {
		return fmt.Errorf("could not make %s private: %w", dir, perr)
	}
	return nil
}

// ServiceSID returns the security identifier of a Windows service's
// virtual account (NT SERVICE\<name>): S-1-5-80- and the SHA-1 of the
// upper-case service name in UTF-16, as five numbers. Windows works it out
// the same way, so it is known before the service is installed.
func ServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	parts := make([]string, 5)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return "S-1-5-80-" + strings.Join(parts, "-")
}
