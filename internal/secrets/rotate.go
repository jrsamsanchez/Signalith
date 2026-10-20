// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Rotation is a new master key written next to the key file but not yet
// in use. Re-encrypt every stored value with Seal, write those files
// (securefile.Prepare), then Commit; or Discard to change nothing. If the
// files cannot all be put in place after Commit, Undo puts the previous
// key back; otherwise Done forgets it.
//
// BeginNew makes a Rotation for the first master key, used the same way,
// so that a command that cannot write its files leaves no key behind.
type Rotation struct {
	k       *Keyring
	path    string
	next    *masterKey
	pending *securefile.Pending
	backup  []byte
	// first is set for the first master key (BeginNew); madeDir is the
	// keys folder it made, removed again if the key is not kept.
	first   bool
	madeDir string
}

// BeginNew makes a master key for a keyring that has none yet, without
// putting it in place. It fails if there is one.
func (k *Keyring) BeginNew() (*Rotation, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensure(); err == nil {
		return nil, fmt.Errorf("there is a master key already (%s)", k.src)
	} else if !errors.Is(err, ErrNoKey) {
		return nil, err
	}
	path := k.DefaultPath()
	if path == "" {
		return nil, &NoKeyError{}
	}
	raw := make([]byte, keySize)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	next, err := newMasterKey(raw)
	if err != nil {
		return nil, err
	}
	data, err := encodeDefault(raw)
	if err != nil {
		return nil, fmt.Errorf("could not protect a new master key: %w", err)
	}
	defer clear(data)
	dir := filepath.Dir(path)
	madeDir := ""
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		madeDir = dir
	}
	if err := securefile.MkdirPrivate(dir); err != nil {
		return nil, fmt.Errorf("could not make a folder for the master key: %w", err)
	}
	p, err := securefile.PreparePrivate(path, data)
	if err != nil {
		removeIfEmpty(madeDir)
		return nil, fmt.Errorf("could not save a new master key: %w", err)
	}
	return &Rotation{k: k, path: path, next: next, pending: p, first: true, madeDir: madeDir}, nil
}

// removeIfEmpty removes a folder this command made, if nothing is in it.
func removeIfEmpty(dir string) {
	if dir != "" {
		os.Remove(dir)
	}
}

// BeginRotation makes a new master key. Only a key kept in a file can be
// rotated: the default key file or SIGNALITH_MASTER_KEY_FILE.
func (k *Keyring) BeginRotation() (*Rotation, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensure(); err != nil {
		if errors.Is(err, ErrNoKey) {
			return nil, errors.New("there is no master key yet, so there is nothing to rotate; Signalith makes one the first time it stores a password or key")
		}
		return nil, err
	}
	src := k.src
	switch src.Kind {
	case FromEnv:
		return nil, errors.New("the master key comes from the SIGNALITH_MASTER_KEY environment variable, which this command cannot change; " +
			"put the key in a file and point SIGNALITH_MASTER_KEY_FILE at it, then run this again")
	case FromCredential:
		return nil, fmt.Errorf("the master key is a systemd credential (%s); run this command outside the service, as root, so it rotates the file systemd reads", src.Path)
	}
	if _, err := os.Stat(src.Path + ".old"); err == nil {
		return nil, fmt.Errorf("a previous rotation is not finished: %s.old is still there. Check with: signalith secrets status, then run: signalith secrets rotate-master -prune", src.Path)
	}
	backup, err := os.ReadFile(src.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the master key %s: %w", src.Path, err)
	}
	raw := make([]byte, keySize)
	defer clear(raw)
	var next *masterKey
	for next == nil || next.id == k.cur.id {
		if _, err := rand.Read(raw); err != nil {
			clear(backup)
			return nil, err
		}
		if next, err = newMasterKey(raw); err != nil {
			clear(backup)
			return nil, err
		}
	}
	var data []byte
	if src.Kind == FromDefault {
		data, err = encodeDefault(raw)
	} else {
		data = keyText(raw)
	}
	if err != nil {
		clear(backup)
		return nil, fmt.Errorf("could not protect the new master key: %w", err)
	}
	defer clear(data)
	// The new key is private whatever the old file allowed.
	p, err := securefile.PreparePrivate(src.Path, data)
	if err != nil {
		clear(backup)
		return nil, fmt.Errorf("could not write the new master key next to %s: %w", src.Path, err)
	}
	return &Rotation{k: k, path: src.Path, next: next, pending: p, backup: backup}, nil
}

// Path returns the key file being rotated.
func (r *Rotation) Path() string { return r.path }

// KeyID returns the new key's id.
func (r *Rotation) KeyID() string { return r.next.id }

// Seal encrypts plain for the setting field with the new key.
func (r *Rotation) Seal(field, plain string) (string, error) {
	if plain == "" || IsSealed(plain) {
		return plain, nil
	}
	return r.next.seal(field, plain)
}

// Commit makes the new key the one in use and keeps the current one as
// the key file with .old added, so values not yet re-encrypted can still
// be opened. If it fails, the current key stays in use.
func (r *Rotation) Commit() error {
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	if r.first {
		if err := r.pending.CommitNew(); err != nil {
			removeIfEmpty(r.madeDir)
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("another program (the server?) made a master key at %s meanwhile; run the command again to use it", r.path)
			}
			return fmt.Errorf("could not save the new master key %s: %w", r.path, err)
		}
		r.k.reset()
		return nil
	}
	if err := securefile.WriteFile(r.path+".old", r.backup); err != nil {
		r.pending.Discard()
		clear(r.backup)
		return fmt.Errorf("could not keep the current master key as %s.old: %w", r.path, err)
	}
	if err := r.pending.Commit(); err != nil {
		os.Remove(r.path + ".old")
		clear(r.backup)
		return fmt.Errorf("could not put the new master key in place: %w", err)
	}
	r.k.reset()
	return nil
}

// Undo, after Commit, puts the previous key back in use and removes the
// .old copy, for when the re-encrypted files could not all be written.
func (r *Rotation) Undo() error {
	defer clear(r.backup)
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	if r.first {
		// Nothing was encrypted with the new key in the end.
		err := os.Remove(r.path)
		removeIfEmpty(r.madeDir)
		r.k.reset()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("could not remove the new master key %s, which nothing uses: %w", r.path, err)
		}
		return nil
	}
	if err := securefile.WriteFile(r.path, r.backup); err != nil {
		return fmt.Errorf("could not put the previous master key back in %s (it is still in %s.old): %w", r.path, r.path, err)
	}
	os.Remove(r.path + ".old")
	r.k.reset()
	return nil
}

// Done forgets the copy of the previous key kept for Undo.
func (r *Rotation) Done() { clear(r.backup) }

// Discard throws the new key away.
func (r *Rotation) Discard() {
	clear(r.backup)
	r.pending.Discard()
	if r.first {
		removeIfEmpty(r.madeDir)
	}
}

// RemoveOld deletes the previous master key kept after a rotation and
// returns its file, or "" when there is none.
func (k *Keyring) RemoveOld() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensure(); err != nil {
		return "", err
	}
	if k.src.OldPath == "" {
		return "", nil
	}
	p := k.src.OldPath
	if err := os.Remove(p); err != nil {
		return "", err
	}
	k.reset()
	return p, nil
}
