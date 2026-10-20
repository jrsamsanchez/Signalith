// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Where a master key can come from, in the order they are tried.
const (
	// FromCredential is $CREDENTIALS_DIRECTORY/master.key, a credential
	// systemd passes to the service (LoadCredential=master.key:...).
	FromCredential = "credential"
	// FromKeyFile is the file SIGNALITH_MASTER_KEY_FILE names, such as a
	// Docker or Kubernetes secret.
	FromKeyFile = "key file"
	// FromEnv is SIGNALITH_MASTER_KEY, the key itself in base64. It works
	// but is weak: other programs can sometimes read a process's
	// environment (docker inspect, /proc/<pid>/environ).
	FromEnv = "environment"
	// FromDefault is the key file Signalith makes for itself:
	// keys/master.key in its state folder, readable only by its account,
	// or on Windows keys\master.key.dpapi, protected with DPAPI for this
	// computer.
	FromDefault = "default"
)

// ErrNoKey means no master key was found.
var ErrNoKey = errors.New("no master key was found")

// NoKeyError is ErrNoKey with the places looked in.
type NoKeyError struct{ Looked []string }

func (e *NoKeyError) Error() string {
	if len(e.Looked) == 0 {
		return ErrNoKey.Error() + " (SIGNALITH_MASTER_KEY_FILE and SIGNALITH_MASTER_KEY are not set)"
	}
	return ErrNoKey.Error() + " (SIGNALITH_MASTER_KEY_FILE and SIGNALITH_MASTER_KEY are not set, and there is no " + strings.Join(e.Looked, " or ") + ")"
}

func (e *NoKeyError) Is(target error) bool { return target == ErrNoKey }

// Source says where the master key comes from.
type Source struct {
	// Kind is FromCredential, FromKeyFile, FromEnv or FromDefault.
	Kind string
	// Path is the key file; empty for FromEnv.
	Path string
	// KeyID is the key's fingerprint, as in the values it encrypts.
	KeyID string
	// OldPath and OldKeyID are the previous key, kept after rotate-master
	// until nothing uses it; OldErr says why it could not be read.
	OldPath, OldKeyID, OldErr string
	// Created is true when the key was made just now.
	Created bool
	// Warning says what is wrong with who may use the key file, such as
	// other accounts being able to read it; "" when nothing is.
	Warning string
}

// Weak reports whether the key comes from SIGNALITH_MASTER_KEY.
func (s Source) Weak() bool { return s.Kind == FromEnv }

// String describes the source in plain words.
func (s Source) String() string {
	switch s.Kind {
	case FromCredential:
		return "the systemd credential " + s.Path
	case FromKeyFile:
		return s.Path + " (SIGNALITH_MASTER_KEY_FILE)"
	case FromEnv:
		return "the SIGNALITH_MASTER_KEY environment variable"
	case FromDefault:
		return s.Path + defaultNote
	}
	return "nowhere"
}

// Keyring finds the master key and encrypts and decrypts values with it.
// The key is looked for, in order:
//
//  1. $CREDENTIALS_DIRECTORY/master.key: a systemd credential
//     (LoadCredential=master.key:/path in the unit).
//  2. The file SIGNALITH_MASTER_KEY_FILE names.
//  3. SIGNALITH_MASTER_KEY: the key in base64. Allowed, but reported as
//     weak, since other programs can sometimes see the environment.
//  4. keys/master.key (keys\master.key.dpapi on Windows) in each of the
//     keyring's folders, in order.
//
// When none exists, Seal makes a key in the first folder: 32 random bytes,
// in a file only Signalith's account can read (on Windows protected with
// DPAPI for this computer, so both the service and an administrator can
// open it, and a copy is useless on another computer). Key files hold 32
// bytes as they are or as one line of base64 or hex text; lines starting
// with # are comments.
//
// After "signalith secrets rotate-master" the previous key is kept next to
// the key file with .old added, and values encrypted with it can still be
// opened. A key file that changes on disk is read again, so a running
// server picks up a rotated key.
type Keyring struct {
	dirs []string
	// also are folders looked in after dirs only for a key that is
	// there (see LookAlsoIn).
	also   []string
	getenv func(string) string
	// OnCreate, when set, is called after a new master key is made.
	OnCreate func(Source)

	mu        sync.Mutex
	cur, old  *masterKey
	src       Source
	stamp     os.FileInfo
	oldStamp  os.FileInfo
	oldExists bool
}

// NewKeyring returns a keyring that looks for keys/master.key in dirs, in
// order, and makes a new key in the first. Nothing is read until a key is
// needed.
func NewKeyring(dirs ...string) *Keyring {
	k := &Keyring{getenv: os.Getenv}
	seen := map[string]bool{}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		d = filepath.Clean(d)
		if !seen[d] {
			seen[d] = true
			k.dirs = append(k.dirs, d)
		}
	}
	return k
}

// LookAlsoIn adds folders looked in after the others, for a key another
// install of Signalith on this computer made there. Unlike the others, a
// folder this account may not look into is passed over rather than an
// error: it is most likely that install's own, not this one's. A new key
// is never made there.
func (k *Keyring) LookAlsoIn(dirs ...string) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		d = filepath.Clean(d)
		if !slices.Contains(k.dirs, d) && !slices.Contains(k.also, d) {
			k.also = append(k.also, d)
		}
	}
}

// DefaultPath returns where a new master key is made, or "" when the
// keyring has no folders.
func (k *Keyring) DefaultPath() string {
	if len(k.dirs) == 0 {
		return ""
	}
	return filepath.Join(k.dirs[0], "keys", defaultName)
}

func (k *Keyring) defaultFiles() []string {
	var out []string
	for _, d := range append(slices.Clone(k.dirs), k.also...) {
		out = append(out, filepath.Join(d, "keys", defaultName))
	}
	return out
}

// lookFor reports whether the default key file p is there. For a file in
// one of the also folders, not being allowed to look counts as not there.
func (k *Keyring) lookFor(p string) (bool, error) {
	_, err := os.Lstat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		// Where the keys folder is a file, Windows says "not found" while
		// Linux says "not a directory". Either way the key path cannot be
		// read, which is not a missing key.
		if st, serr := os.Stat(filepath.Dir(p)); serr == nil && !st.IsDir() {
			return false, fmt.Errorf("%s is not a folder", filepath.Dir(p))
		}
		return false, nil
	case errors.Is(err, fs.ErrPermission) && slices.Contains(k.also, filepath.Dir(filepath.Dir(p))):
		return false, nil
	}
	return false, err
}

// Unused lists default key files that exist but are not the one in use,
// such as a key made by "signalith init" next to signalith.yaml when the
// server already had one. Values encrypted with them cannot be opened.
func (k *Keyring) Unused() []string {
	src, err := k.Source()
	var out []string
	for _, p := range k.defaultFiles() {
		if err == nil && filepath.Clean(p) == filepath.Clean(src.Path) {
			continue
		}
		if there, serr := k.lookFor(p); there || serr != nil {
			out = append(out, p)
		}
	}
	return out
}

// Source finds the master key, without making one, and says where it
// comes from. It returns an error wrapping ErrNoKey when there is none.
func (k *Keyring) Source() (Source, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensure(); err != nil {
		return Source{}, err
	}
	return k.src, nil
}

// KeyID returns the id of the master key in use, or "".
func (k *Keyring) KeyID() string {
	src, err := k.Source()
	if err != nil {
		return ""
	}
	return src.KeyID
}

// Seal encrypts plain for the setting field, making a master key if there
// is none yet. Empty and already encrypted values are returned as they
// are, so a value that could not be decrypted is kept rather than lost.
func (k *Keyring) Seal(field, plain string) (string, error) {
	if plain == "" || IsSealed(plain) {
		return plain, nil
	}
	k.mu.Lock()
	err := k.ensure()
	var made *Source
	if errors.Is(err, ErrNoKey) {
		var src Source
		// Another process may have made it at the same moment; then
		// there is nothing new to report.
		if src, err = k.create(); err == nil && src.Created {
			made = &src
		}
	}
	var cur *masterKey
	if err == nil {
		cur = k.cur
	}
	k.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("could not encrypt %s: %w", field, err)
	}
	if made != nil && k.OnCreate != nil {
		k.OnCreate(*made)
	}
	return cur.seal(field, plain)
}

// Open decrypts a value stored for the setting field. Plain text is
// returned as it is. A value that cannot be decrypted gives an *OpenError.
func (k *Keyring) Open(field, stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	plain, _, err := k.open(field, stored)
	return plain, err
}

// Check reports how a stored value is kept, and for an Unreadable one
// why.
func (k *Keyring) Check(field, stored string) (State, error) {
	if !IsSealed(stored) {
		return Plain, nil
	}
	_, prev, err := k.open(field, stored)
	switch {
	case err != nil:
		return Unreadable, err
	case prev:
		return Previous, nil
	}
	return Current, nil
}

// open decrypts stored and reports whether the previous key did it.
func (k *Keyring) open(field, stored string) (string, bool, error) {
	id, blob, err := parse(stored)
	if err != nil {
		return "", false, &OpenError{Field: field, Reason: err.Error()}
	}
	k.mu.Lock()
	kerr := k.ensure()
	if kerr == nil && !k.has(id) {
		// The key file may have changed since it was read.
		k.reset()
		kerr = k.ensure()
	}
	var key *masterKey
	prev := false
	switch {
	case kerr != nil:
	case k.cur.id == id:
		key = k.cur
	case k.old != nil && k.old.id == id:
		key, prev = k.old, true
	}
	src := k.src
	k.mu.Unlock()
	if kerr != nil && !errors.Is(kerr, ErrNoKey) {
		return "", false, fmt.Errorf("could not decrypt %s: %w", field, kerr)
	}
	if key == nil {
		e := &OpenError{Field: field, KeyID: id}
		if kerr == nil {
			e.Have, e.Where = src.KeyID, src.String()
		}
		return "", false, e
	}
	plain, ok := key.open(field, blob)
	if !ok {
		return "", false, &OpenError{Field: field, KeyID: id, Reason: "it was changed, or copied from another setting"}
	}
	return plain, prev, nil
}

func (k *Keyring) has(id string) bool {
	return k.cur != nil && k.cur.id == id || k.old != nil && k.old.id == id
}

// reset forgets the keys, so the next use reads them again.
func (k *Keyring) reset() {
	k.cur, k.old, k.src, k.stamp, k.oldStamp, k.oldExists = nil, nil, Source{}, nil, nil, false
}

// ensure loads the master key, or reloads it when its file changed; the
// caller holds k.mu.
func (k *Keyring) ensure() error {
	if k.cur != nil {
		if !k.changed() {
			return nil
		}
		k.reset()
	}
	return k.load()
}

// changed reports whether the key file or the previous key's file is not
// the one that was read.
func (k *Keyring) changed() bool {
	if k.src.Kind == FromEnv || k.src.Path == "" {
		return false
	}
	st, err := os.Stat(k.src.Path)
	if err != nil || !sameFile(st, k.stamp) {
		return true
	}
	ost, err := os.Stat(k.src.Path + ".old")
	if exists := err == nil; exists != k.oldExists || exists && !sameFile(ost, k.oldStamp) {
		return true
	}
	return false
}

func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// load finds the master key; the caller holds k.mu.
func (k *Keyring) load() error {
	if d := k.getenv("CREDENTIALS_DIRECTORY"); d != "" {
		p := filepath.Join(d, "master.key")
		if _, err := os.Stat(p); err == nil {
			return k.loadFile(FromCredential, p, readKeyFile)
		}
	}
	if p := strings.TrimSpace(k.getenv("SIGNALITH_MASTER_KEY_FILE")); p != "" {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("SIGNALITH_MASTER_KEY_FILE names %s, which does not exist", p)
		}
		return k.loadFile(FromKeyFile, p, readKeyFile)
	}
	if v := strings.TrimSpace(k.getenv("SIGNALITH_MASTER_KEY")); v != "" {
		raw, err := parseKeyText([]byte(v))
		if err != nil {
			return fmt.Errorf("SIGNALITH_MASTER_KEY: %w", err)
		}
		m, err := newMasterKey(raw)
		clear(raw)
		if err != nil {
			return err
		}
		k.cur, k.src = m, Source{Kind: FromEnv, KeyID: m.id}
		return nil
	}
	for _, p := range k.defaultFiles() {
		there, err := k.lookFor(p)
		if there {
			return k.loadFile(FromDefault, p, readDefault)
		}
		if err != nil {
			// A key that is there but cannot be read is not a missing key:
			// making another would leave the values it encrypted unreadable.
			return fmt.Errorf("cannot read the master key %s: %w. %s", p, err, accessHint(p))
		}
	}
	return &NoKeyError{Looked: k.defaultFiles()}
}

// loadFile reads the key in path, and the previous key next to it.
func (k *Keyring) loadFile(kind, path string, read func(string) ([]byte, error)) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read the master key %s: %w", path, err)
	}
	raw, err := read(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("cannot read the master key %s: %w. %s", path, err, accessHint(path))
		}
		return fmt.Errorf("cannot read the master key %s: %w", path, err)
	}
	m, err := newMasterKey(raw)
	clear(raw)
	if err != nil {
		return fmt.Errorf("the master key %s: %w", path, err)
	}
	k.cur, k.stamp = m, st
	k.src = Source{Kind: kind, Path: path, KeyID: m.id, Warning: keyFileWarning(path, st)}
	if ost, err := os.Stat(path + ".old"); err == nil {
		k.oldExists, k.oldStamp = true, ost
		k.src.OldPath = path + ".old"
		raw, err := read(path + ".old")
		if err == nil {
			var om *masterKey
			om, err = newMasterKey(raw)
			clear(raw)
			if err == nil {
				k.old, k.src.OldKeyID = om, om.id
			}
		}
		if err != nil {
			k.src.OldErr = err.Error()
		}
	}
	return nil
}

// create makes a new master key in the first folder; the caller holds
// k.mu. When another process made one at the same moment, that one is
// used.
func (k *Keyring) create() (Source, error) {
	path := k.DefaultPath()
	if path == "" {
		return Source{}, &NoKeyError{}
	}
	raw := make([]byte, keySize)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return Source{}, err
	}
	data, err := encodeDefault(raw)
	if err != nil {
		return Source{}, fmt.Errorf("could not protect a new master key: %w", err)
	}
	defer clear(data)
	if err := securefile.MkdirPrivate(filepath.Dir(path)); err != nil {
		return Source{}, fmt.Errorf("could not make a folder for the master key: %w", err)
	}
	p, err := securefile.PreparePrivate(path, data)
	if err != nil {
		return Source{}, fmt.Errorf("could not save a new master key: %w", err)
	}
	err = p.CommitNew()
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return Source{}, fmt.Errorf("could not save a new master key: %w", err)
	}
	made := err == nil
	if err := k.loadFile(FromDefault, path, readDefault); err != nil {
		return Source{}, err
	}
	k.src.Created = made
	return k.src, nil
}

// readKeyFile reads a key file written as bytes or text.
func readKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return parseKey(data)
}

var errBadKey = errors.New("it does not hold a master key: 32 random bytes, or one line of base64 (make one with: openssl rand -base64 32)")

var errTypedKey = errors.New("it holds 32 characters of text, which look typed rather than random, so they are not used as a key. " +
	"A master key is 32 random bytes, written as one line of base64 (make one with: openssl rand -base64 32)")

// parseKey reads a key file: 32 bytes as they are, or one line of base64
// or hex text, with optional # comment lines. 32 bytes that are all text
// are read as text, not as a key, since they are far more likely a typed
// passphrase than random bytes.
func parseKey(data []byte) ([]byte, error) {
	if len(data) == keySize && !isText(data) {
		return bytes.Clone(data), nil
	}
	return parseKeyText(data)
}

// isText reports whether data is all printable ASCII or white space.
func isText(data []byte) bool {
	for _, c := range data {
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// parseKeyText reads a master key written as one line of base64 or hex
// text, with optional # comment lines, as SIGNALITH_MASTER_KEY holds it.
func parseKeyText(data []byte) ([]byte, error) {
	var line []byte
	n := 0
	for _, l := range bytes.Split(data, []byte("\n")) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		line = l
		n++
	}
	if n != 1 {
		return nil, errBadKey
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b := make([]byte, enc.DecodedLen(len(line)))
		if n, err := enc.Decode(b, line); err == nil && n == keySize {
			return b[:n], nil
		}
		clear(b)
	}
	if len(line) == 2*keySize {
		b := make([]byte, keySize)
		if _, err := hex.Decode(b, line); err == nil {
			return b, nil
		}
		clear(b)
	}
	if len(line) == keySize {
		return nil, errTypedKey
	}
	return nil, errBadKey
}

// keyText is a key file as Signalith writes one.
func keyText(raw []byte) []byte {
	out := []byte(`# Signalith master key. It decrypts the passwords and API keys Signalith
# stores. Keep a copy somewhere safe, apart from signalith.yaml and its
# backups. Without it those passwords and keys must be entered again;
# events are not affected. See docs/encryption.md.
`)
	b := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(b, raw)
	out = append(out, b...)
	clear(b)
	return append(out, '\n')
}
