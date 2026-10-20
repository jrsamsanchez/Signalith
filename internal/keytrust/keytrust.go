// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package keytrust decides which signing keys a build still trusts: the
// online keys that sign agent programs (internal/agentproto) and content
// bundles (internal/content), the offline root keys in root.keys, and the
// keys revoked since.
//
// A key is revoked by the key IDs in revoked.keys, built in, or by a
// revocation list signed with a root key, which servers download next to
// the content bundle and hand to their agents. A list, once checked, is
// kept, and only a newer list replaces it, so a server or agent that saw a
// revocation keeps it whatever it is sent later. Root keys are never
// revoked by a list: a leaked online key cannot be used to revoke the
// root key that recovers from it.
package keytrust

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed root.keys
var rootKeys string

//go:embed revoked.keys
var revokedKeys string

// Files a revocation list is published and kept as.
const (
	ListFile      = "signalith-revoked.json"
	SignatureFile = ListFile + ".sig"
)

// Format is the revocation list format this build reads.
const Format = 1

// MaxList is the largest revocation list read, so a hostile server cannot
// fill memory.
const MaxList = 64 << 10

var keyIDRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// Builtin are the root keys and revoked key IDs this build was made with.
// Tests replace them.
var (
	Roots   = mustKeys(rootKeys)
	Revoked = mustIDs(revokedKeys)
)

func mustKeys(s string) []ed25519.PublicKey {
	k, err := ParseKeys(s)
	if err != nil {
		panic("keytrust/root.keys: " + err.Error())
	}
	return k
}

func mustIDs(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if !keyIDRE.MatchString(line) {
			panic(fmt.Sprintf("keytrust/revoked.keys: %q is not a key ID", line))
		}
		out = append(out, line)
	}
	return out
}

// ParseKeys reads public keys, one base64 key per line; # starts a comment.
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, line := range strings.Split(s, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%q is not a base64 Ed25519 public key", line)
		}
		out = append(out, ed25519.PublicKey(k))
	}
	return out, nil
}

// KeyID is the short name of a public key that signature files carry, the
// same as agentproto.KeyID and content.KeyID.
func KeyID(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return fmt.Sprintf("%x", sum[:6])
}

// List is a revocation list.
type List struct {
	Format int `json:"format"`
	// Issued orders lists: a newer one replaces an older one.
	Issued time.Time `json:"issued"`
	// Revoked are the keys no longer trusted.
	Revoked []RevokedKey `json:"revoked"`
}

// RevokedKey is one revoked key.
type RevokedKey struct {
	ID string `json:"id"`
	// Note says why, for people.
	Note string `json:"note,omitempty"`
}

// Sign signs a revocation list file. The signature file is one line: the
// signing key's ID and the base64 signature, as for manifests and bundles.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	sig := ed25519.Sign(priv, data)
	return []byte(KeyID(priv.Public().(ed25519.PublicKey)) + " " + base64.StdEncoding.EncodeToString(sig) + "\n")
}

// ErrNoRoot is returned for a list when this build has no root key, so it
// can check none.
var ErrNoRoot = errors.New("this build has no root key, so it cannot check a revocation list")

// Verify checks a revocation list file's signature against the root keys
// roots and reads it.
func Verify(roots []ed25519.PublicKey, data, sig []byte) (*List, error) {
	if len(roots) == 0 {
		return nil, ErrNoRoot
	}
	if len(data) > MaxList || len(sig) > 1024 {
		return nil, errors.New("the revocation list is larger than any Signalith makes")
	}
	f := strings.Fields(string(sig))
	if len(f) != 2 {
		return nil, errors.New("the revocation list's signature file is not a Signalith signature")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("the revocation list's signature file is not a Signalith signature")
	}
	ok := false
	for _, k := range roots {
		if KeyID(k) == f[0] && ed25519.Verify(k, data, raw) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("the revocation list's signature does not match: it was changed, or not signed by a root key this build trusts")
	}
	var l List
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("the revocation list is not valid JSON: %w", err)
	}
	if l.Format != Format {
		return nil, fmt.Errorf("the revocation list is format %d; this build reads format %d", l.Format, Format)
	}
	if l.Issued.IsZero() {
		return nil, errors.New("the revocation list has no issue time")
	}
	for _, r := range l.Revoked {
		if !keyIDRE.MatchString(r.ID) {
			return nil, fmt.Errorf("the revocation list names %q, which is not a key ID", r.ID)
		}
	}
	return &l, nil
}

// Store keeps the newest revocation list seen in a folder.
type Store struct {
	// Dir is the folder; it is made when a list is first kept.
	Dir string
	// Roots check the lists; nil means the built-in Roots.
	Roots []ed25519.PublicKey

	mu sync.Mutex
}

func (s *Store) roots() []ed25519.PublicKey {
	if s.Roots != nil {
		return s.Roots
	}
	return Roots
}

// Load returns the list kept, checked again, with its file and signature;
// nil and no error when none is kept.
func (s *Store) Load() (*List, []byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) load() (*List, []byte, []byte, error) {
	data, err := readMax(filepath.Join(s.Dir, ListFile), MaxList)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := readMax(filepath.Join(s.Dir, SignatureFile), 1024)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := Verify(s.roots(), data, sig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the kept revocation list %s: %w", filepath.Join(s.Dir, ListFile), err)
	}
	return l, data, sig, nil
}

// Offer checks a revocation list and keeps it when it is newer than the
// one kept. It reports whether it kept it. A list no newer than the one
// kept is not an error: servers hand the same list out again and again.
func (s *Store) Offer(data, sig []byte) (bool, error) {
	l, err := Verify(s.roots(), data, sig)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, _, _, err := s.load()
	if err == nil && cur != nil && !l.Issued.After(cur.Issued) {
		return false, nil
	}
	// A kept list that cannot be read any more is replaced by a good one.
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return false, err
	}
	// The signature first: a list is only read with a signature that
	// matches it, so a crash between the two leaves the old list or none.
	if err := writeAtomic(filepath.Join(s.Dir, SignatureFile), sig); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Join(s.Dir, ListFile), data); err != nil {
		return false, err
	}
	return true, nil
}

// RevokedIDs are the key IDs revoked by the built-in list and the lists
// given (nil ones are skipped), except the root keys.
func RevokedIDs(lists ...*List) map[string]bool {
	out := map[string]bool{}
	for _, id := range Revoked {
		out[id] = true
	}
	for _, l := range lists {
		if l == nil {
			continue
		}
		for _, r := range l.Revoked {
			out[r.ID] = true
		}
	}
	for _, k := range Roots {
		delete(out, KeyID(k))
	}
	return out
}

// Trusted returns keys and the root keys, without the revoked ones: the
// keys a signature may be checked with.
func Trusted(keys []ed25519.PublicKey, revoked map[string]bool) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	seen := map[string]bool{}
	for _, k := range slices.Concat(keys, Roots) {
		id := KeyID(k)
		if seen[id] || (revoked[id] && !isRoot(id)) {
			continue
		}
		seen[id] = true
		out = append(out, k)
	}
	return out
}

// ErrRevoked is returned for a file signed with a revoked key.
var ErrRevoked = errors.New("the key it is signed with is revoked")

// Explain says a failed signature check failed because the signature file
// sig names a revoked key, when it does; otherwise it returns err.
func Explain(err error, sig []byte, revoked map[string]bool) error {
	if f := strings.Fields(string(sig)); err != nil && len(f) > 0 && revoked[f[0]] {
		return fmt.Errorf("%w (key %s); it was revoked because the key leaked or was retired", ErrRevoked, f[0])
	}
	return err
}

func isRoot(id string) bool {
	return slices.ContainsFunc(Roots, func(k ed25519.PublicKey) bool { return KeyID(k) == id })
}

func readMax(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 0, 1024)
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		b = append(b, buf[:n]...)
		if int64(len(b)) > max {
			return nil, fmt.Errorf("%s is larger than any Signalith writes", path)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return b, nil
			}
			return nil, err
		}
	}
}

// writeAtomic writes path through a new file renamed into place, private
// to its owner.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	ok = true
	return nil
}
