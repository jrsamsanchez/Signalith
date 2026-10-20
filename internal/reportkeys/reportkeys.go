// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package reportkeys keeps the public keys that have signed case reports
// (internal/casereport), so a report still verifies after the key that
// signed it was replaced, and one signed with a key that may have leaked
// says so.
//
// The signing key itself is never stored: it is made again from the
// cluster key (a cluster) or the master key (a server on its own). What is
// kept is each public key, when it was first used, and whether it was
// retired (a newer key took over) or revoked (it may have leaked). A
// cluster keeps the list in its shared settings, signed like every shared
// document; a server on its own keeps it in report-keys.json in its state
// folder, which backups include.
package reportkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Sources of a signing key.
const (
	FromCluster = "cluster"
	FromMaster  = "master"
)

// Statuses of a key.
const (
	Current = "current"
	Retired = "retired"
	Revoked = "revoked"
)

// FileName is the list's file in the state folder of a server on its own.
const FileName = "report-keys.json"

// MaxReason caps the note on a revocation.
const MaxReason = 500

// Key is one signing key's public half and its history.
type Key struct {
	ID        string     `json:"id"`
	Public    string     `json:"public"`
	Source    string     `json:"source"`
	FirstUsed time.Time  `json:"first_used"`
	Retired   *time.Time `json:"retired,omitempty"`
	Revoked   *time.Time `json:"revoked,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// Status is current, retired or revoked.
func (k *Key) Status() string {
	switch {
	case k.Revoked != nil:
		return Revoked
	case k.Retired != nil:
		return Retired
	}
	return Current
}

// PublicKey decodes the key.
func (k *Key) PublicKey() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("report key %s: not an Ed25519 public key", k.ID)
	}
	if KeyID(b) != k.ID {
		return nil, fmt.Errorf("report key %s: its ID does not match the key", k.ID)
	}
	return b, nil
}

// KeyID is the first 12 hex digits of the SHA-256 of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:12]
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ValidID is true for an ID KeyID could have made.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ErrNotFound is a key the list does not have.
var ErrNotFound = errors.New("no report key with that ID")

// Registry keeps the list.
type Registry interface {
	// List returns the keys, oldest first.
	List(ctx context.Context) ([]Key, error)
	// Use records pub as the key that signs now: it is added the first
	// time, and the other keys still current are marked retired.
	Use(ctx context.Context, pub ed25519.PublicKey, source string, now time.Time) error
	// Revoke marks a key as possibly leaked.
	Revoke(ctx context.Context, id, by, reason string, now time.Time) error
}

// Apply is Use on a list: it returns the new list and whether it changed.
func Apply(ks []Key, pub ed25519.PublicKey, source string, now time.Time) ([]Key, bool) {
	id := KeyID(pub)
	out := slices.Clone(ks)
	changed := false
	if !slices.ContainsFunc(out, func(k Key) bool { return k.ID == id }) {
		out = append(out, Key{ID: id, Public: base64.StdEncoding.EncodeToString(pub), Source: source, FirstUsed: now.UTC().Truncate(time.Second)})
		changed = true
	}
	for i := range out {
		if out[i].ID != id && out[i].Retired == nil && out[i].Revoked == nil {
			t := now.UTC().Truncate(time.Second)
			out[i].Retired, changed = &t, true
		}
	}
	return out, changed
}

// CheckReason checks the note on a revocation.
func CheckReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > MaxReason || strings.ContainsFunc(reason, func(r rune) bool { return r < 0x20 && r != '\n' }) {
		return "", fmt.Errorf("the reason must be at most %d characters of text", MaxReason)
	}
	return reason, nil
}

// RevokeIn is Revoke on a list.
func RevokeIn(ks []Key, id, by, reason string, now time.Time) ([]Key, error) {
	reason, err := CheckReason(reason)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(ks, func(k Key) bool { return k.ID == id })
	if i < 0 {
		return nil, ErrNotFound
	}
	out := slices.Clone(ks)
	if out[i].Revoked == nil {
		t := now.UTC().Truncate(time.Second)
		out[i].Revoked, out[i].RevokedBy, out[i].Reason = &t, by, reason
	}
	return out, nil
}

// File keeps the list of a server on its own in a file of its state
// folder. It reads the file each time, so a key revoked with the command
// line counts at once.
type File struct {
	Path string

	mu sync.Mutex
}

type fileBody struct {
	Keys []Key `json:"keys"`
}

// Read returns the keys in path; a missing file is an empty list.
func Read(path string) ([]Key, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f fileBody
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f.Keys, nil
}

func write(path string, ks []Key) error {
	b, err := json.MarshalIndent(fileBody{Keys: ks}, "", "  ")
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, append(b, '\n'))
}

func (f *File) List(context.Context) ([]Key, error) { return Read(f.Path) }

func (f *File) Use(_ context.Context, pub ed25519.PublicKey, source string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks, err := Read(f.Path)
	if err != nil {
		return err
	}
	ks, changed := Apply(ks, pub, source, now)
	if !changed {
		return nil
	}
	return write(f.Path, ks)
}

func (f *File) Revoke(_ context.Context, id, by, reason string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks, err := Read(f.Path)
	if err != nil {
		return err
	}
	if ks, err = RevokeIn(ks, id, by, reason, now); err != nil {
		return err
	}
	return write(f.Path, ks)
}

// Memory keeps the list in memory, for tests.
type Memory struct {
	mu sync.Mutex
	ks []Key
}

func (m *Memory) List(context.Context) ([]Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ks), nil
}

func (m *Memory) Use(_ context.Context, pub ed25519.PublicKey, source string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ks, _ = Apply(m.ks, pub, source, now)
	return nil
}

func (m *Memory) Revoke(_ context.Context, id, by, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := RevokeIn(m.ks, id, by, reason, now)
	if err != nil {
		return err
	}
	m.ks = ks
	return nil
}

// Switch uses the cluster's list while the server is a member of a
// cluster, and its own file otherwise.
type Switch struct {
	Clustered func() bool
	Shared    *Shared
	File      *File
}

func (s *Switch) pick() Registry {
	if s.Shared != nil && s.Clustered != nil && s.Clustered() {
		return s.Shared
	}
	return s.File
}

func (s *Switch) List(ctx context.Context) ([]Key, error) { return s.pick().List(ctx) }

func (s *Switch) Use(ctx context.Context, pub ed25519.PublicKey, source string, now time.Time) error {
	return s.pick().Use(ctx, pub, source, now)
}

func (s *Switch) Revoke(ctx context.Context, id, by, reason string, now time.Time) error {
	return s.pick().Revoke(ctx, id, by, reason, now)
}

// Lookup returns the Keys of a list read now, for Verify.
func Lookup(ks []Key) func(id string) (*Key, bool) {
	return func(id string) (*Key, bool) {
		for i := range ks {
			if ks[i].ID == id {
				return &ks[i], true
			}
		}
		return nil, false
	}
}
