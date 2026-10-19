// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"context"
	"fmt"
)

// The lists' names, as the API and the shared settings call them.
const (
	KindAssets     = "assets"
	KindIdentities = "identities"
)

// Backend keeps the user's lists in the shared settings of a cluster, so
// every server uses the same ones. The store still keeps a copy in Dir,
// which the backend's owner writes back (Write) when another server
// changes a list: lookups never wait on OpenSearch.
type Backend interface {
	// ETag returns the version of the list kind in use, "" when there is
	// none.
	ETag(kind string) string
	// Put replaces the list kind with data, read at etag ("" for the
	// latest), and refuses it with an error naming who changed it when
	// it changed since.
	Put(ctx context.Context, by, kind string, data []byte, etag string) error
}

// UseBackend makes the store keep the user's lists in b; nil keeps them
// in Dir only.
func (s *Store) UseBackend(b Backend) {
	s.mu.Lock()
	s.backend = b
	s.mu.Unlock()
}

func (s *Store) backendOf() Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend
}

// Shared reports whether the lists are kept in the shared settings.
func (s *Store) Shared() bool { return s.backendOf() != nil }

// ETag returns the version of the list kind for If-Match, "" when the
// lists are not shared.
func (s *Store) ETag(kind string) string {
	if b := s.backendOf(); b != nil {
		return b.ETag(kind)
	}
	return ""
}

func fileOf(kind string) (string, error) {
	switch kind {
	case KindAssets:
		return AssetsFile, nil
	case KindIdentities:
		return IdentitiesFile, nil
	}
	return "", fmt.Errorf("unknown list %q", kind)
}

// SetIf replaces the list kind with CSV uploaded by by, read at etag:
// with a backend, the shared list first (a change made meanwhile is
// refused), then this server's copy. It returns the number of rows.
func (s *Store) SetIf(ctx context.Context, by, kind string, data []byte, etag string) (int, error) {
	if _, err := fileOf(kind); err != nil {
		return 0, err
	}
	n, err := s.check(kind, data)
	if err != nil {
		return 0, err
	}
	if b := s.backendOf(); b != nil {
		if err := b.Put(ctx, by, kind, data, etag); err != nil {
			return 0, err
		}
	} else if s.Hold != nil {
		release, err := s.Hold()
		if err != nil {
			return 0, err
		}
		defer release()
	}
	if kind == KindAssets {
		return s.SetAssets(data)
	}
	_, err = s.SetIdentities(data)
	return n, err
}

// Write replaces this server's copy of the list kind with data, a list
// changed on another server: the shared list is left as it is.
func (s *Store) Write(kind string, data []byte) error {
	var err error
	switch kind {
	case KindAssets:
		_, err = s.SetAssets(data)
	case KindIdentities:
		_, err = s.SetIdentities(data)
	default:
		_, err = fileOf(kind)
	}
	return err
}

// check parses data as the list kind and returns its number of rows.
func (s *Store) check(kind string, data []byte) (int, error) {
	if kind == KindAssets {
		as, err := ParseAssets(data)
		return len(as), err
	}
	ids, err := ParseIdentities(data)
	return len(ids), err
}
