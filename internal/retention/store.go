// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Store keeps the settings saved on the Data retention page in a YAML
// file, readable by the server's user only. Edits made to the file by
// hand are picked up without a restart.
type Store struct {
	Path string

	mu    sync.Mutex
	saved Saved
	mod   time.Time
	size  int64
	err   error
}

const storeHeader = `# Data retention settings saved from the Data retention page.
# Settings under retention: in signalith.yaml take precedence over these.
# See docs/retention.md.
`

// NewStore loads the settings file if it exists. A file with errors is
// reported by Err and pauses retention until it is fixed, so a typo can
// never make retention fall back to deleting more than intended.
func NewStore(path string) *Store {
	s := &Store{Path: path}
	s.reload()
	return s
}

// reload reads the file if it changed; the caller holds s.mu or owns s.
func (s *Store) reload() {
	if s.Path == "" {
		return
	}
	st, err := os.Stat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		s.saved, s.err, s.mod, s.size = Saved{}, nil, time.Time{}, 0
		return
	}
	if err != nil {
		s.err = err
		return
	}
	if st.ModTime().Equal(s.mod) && st.Size() == s.size && s.err == nil {
		return
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		s.err = err
		return
	}
	s.mod, s.size = st.ModTime(), st.Size()
	var saved Saved
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&saved); err != nil && err.Error() != "EOF" {
		s.err = fmt.Errorf("%s: %w", s.Path, err)
		return
	}
	if p := saved.problems(); len(p) > 0 {
		s.err = fmt.Errorf("%s: %s", s.Path, (&PolicyError{Problems: p}).Error())
		return
	}
	s.saved, s.err = saved, nil
}

// Get returns the saved settings, re-reading the file if it changed, and
// the file's error, if it has one.
func (s *Store) Get() (Saved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	return s.saved.clone(), s.err
}

// Update changes the saved settings and writes the file. It refuses to
// overwrite a file with errors, which the admin should fix first.
func (s *Store) Update(change func(*Saved)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	if s.err != nil {
		return s.err
	}
	next := s.saved.clone()
	change(&next)
	if len(next.Policies) == 0 {
		next.Policies = nil
	}
	if p := next.problems(); len(p) > 0 {
		return &PolicyError{Problems: p}
	}
	if s.Path != "" {
		data, err := yaml.Marshal(next)
		if err != nil {
			return err
		}
		if err := writeAtomic(s.Path, append([]byte(storeHeader), data...)); err != nil {
			return fmt.Errorf("saving %s: %w", s.Path, err)
		}
		if st, err := os.Stat(s.Path); err == nil {
			s.mod, s.size = st.ModTime(), st.Size()
		}
	}
	s.saved = next
	return nil
}

// writeAtomic writes a file readable by its owner only: to a temporary
// file first, synced, then renamed over the old one.
func writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+filepath.Base(name)+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}
