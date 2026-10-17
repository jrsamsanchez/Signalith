package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// firstPasswordCheck remembers whether the built-in admin's password in
// use is the first one Signalith made, for the password hash in use and
// the file that keeps the first password as they were when last checked.
// Comparing them costs a password hash check, so it is done again only
// when either changes.
type firstPasswordCheck struct {
	mu    sync.Mutex
	key   string
	first bool
}

// builtinFirstPassword reports whether the built-in admin's password in
// use is still the first one Signalith made (see config.FirstPassword).
// It must then be changed before anything else, as a local user's
// temporary password must. With shared users it is not asked while the
// shared settings cannot be used, since the new password could not be
// saved then.
func (s *Server) builtinFirstPassword() bool {
	c := s.conf()
	if c == nil || (s.SharedUsers != nil && s.sharedDegraded()) {
		return false
	}
	h := s.builtinHash()
	if h == "" {
		return false
	}
	if fh := c.FirstPasswordHash(); fh != "" && subtle.ConstantTimeCompare([]byte(fh), []byte(h)) == 1 {
		return true
	}
	file, _ := c.InitialPasswordFile()
	if file == "" {
		return false
	}
	fi, err := os.Stat(file)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", h, file, fi.Size(), fi.ModTime().UnixNano())
	s.firstPW.mu.Lock()
	defer s.firstPW.mu.Unlock()
	if s.firstPW.key == key {
		return s.firstPW.first
	}
	// A file this server cannot read (the packages keep it root's) counts
	// as no first password here; signalith init noted its hash instead.
	first := false
	if b, err := os.ReadFile(file); err == nil {
		if pw := strings.TrimSpace(string(b)); pw != "" {
			first = users.ComparePassword(h, pw)
		}
	}
	s.firstPW.key, s.firstPW.first = key, first
	return first
}

// keepError is a new password that was accepted but could not be kept.
type keepError struct{ error }

func (e keepError) Unwrap() error { return e.error }

// setBuiltinHere gives the built-in admin of a server that keeps its
// users in its own files the new password hash: it is kept in
// AdminHashFile, where signalith passwd keeps it when signalith.yaml
// cannot hold it and which replaces the configured password at every
// start, and is in use at once.
func (s *Server) setBuiltinHere(hash string) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	c := s.conf()
	path := c.AdminHashFile()
	if err := securefile.Replace(path, []byte(hash+"\n")); err != nil {
		return keepError{fmt.Errorf("Signalith could not keep the new password in %s: %w. Set one on the server with signalith passwd instead", path, err)}
	}
	s.live.Store(c.WithAdminHashFile(hash))
	return nil
}

// firstPasswordChanged follows the built-in admin's replacing the first
// password Signalith made: it notes the change in the state folder, so
// signalith initial-password no longer shows the password, and removes
// the file that kept it where Signalith may (see
// config.InitialPasswordFile). The Docker quick start's is on a volume
// this server can only read, and stays; it no longer works.
func (s *Server) firstPasswordChanged() {
	c := s.conf()
	dir := c.StateDir()
	if err := config.NoteFirstPasswordChanged(dir, time.Now()); err != nil {
		s.Log.Warn("could not note in the state folder that the first admin password was changed, so signalith initial-password may still show it, though it no longer works",
			"file", config.FirstPasswordFileIn(dir), "err", err)
	}
	file, own := c.InitialPasswordFile()
	if !own || file == "" {
		return
	}
	switch err := os.Remove(file); {
	case err == nil:
		s.Log.Info("removed the file that kept the first admin password, which no longer works", "audit", true, "file", file)
	case errors.Is(err, fs.ErrNotExist):
	default:
		s.Log.Info("the first admin password no longer works, but this server may not remove the file that kept it; delete it as an administrator",
			"file", file, "err", err)
	}
}
