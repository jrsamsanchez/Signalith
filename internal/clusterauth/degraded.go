package clusterauth

import (
	"errors"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// While a server cannot use OpenSearch (degraded), or OpenSearch refuses
// writes (a full disk), no session can be stored, so only the people who
// may have to fix that can sign in, with a session this server keeps in
// memory: the built-in admin (with the copy of its password this server
// has, or the one signalith passwd -local wrote), and local admins whose
// copy is recent. Directory users cannot: the directory may have taken
// their access away since. Sessions already read keep working for
// StaleFor past their last confirmation.

const (
	// DegradedCopyAge is how old the copy of the shared settings may be
	// for a local admin to sign in while OpenSearch cannot be used.
	DegradedCopyAge = 24 * time.Hour
	// DegradedSession is how long a session made then lasts.
	DegradedSession = time.Hour
)

// ErrDegraded refuses a sign-in while OpenSearch cannot be used.
var ErrDegraded = errors.New("OpenSearch cannot be used right now, so only admins can sign in; try again later")

// MayDegrade says whether user, signing in by method, may get a session
// kept in memory while OpenSearch cannot be used: nil when they may.
func (s *Sessions) MayDegrade(user, method string) error {
	if method == users.SourceDirectory {
		return ErrDegraded
	}
	if b := s.Docs.builtinName(); b != "" && strings.EqualFold(user, b) {
		return nil
	}
	u, _, ok := s.Docs.Users().Get(users.NormalizeUsername(user))
	if !ok || u.Source != users.SourceLocal || u.Role != users.Admin || u.Disabled {
		return ErrDegraded
	}
	if s.Confirmed == nil {
		return ErrDegraded
	}
	if at := s.Confirmed(); at.IsZero() || s.now().Sub(at) > DegradedCopyAge {
		return ErrDegraded
	}
	return nil
}
