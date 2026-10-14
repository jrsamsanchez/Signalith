package api

import (
	"context"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
)

// SessionStore keeps the sign-in sessions: in memory on this server
// (MemorySessions), or in OpenSearch, valid on every server of a cluster.
type SessionStore interface {
	// Create starts a session and returns its token.
	Create(ctx context.Context, s auth.NewSession) (token string, err error)
	// Lookup returns the session for a token. used marks it used, so it
	// does not end for being idle; a request a page makes on its own
	// passes false.
	Lookup(ctx context.Context, token string, used bool) (auth.Session, bool)
	// SetVersion records which password a session's user has now (see
	// auth.Session.Version).
	SetVersion(ctx context.Context, token, version string)
	// Delete ends a session.
	Delete(ctx context.Context, token string)
	// EndUser ends every session of a user except the one with token keep
	// ("" keeps none), and reports how many there were.
	EndUser(ctx context.Context, user, keep string) int
	// Users lists the users with a session, each once, in lower case.
	Users(ctx context.Context) []string
	// SetIdle changes how long a session lasts without a request.
	SetIdle(d time.Duration)
	// MaxAge is how long any session lasts after sign-in.
	MaxAge() time.Duration
}

// MemorySessions returns the sessions s keeps in memory as a
// SessionStore.
func MemorySessions(s *auth.Sessions) SessionStore { return memorySessions{s} }

type memorySessions struct{ s *auth.Sessions }

func (m memorySessions) Create(_ context.Context, n auth.NewSession) (string, error) {
	return m.s.Start(n), nil
}

func (m memorySessions) Lookup(_ context.Context, token string, used bool) (auth.Session, bool) {
	if used {
		return m.s.Lookup(token)
	}
	return m.s.Peek(token)
}

func (m memorySessions) SetVersion(_ context.Context, token, version string) {
	m.s.SetVersion(token, version)
}

func (m memorySessions) Delete(_ context.Context, token string) { m.s.Delete(token) }

func (m memorySessions) EndUser(_ context.Context, user, keep string) int {
	return m.s.EndUser(user, keep)
}

func (m memorySessions) Users(context.Context) []string { return m.s.Users() }

func (m memorySessions) SetIdle(d time.Duration) { m.s.SetIdle(d) }

func (m memorySessions) MaxAge() time.Duration { return m.s.MaxAge }
