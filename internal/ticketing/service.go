package ticketing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Service opens tickets for cases and keeps them in step. The API uses
// it to open a ticket and test a connection; the server that runs the
// background jobs runs its sync (Run).
type Service struct {
	Settings *Manager
	Cases    cases.Store
	Links    Store
	// Protected are services connections must never reach, such as
	// Signalith's own OpenSearch, as host:port.
	Protected notify.Protected
	// PublicURL returns server.public_url, for the link to the case.
	PublicURL func() string
	// Server names this server on the links it writes.
	Server string
	// Allowed reports whether this server may sync now: it runs the
	// background jobs. nil always may.
	Allowed func() bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger

	// sleep waits before a request is tried again; nil is a timer.
	sleep func(context.Context, time.Duration) error

	tokens tokenCache
	quirks sync.Map

	mu sync.Mutex
	st syncState
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) allowed() bool { return s.Allowed == nil || s.Allowed() }

func (s *Service) sleepFunc() func(context.Context, time.Duration) error {
	if s.sleep != nil {
		return s.sleep
	}
	return func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
}

// caseLink returns the address of a case in Signalith, or "".
func (s *Service) caseLink(caseID string) string {
	if s.PublicURL == nil {
		return ""
	}
	return CaseLink(s.PublicURL(), caseID)
}

// Errors of Create and Request.
var (
	ErrNoConnection = errors.New("there is no ticketing connection with this ID; reload the page")
	ErrInProgress   = errors.New("a ticket is already being opened for this case in this connection; reload the page in a moment")
)

// LinkedError is a case that already has a ticket in a connection.
type LinkedError struct {
	System string
	Key    string
}

func (e *LinkedError) Error() string {
	return fmt.Sprintf("this case already has a ticket in %s: %s", TypeLabel(e.System), e.Key)
}

// staleAfter is how long a ticket may stay pending or being opened before
// an analyst may try again: the server that was opening it may have
// stopped.
const staleAfter = 10 * time.Minute

// newLink returns the link of a new ticket for case c.
func newLink(conn Connection, c *cases.Case, user string, auto bool, state string, now time.Time) *Link {
	return &Link{ID: LinkID(conn.ID, c.ID), CaseID: c.ID, Connection: conn.ID, ConnectionName: conn.Name, System: conn.Type,
		State: state, Auto: auto, CreatedBy: user, Created: now, Updated: now}
}

// prepare checks that a ticket can be opened for case caseID in
// connection connID.
func (s *Service) prepare(ctx context.Context, caseID, connID string) (Connection, *cases.Case, error) {
	set, err := s.Settings.Settings()
	if err != nil {
		return Connection{}, nil, err
	}
	conn, ok := set.Connection(connID)
	if !ok {
		return Connection{}, nil, ErrNoConnection
	}
	c, err := s.Cases.Get(ctx, caseID)
	if err != nil {
		return Connection{}, nil, err
	}
	if t, ok := c.Ticket(connID); ok {
		// A ticket deleted in its system may be replaced by a new one.
		st, err := s.Links.Get(ctx, LinkID(connID, caseID))
		if err != nil || st.State != StateGone || st.Key != t.Key {
			return Connection{}, nil, &LinkedError{System: t.System, Key: t.Key}
		}
	}
	return conn, c, nil
}

// Create opens a ticket for a case now, on this server, which runs the
// background jobs. user is who asked.
func (s *Service) Create(ctx context.Context, caseID, connID, user string) (*Link, error) {
	conn, c, err := s.prepare(ctx, caseID, connID)
	if err != nil {
		return nil, err
	}
	st, err := s.claim(ctx, newLink(conn, c, user, false, StateCreating, s.now().UTC()))
	if err != nil {
		return nil, err
	}
	return s.open(ctx, conn, st)
}

// Request asks the server that runs the background jobs to open a ticket
// for a case, from a server that does not: only that server calls the
// ticketing systems. It opens it within a minute.
func (s *Service) Request(ctx context.Context, caseID, connID, user string) (*Link, error) {
	conn, c, err := s.prepare(ctx, caseID, connID)
	if err != nil {
		return nil, err
	}
	st, err := s.claim(ctx, newLink(conn, c, user, false, StatePending, s.now().UTC()))
	if err != nil {
		return nil, err
	}
	s.log().Info("asked for a ticket for a case; the server that runs the background jobs opens it", "audit", true,
		"connection", conn.Name, "system", conn.Type, "case", c.ID, "by", user)
	return &st.Link, nil
}

// claim writes a new link, or takes over one whose ticket failed, was
// deleted, or was left half way by a server that stopped.
func (s *Service) claim(ctx context.Context, l *Link) (Stored, error) {
	v, err := s.Links.Create(ctx, l)
	if err == nil {
		return Stored{Link: *l, Version: v}, nil
	}
	if !errors.Is(err, store.ErrExists) {
		return Stored{}, err
	}
	cur, err := s.Links.Get(ctx, l.ID)
	if err != nil {
		return Stored{}, err
	}
	switch cur.State {
	case StateLinked:
		return Stored{}, &LinkedError{System: cur.System, Key: cur.Key}
	case StatePending, StateCreating:
		if s.now().Sub(cur.Updated) < staleAfter {
			return Stored{}, ErrInProgress
		}
	}
	l.Attempts = cur.Attempts
	v, err = s.Links.Update(ctx, l, cur.Version)
	if errors.Is(err, store.ErrConflict) {
		return Stored{}, ErrInProgress
	}
	if err != nil {
		return Stored{}, err
	}
	return Stored{Link: *l, Version: v}, nil
}

// open opens the ticket of a link being created, links it to the case and
// returns the link.
func (s *Service) open(ctx context.Context, conn Connection, st Stored) (*Link, error) {
	l := st.Link
	now := s.now().UTC()
	c, err := s.Cases.Get(ctx, l.CaseID)
	var cr created
	if err == nil {
		var rem remote
		rem, err = s.remote(conn)
		if err == nil {
			cr, err = rem.create(ctx, contentOf(c, s.caseLink(l.CaseID)))
		}
	}
	l.Attempts++
	l.Updated, l.Server = now, s.Server
	if err != nil {
		msg := Scrub(err.Error(), conn)
		if errors.Is(err, cases.ErrNotFound) {
			msg = "The case was deleted."
		}
		l.State, l.Error, l.ErrorAt = StateFailed, sentence(msg), now
		if _, uerr := s.Links.Update(ctx, &l, st.Version); uerr != nil {
			s.log().Error("could not record that a ticket could not be opened", "case", l.CaseID, "connection", conn.Name, "err", uerr)
		}
		s.log().Warn("could not open a ticket for a case", "audit", true, "connection", conn.Name, "system", conn.Type,
			"case", l.CaseID, "by", l.CreatedBy, "auto", l.Auto, "attempt", l.Attempts, "err", l.Error)
		return nil, &Error{Msg: l.Error, Retry: retryable(err)}
	}
	l.State, l.Active, l.Error, l.ErrorAt = StateLinked, true, "", time.Time{}
	l.Key, l.RemoteID, l.URL = cr.Key, cr.ID, cr.URL
	l.RemoteStatus, l.RemoteUpdated = cr.Status, cr.Updated
	l.CaseTitle, l.CaseSeverity, l.CaseStatus = c.Title, c.Severity, ""
	l.Notes, l.Comments = nil, nil
	// The ticket starts with what the case says; only notes added from
	// now on become comments.
	for _, e := range c.Entries {
		if e.Kind == cases.KindNote {
			l.Notes = append(l.Notes, e.ID)
		}
	}
	if _, err := s.Links.Update(ctx, &l, st.Version); err != nil {
		s.log().Error("opened a ticket but could not record it; it may be opened again", "case", l.CaseID, "connection", conn.Name, "key", l.Key, "err", err)
	}
	if err := s.linkCase(ctx, l, now); err != nil {
		s.log().Error("opened a ticket but could not add it to the case; the sync adds it later", "case", l.CaseID, "key", l.Key, "err", err)
	}
	s.log().Info("opened a ticket for a case", "audit", true, "connection", conn.Name, "system", conn.Type,
		"case", l.CaseID, "key", l.Key, "by", l.CreatedBy, "auto", l.Auto)
	return &l, nil
}

// ticketsMapper is a cases store that maps the tickets field on demand
// (cases.OpenSearch).
type ticketsMapper interface {
	EnsureTicketsField(ctx context.Context) error
}

// linkCase adds a link's ticket to its case, replacing an older ticket of
// the same connection that was deleted.
func (s *Service) linkCase(ctx context.Context, l Link, now time.Time) error {
	if m, ok := s.Cases.(ticketsMapper); ok {
		s.mu.Lock()
		mapped := s.st.mapped
		s.mu.Unlock()
		if !mapped {
			if err := m.EnsureTicketsField(ctx); err != nil {
				return err
			}
			s.mu.Lock()
			s.st.mapped = true
			s.mu.Unlock()
		}
	}
	author := l.CreatedBy
	if author == "" {
		author = "Signalith"
	}
	_, err := s.Cases.Modify(ctx, l.CaseID, func(c *cases.Case) (bool, error) {
		t := cases.Ticket{Connection: l.Connection, System: l.System, Key: l.Key, RemoteID: l.RemoteID, URL: l.URL, CreatedBy: l.CreatedBy, Created: l.Created}
		for i, have := range c.Tickets {
			if have.Connection == l.Connection {
				if have.Key == l.Key {
					return false, nil
				}
				c.Tickets[i] = t
				c.History = append(c.History, findings.Change{Author: author, Field: "ticket", From: TypeLabel(have.System) + " " + have.Key, To: TypeLabel(l.System) + " " + l.Key, Time: now})
				c.Updated = now
				return true, nil
			}
		}
		c.Tickets = append(c.Tickets, t)
		c.History = append(c.History, findings.Change{Author: author, Field: "ticket", To: TypeLabel(l.System) + " " + l.Key, Time: now})
		c.Updated = now
		return true, nil
	})
	return err
}

// Test checks a connection's credentials and its access to the project
// or table, and says what it found.
func (s *Service) Test(ctx context.Context, c Connection) (string, error) {
	rem, err := s.remote(c)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*RequestTimeout)
	defer cancel()
	msg, err := rem.test(ctx)
	if err != nil {
		if e := errorOf(err); e != nil {
			return "", &Error{Msg: Scrub(e.Msg, c), Code: e.Code}
		}
		return "", err
	}
	return Scrub(msg, c), nil
}

// LinksOf returns the links of a case.
func (s *Service) LinksOf(ctx context.Context, caseID string) ([]Stored, error) {
	return s.Links.ForCases(ctx, []string{caseID})
}
