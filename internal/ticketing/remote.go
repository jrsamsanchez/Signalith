// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"time"
)

// remote is what the sync does with a ticketing system; jira and
// serviceNow implement it.
type remote interface {
	// create opens a ticket and returns it and its status.
	create(ctx context.Context, t ticketContent) (created, error)
	// update sets a ticket's title and the priority of a severity.
	update(ctx context.Context, r ref, title, severity string) error
	// setStatus moves a ticket to the status a case status maps to, and
	// returns the status it moved to. resolution is the case's
	// resolution, for a system that asks for close notes.
	setStatus(ctx context.Context, r ref, caseStatus, resolution string) (RemoteStatus, error)
	// comment adds a comment and returns its ID, or "" when the system
	// does not say.
	comment(ctx context.Context, r ref, text string) (string, error)
	// poll returns the state of each of refs changed since since, or of
	// all of them when since is zero. A ticket that no longer exists is
	// returned with Gone set.
	poll(ctx context.Context, refs []ref, since time.Time) ([]remoteState, error)
	// comments returns a ticket's comments, oldest first.
	comments(ctx context.Context, r ref) ([]comment, error)
	// find returns the ticket opened earlier for a case, by the marker
	// create puts on it (jiraLabel, correlationID), or nil when there is
	// none. It is asked before a ticket is opened again for a case whose
	// earlier opening may have created one, so a crash never opens two.
	// Anyone who can open tickets can put the marker on one, so only a
	// ticket the connection's own account opened at or after since is
	// found, the newest when there are several; when the system cannot
	// say who the account is, none is.
	find(ctx context.Context, caseID string, since time.Time) (*created, error)
	// test checks the credentials and access to the project or table,
	// and says what it found.
	test(ctx context.Context) (string, error)
}

// ref names a ticket: Key is how people name it (PROJ-12, INC0010001),
// ID how the API does.
type ref struct {
	Key string
	ID  string
}

// created is a ticket just opened.
type created struct {
	ref
	URL     string
	Status  RemoteStatus
	Updated string
}

// remoteState is a ticket's state as polled.
type remoteState struct {
	ref
	Status RemoteStatus
	// Updated is when the ticket last changed, as the system writes it;
	// it is only compared with the last value seen.
	Updated string
	Gone    bool
}

// comment is one comment on a ticket.
type comment struct {
	ID     string
	Author string
	Text   string
	// Own is a comment by the connection's own account. OwnUnknown is
	// set instead when the system does not say who that account is
	// (ServiceNow with OAuth, or a Jira whose /myself fails).
	Own, OwnUnknown bool
}

// remote returns the client of a connection's system.
func (s *Service) remote(c Connection) (remote, error) {
	cl, err := s.newClient(c)
	if err != nil {
		return nil, err
	}
	if c.Type == TypeServiceNow {
		return &serviceNow{client: cl}, nil
	}
	return &jira{client: cl}, nil
}

// chunks splits refs into lists of at most n.
func chunks(refs []ref, n int) [][]ref {
	var out [][]ref
	for len(refs) > 0 {
		k := min(n, len(refs))
		out = append(out, refs[:k])
		refs = refs[k:]
	}
	return out
}

// pollChunk is how many tickets one poll request asks about.
const pollChunk = 50

// maxComments is the most comments read from one ticket, in at most
// maxCommentPages pages (Jira may answer with pages smaller than asked).
const (
	maxComments     = 1000
	maxCommentPages = 50
)

// pageSize is how many items one page of a search or of a ticket's
// comments asks for; more in an answer are left out.
const pageSize = 100

// pages returns how many pages of size a list of total items takes, plus
// one in case it grew, and never more than most: a system's total is not
// trusted beyond that.
func pages(total, size, most int) int {
	if total <= 0 || size <= 0 {
		return 1
	}
	return min(total/size+1, most)
}
