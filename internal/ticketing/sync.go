// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The sync is the background job "ticketing". Every Interval it:
//
//  1. opens the tickets analysts asked for on other servers, and tries
//     again the ones a connection failed to open by itself;
//  2. opens a ticket for each new case a connection opens them for
//     (AutoCreate);
//  3. asks each system which of the linked tickets changed since the last
//     pass, finds the cases with tickets that changed, and brings each
//     changed pair in step.
//
// Bringing a pair in step goes both ways. From the ticket: its new
// comments become case notes (by "jira:<name>" or "servicenow:<user>"),
// and a new status moves the case by the connection's mapping. From the
// case: a new status moves the ticket, a new title or severity changes
// its summary and priority, and new notes become comments that start with
// Marker. When both statuses changed since the last pass, the case's wins
// and the ticket moves back.
//
// Nothing echoes back: each link remembers the statuses last sent and
// seen, the notes sent or taken by ID, and the comments taken or written
// by ID; a comment that starts with Marker is never taken, and a note by
// "jira:" or "servicenow:" is never sent. Every hour, and when the server
// takes the jobs over, a pass looks at every linked ticket, so nothing
// missed stays missed.

// Timing and limits of the sync.
const (
	Interval = time.Minute
	// fullEvery is how often a pass looks at every linked ticket.
	fullEvery = time.Hour
	// overlap is how far back each pass looks before the last one
	// started, for changes saved while it ran and clocks a little apart.
	overlap = 2 * time.Minute
	// retryEvery is how long a link whose last sync failed waits before
	// it is tried again on a pass that has nothing new for it.
	retryEvery = 5 * time.Minute
	// quietAfter is how long after a case was last changed a link of a
	// closed case whose ticket agrees stops being polled.
	quietAfter = 30 * 24 * time.Hour
	// maxAutoAttempts is how many times a connection tries to open a
	// ticket by itself.
	maxAutoAttempts = 3
	// maxPassCases is the most changed cases one pass reads; more wait
	// for the next pass, which looks at every ticket.
	maxPassCases = 1000
	// autoLookBack bounds how far back the first pass after a start looks
	// for new cases to open tickets for.
	autoLookBack = 7 * 24 * time.Hour
	// passTimeout bounds the time one pass spends on one connection's
	// requests, from its first; what is left waits for the next pass.
	passTimeout = 2 * time.Minute
	// maxImportPass is the most of a ticket's comments one pass adds to
	// its case; the rest wait for the next pass.
	maxImportPass = 50
	// maxImportLink is the most of a ticket's comments ever added to its
	// case; later ones are left out, and the ticket says so.
	maxImportLink = 200
	// analystReserve is how many of a case's timeline entries
	// (cases.MaxEntries) ticket comments never take, so a ticket cannot
	// fill the case and keep analysts from adding notes.
	analystReserve = 100
)

// budgetKey is the context key of a pass's budget.
type budgetKey struct{}

// budget is when each connection's share of a pass ends: passTimeout
// after its first request in the pass.
type budget struct {
	mu    sync.Mutex
	limit time.Duration
	ends  map[string]time.Time
}

// withBudget returns ctx with a new pass budget of limit per connection.
func withBudget(ctx context.Context, limit time.Duration) context.Context {
	return context.WithValue(ctx, budgetKey{}, &budget{limit: limit, ends: map[string]time.Time{}})
}

// passDeadline returns when connection connID's share of the pass in ctx
// ends, starting it now if it has not started; zero outside a pass.
func passDeadline(ctx context.Context, connID string) time.Time {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	if b == nil {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	end, ok := b.ends[connID]
	if !ok {
		end = time.Now().Add(b.limit)
		b.ends[connID] = end
	}
	return end
}

// spent reports whether connection connID used up its share of the pass
// in ctx.
func spent(ctx context.Context, connID string) bool {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	end, ok := b.ends[connID]
	return ok && !time.Now().Before(end)
}

// syncState is what the sync remembers between passes. It is kept in
// memory: a server that takes the jobs over starts with a pass that
// looks at every ticket.
type syncState struct {
	casesCursor time.Time
	autoCursor  map[string]time.Time // by connection
	polled      map[string]time.Time // by connection: when its last poll started
	lastFull    time.Time
	paused      map[string]time.Time // by connection: no requests until then
	failures    map[string]int       // by connection: polls failed in a row
	problems    map[string]string    // the last problem logged, by subject
	mapped      bool                 // the cases index maps tickets
}

// Run syncs every Interval until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		s.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// problem logs a problem once until it changes or clears; "" clears it.
func (s *Service) problem(subject, msg string, args ...any) {
	s.mu.Lock()
	if s.st.problems == nil {
		s.st.problems = map[string]string{}
	}
	last := s.st.problems[subject]
	s.st.problems[subject] = msg
	s.mu.Unlock()
	switch {
	case msg == last:
	case msg == "":
		s.log().Info("ticketing works again", append([]any{"what", subject}, args...)...)
	default:
		s.log().Warn(msg, append([]any{"what", subject}, args...)...)
	}
}

// paused reports whether requests to a connection wait.
func (s *Service) paused(connID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.st.paused[connID])
}

// connFailed pauses a connection whose system could not be reached or
// asked Signalith to slow down: until the time it asked for, or for longer
// after each failure in a row, up to 30 minutes.
func (s *Service) connFailed(conn Connection, err error, now time.Time) {
	s.mu.Lock()
	if s.st.paused == nil {
		s.st.paused, s.st.failures = map[string]time.Time{}, map[string]int{}
	}
	s.st.failures[conn.ID]++
	n := s.st.failures[conn.ID]
	wait := min(time.Minute<<min(n-1, 5), 30*time.Minute)
	if e := errorOf(err); e != nil && !e.Until.IsZero() {
		wait = max(e.Until.Sub(now), time.Second)
	}
	s.st.paused[conn.ID] = now.Add(wait)
	s.mu.Unlock()
	s.problem("connection "+conn.ID, "ticketing could not reach a connection's system; it tries again later",
		"connection", conn.Name, "system", conn.Type, "retry_in", wait.Round(time.Second).String(), "err", Scrub(err.Error(), conn))
}

// connOK clears a connection's failures.
func (s *Service) connOK(conn Connection) {
	s.mu.Lock()
	delete(s.st.failures, conn.ID)
	delete(s.st.paused, conn.ID)
	s.mu.Unlock()
	s.problem("connection "+conn.ID, "", "connection", conn.Name)
}

// Pass does one round of the sync.
func (s *Service) Pass(ctx context.Context) {
	if !s.allowed() {
		return
	}
	set, err := s.Settings.Settings()
	if err != nil {
		s.problem("file", "ticketing does not sync until the ticketing file is fixed", "err", err)
		return
	}
	s.problem("file", "")
	// The connections may have changed in the file since the last pass.
	s.Forget(set)
	if len(set.Connections) == 0 {
		return
	}
	limit := s.passLimit
	if limit <= 0 {
		limit = passTimeout
	}
	ctx = withBudget(ctx, limit)
	now := s.now().UTC()
	due, err := s.Links.Due(ctx)
	if err != nil {
		s.problem("links", "ticketing could not read its links from OpenSearch; it tries again in a minute", "err", err)
		return
	}
	s.problem("links", "")
	for _, st := range due {
		if st.State != StatePending && st.State != StateFailed && st.State != StateCreating {
			continue
		}
		if !s.allowed() || ctx.Err() != nil {
			return
		}
		if spent(ctx, st.Connection) {
			continue
		}
		s.openDue(ctx, set, st, now)
	}
	s.autoCreate(ctx, set, now)
	s.syncAll(ctx, set, due, now)
}

// openDue opens a ticket asked for on another server, or tries again one
// a connection failed to open by itself.
func (s *Service) openDue(ctx context.Context, set Settings, st Stored, now time.Time) {
	conn, ok := set.Connection(st.Connection)
	if !ok {
		if st.State == StatePending {
			l := st.Link
			l.State, l.Error, l.ErrorAt, l.Updated = StateFailed, "The connection was removed on the Ticketing page.", now, now
			_, _ = s.Links.Update(ctx, &l, st.Version)
		}
		return
	}
	if s.paused(conn.ID, now) {
		return
	}
	if st.State == StateFailed && now.Before(st.ErrorAt.Add(time.Duration(st.Attempts)*retryEvery)) {
		return
	}
	l := st.Link
	if st.State == StateCreating {
		// A ticket a connection was opening by itself when its server
		// stopped: once stale, it may or may not exist, so the next try
		// looks for it first. The lost try counts toward the limit.
		if !st.Auto || now.Sub(st.Updated) < staleAfter {
			return
		}
		l.MayExist = true
		l.Attempts++
		if l.Attempts >= maxAutoAttempts {
			l.State, l.Error, l.ErrorAt, l.Updated = StateFailed, "The server opening this ticket stopped, and it could not be opened after several tries. Open it from the case.", now, now
			_, _ = s.Links.Update(ctx, &l, st.Version)
			return
		}
	}
	l.State, l.Updated, l.Server = StateCreating, now, s.Server
	v, err := s.Links.Update(ctx, &l, st.Version)
	if err != nil {
		return
	}
	if _, err := s.open(ctx, conn, Stored{Link: l, Version: v}); err != nil && !retryable(err) {
		return
	}
}

// autoCreate opens a ticket for each case opened since a connection's
// AutoSince at its least severity or above, that has none in it yet.
// Sample data never gets one.
func (s *Service) autoCreate(ctx context.Context, set Settings, now time.Time) {
	for _, conn := range set.Connections {
		if !conn.AutoCreate || s.paused(conn.ID, now) {
			continue
		}
		since := conn.AutoSince
		s.mu.Lock()
		cur := s.st.autoCursor[conn.ID]
		s.mu.Unlock()
		if !cur.IsZero() && cur.Add(-overlap).After(since) {
			since = cur.Add(-overlap)
		}
		if since.Before(now.Add(-autoLookBack)) {
			since = now.Add(-autoLookBack)
		}
		list, _, err := s.Cases.Search(ctx, cases.Filter{Status: cases.OpenStatuses, UpdatedSince: since, Limit: 500})
		if err != nil {
			s.problem("cases", "ticketing could not search the cases; it tries again in a minute", "err", err)
			continue
		}
		done := true
		for _, c := range list {
			if c.Sample != "" || c.Created.Before(conn.AutoSince) || !AtLeast(c.Severity, conn.AutoMinSeverity) {
				continue
			}
			if _, has := c.Ticket(conn.ID); has {
				continue
			}
			if !s.allowed() || ctx.Err() != nil {
				return
			}
			if spent(ctx, conn.ID) {
				done = false
				break
			}
			l := newLink(conn, c, "Signalith", true, StateCreating, now)
			v, err := s.Links.Create(ctx, l)
			if errors.Is(err, store.ErrExists) {
				// Opened, being opened, or failed and tried again in step 1.
				continue
			}
			if err != nil {
				done = false
				continue
			}
			if _, err := s.open(ctx, conn, Stored{Link: *l, Version: v}); err != nil && !retryable(err) {
				continue
			}
		}
		if done {
			s.mu.Lock()
			if s.st.autoCursor == nil {
				s.st.autoCursor = map[string]time.Time{}
			}
			s.st.autoCursor[conn.ID] = now
			s.mu.Unlock()
		}
	}
}

// workItem is a link to bring in step, with its ticket's state when the
// poll returned it.
type workItem struct {
	st Stored
	rs *remoteState
}

// syncAll brings in step the links whose ticket or case changed.
func (s *Service) syncAll(ctx context.Context, set Settings, due []Stored, now time.Time) {
	s.mu.Lock()
	full := s.st.lastFull.IsZero() || now.Sub(s.st.lastFull) >= fullEvery || s.st.casesCursor.IsZero()
	casesCursor := s.st.casesCursor
	s.mu.Unlock()

	byConn := map[string][]Stored{}
	for _, st := range due {
		if st.State == StateLinked && st.Active {
			byConn[st.Connection] = append(byConn[st.Connection], st)
		}
	}
	work := map[string]*workItem{}
	allPolled := true
	for connID, links := range byConn {
		conn, ok := set.Connection(connID)
		if !ok {
			s.problem("missing "+connID, "some tickets belong to a connection that is not on this server's Ticketing page, so they are not kept in step", "connection", links[0].ConnectionName)
			continue
		}
		if s.paused(conn.ID, now) {
			allPolled = false
			continue
		}
		rem, err := s.remote(conn)
		if err != nil {
			s.problem("connection "+conn.ID, "a ticketing connection cannot be used; edit it on the Ticketing page", "connection", conn.Name, "err", err)
			allPolled = false
			continue
		}
		var since time.Time
		if !full {
			s.mu.Lock()
			if p := s.st.polled[conn.ID]; !p.IsZero() {
				since = p.Add(-overlap)
			}
			s.mu.Unlock()
		}
		refs := make([]ref, 0, len(links))
		for _, l := range links {
			refs = append(refs, ref{Key: l.Key, ID: l.RemoteID})
		}
		states, err := rem.poll(ctx, refs, since)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if spent(ctx, conn.ID) {
				// Slow, not down: the next pass polls it again.
				allPolled = false
				continue
			}
			s.connFailed(conn, err, now)
			allPolled = false
			continue
		}
		s.connOK(conn)
		s.mu.Lock()
		if s.st.polled == nil {
			s.st.polled = map[string]time.Time{}
		}
		s.st.polled[conn.ID] = now
		s.mu.Unlock()
		byRef := map[string]remoteState{}
		for _, rs := range states {
			if rs.ID != "" {
				byRef["id:"+rs.ID] = rs
			}
			byRef["key:"+rs.Key] = rs
		}
		for _, l := range links {
			rs, has := byRef["id:"+l.RemoteID]
			if !has || l.RemoteID == "" {
				rs, has = byRef["key:"+l.Key]
			}
			retry := l.Error != "" && l.Error != l.StatusError && now.Sub(l.ErrorAt) >= retryEvery
			changed := has && (rs.Gone || rs.Updated != l.RemoteUpdated || rs.Status != l.RemoteStatus)
			if full || changed || retry || l.Backlog {
				it := &workItem{st: l}
				if has {
					rs := rs
					it.rs = &rs
				}
				work[l.ID] = it
			}
		}
	}

	// The cases with tickets that changed since the last pass, inactive
	// links among them: a case reopened after a long rest is polled again.
	casesOK := true
	if !full {
		list, total, err := s.Cases.Search(ctx, cases.Filter{Ticketed: true, UpdatedSince: casesCursor.Add(-overlap), Limit: maxPassCases})
		if err != nil {
			s.problem("cases", "ticketing could not search the cases; it tries again in a minute", "err", err)
			casesOK = false
		} else {
			s.problem("cases", "")
			if total > len(list) {
				// More changed than one pass reads: the next looks at all.
				allPolled = false
				s.mu.Lock()
				s.st.lastFull = time.Time{}
				s.mu.Unlock()
			}
			ids := make([]string, 0, len(list))
			for _, c := range list {
				ids = append(ids, c.ID)
			}
			if len(ids) > 0 {
				links, err := s.Links.ForCases(ctx, ids)
				if err != nil {
					s.problem("links", "ticketing could not read its links from OpenSearch; it tries again in a minute", "err", err)
					casesOK = false
				}
				for _, l := range links {
					if l.State != StateLinked || work[l.ID] != nil {
						continue
					}
					work[l.ID] = &workItem{st: l}
				}
			}
		}
	}

	items := make([]*workItem, 0, len(work))
	for _, it := range work {
		items = append(items, it)
	}
	slices.SortFunc(items, func(a, b *workItem) int {
		if c := a.st.Created.Compare(b.st.Created); c != 0 {
			return c
		}
		if a.st.ID < b.st.ID {
			return -1
		}
		return 1
	})
	for _, it := range items {
		if !s.allowed() || ctx.Err() != nil {
			return
		}
		conn, ok := set.Connection(it.st.Connection)
		if !ok || s.paused(conn.ID, now) || spent(ctx, conn.ID) {
			continue
		}
		s.syncLink(ctx, conn, it, now)
	}
	s.mu.Lock()
	if casesOK {
		s.st.casesCursor = now
	}
	if full && allPolled && casesOK {
		s.st.lastFull = now
	}
	s.mu.Unlock()
}

// pendingNote is a ticket comment to add to the case.
type pendingNote struct {
	author, text string
}

// syncLink brings one case and its ticket in step.
func (s *Service) syncLink(ctx context.Context, conn Connection, it *workItem, now time.Time) {
	l := it.st.Link
	before := l.Error
	log := s.log().With("connection", conn.Name, "system", conn.Type, "case", l.CaseID, "key", l.Key)
	c, err := s.Cases.Get(ctx, l.CaseID)
	if errors.Is(err, cases.ErrNotFound) {
		l.Active, l.Error, l.ErrorAt, l.Updated = false, "The case was deleted, so the ticket is no longer kept in step.", now, now
		s.saveLink(ctx, &l, it.st.Version)
		return
	}
	if err != nil {
		s.problem("cases", "ticketing could not read a case; it tries again in a minute", "case", l.CaseID, "err", err)
		return
	}
	rem, err := s.remote(conn)
	if err != nil {
		l.Error, l.ErrorAt = sentence(err.Error()), now
		s.saveLink(ctx, &l, it.st.Version)
		return
	}
	r := ref{Key: l.Key, ID: l.RemoteID}
	var problem error
	note := func(err error) {
		if problem == nil {
			problem = err
		}
	}

	rs := it.rs
	if rs == nil && l.Backlog {
		// Comments left by the last pass: read them again, with the
		// ticket as last seen.
		rs = &remoteState{ref: r, Status: l.RemoteStatus, Updated: l.RemoteUpdated}
	}
	if rs != nil {
		if rs.Gone {
			l.State, l.Active, l.Updated = StateGone, false, now
			l.Error, l.ErrorAt = "The ticket was deleted in "+TypeLabel(conn.Type)+", so it is no longer kept in step. Open a new one if it is still needed.", now
			s.saveLink(ctx, &l, it.st.Version)
			log.Info("ticket sync: the ticket was deleted", "audit", true)
			return
		}
		var notes []pendingNote
		seen := len(l.Comments)
		inboundOK := true
		backlog, warning := false, l.Warning
		if conn.SyncNotes && (rs.Updated != l.RemoteUpdated || l.Backlog) {
			list, err := rem.comments(ctx, r)
			if err != nil {
				note(err)
				inboundOK = false
			}
			// A ticket flooded with comments must not flood the case:
			// at most maxImportPass a pass, maxImportLink ever, and
			// never into the entries kept for analysts.
			passLeft := maxImportPass
			linkLeft := maxImportLink - l.Imported
			room := cases.MaxEntries - analystReserve - len(c.Entries)
			for _, cm := range list {
				if cm.ID == "" || slices.Contains(l.Comments, cm.ID) {
					continue
				}
				t := noteText(cm.Text)
				if t == "" || sentByUs(cm, c) {
					l.Comments = append(l.Comments, cm.ID)
					continue
				}
				switch {
				case linkLeft <= 0:
					warning = fmt.Sprintf("%d of the ticket's comments were added to the case, the most that are; later ones are not. Read them in %s.", maxImportLink, TypeLabel(conn.Type))
				case room <= 0:
					warning = "The case's timeline is nearly full, so the ticket's new comments were not added to it; the rest is kept for analysts' notes."
				case passLeft <= 0:
					// Taken on the next pass.
					backlog = true
				default:
					l.Comments = append(l.Comments, cm.ID)
					notes = append(notes, pendingNote{author: authorName(conn.Type, cm.Author), text: t})
					passLeft, linkLeft, room = passLeft-1, linkLeft-1, room-1
					continue
				}
				if backlog {
					break
				}
				// Left out for good.
				l.Comments = append(l.Comments, cm.ID)
			}
			if len(notes) > 0 && linkLeft > 0 && room > 0 {
				warning = ""
			}
		}
		prevRemote := l.RemoteStatus
		newStatus := ""
		if conn.SyncStatus && rs.Status.Name != "" && rs.Status != l.RemoteStatus {
			// When the case's status changed too, the case's wins: the
			// ticket is moved back below.
			if c.Status == l.CaseStatus && !conn.agrees(c.Status, rs.Status) {
				if cs := conn.caseStatusFor(rs.Status); cs != "" && cs != c.Status {
					newStatus = cs
				}
			}
			l.RemoteStatus = rs.Status
		}
		if len(notes) > 0 || newStatus != "" {
			updated, added, err := s.applyInbound(ctx, conn, l, notes, newStatus, now)
			if err != nil {
				// Taken again on the next pass.
				note(err)
				inboundOK = false
				l.Comments, l.RemoteStatus = l.Comments[:seen], prevRemote
			} else {
				c = updated
				l.Notes = append(l.Notes, added...)
				l.Imported += len(added)
				if len(added) > 0 {
					log.Info("ticket sync: added the ticket's new comments to the case", "audit", true, "comments", len(added))
				}
				if newStatus != "" {
					l.CaseStatus = c.Status
					log.Info("ticket sync: changed the case's status to match the ticket", "audit", true,
						"ticket_status", rs.Status.Label(conn.Type), "case_status", c.Status)
				}
			}
		}
		if inboundOK {
			if warning != "" && warning != l.Warning {
				log.Warn("ticket sync: some of the ticket's comments were not added to the case", "audit", true, "why", warning)
			}
			l.RemoteUpdated = rs.Updated
			l.Backlog, l.Warning = backlog, warning
		}
	}

	// The case's status, title, severity and notes go to the ticket.
	if !conn.SyncStatus {
		l.CaseStatus, l.StatusError = c.Status, ""
	} else if c.Status != l.CaseStatus {
		l.StatusError = ""
		if conn.agrees(c.Status, l.RemoteStatus) {
			l.CaseStatus = c.Status
		} else {
			from := l.RemoteStatus
			got, err := rem.setStatus(ctx, r, c.Status, c.Resolution)
			if got.Name != "" {
				l.RemoteStatus = got
			}
			switch {
			case err == nil:
				l.CaseStatus = c.Status
				log.Info("ticket sync: moved the ticket to match the case", "audit", true,
					"case_status", c.Status, "from", from.Label(conn.Type), "to", got.Label(conn.Type))
				if conn.Type == TypeJira && !findings.IsOpen(c.Status) && c.Resolution != "" && conn.SyncNotes {
					// Jira takes no close notes on a transition; the
					// resolution goes as a comment.
					id, err := rem.comment(ctx, r, truncate(Marker+" The case was "+strings.ReplaceAll(c.Status, "_", " ")+": "+c.Resolution, maxComment))
					if err != nil {
						note(err)
					} else if id != "" {
						l.Comments = append(l.Comments, id)
					}
				}
			case retryable(err):
				note(err)
			default:
				// Trying again cannot help until someone changes the
				// mapping or the workflow: it waits for the case's next
				// change, with the problem shown.
				note(err)
				l.CaseStatus, l.StatusError = c.Status, sentence(Scrub(err.Error(), conn))
			}
		}
	}
	if c.Title != l.CaseTitle || c.Severity != l.CaseSeverity {
		err := rem.update(ctx, r, c.Title, c.Severity)
		if err == nil {
			log.Info("ticket sync: changed the ticket's title and priority to match the case", "audit", true, "severity", c.Severity)
		} else {
			note(err)
		}
		if err == nil || !retryable(err) {
			l.CaseTitle, l.CaseSeverity = c.Title, c.Severity
		}
	}
	if conn.SyncNotes {
		sent := 0
		for _, e := range c.Entries {
			if e.Kind != cases.KindNote || slices.Contains(l.Notes, e.ID) || imported(e.Author) || e.Time.Before(l.Created) {
				continue
			}
			id, err := rem.comment(ctx, r, noteComment(e))
			if err != nil {
				note(err)
				break
			}
			sent++
			l.Notes = append(l.Notes, e.ID)
			if id != "" {
				l.Comments = append(l.Comments, id)
			}
		}
		if sent > 0 {
			log.Info("ticket sync: sent the case's new notes to the ticket", "audit", true, "notes", sent)
		}
	} else {
		// Notes added while syncing them is off are not sent later.
		for _, e := range c.Entries {
			if e.Kind == cases.KindNote && !slices.Contains(l.Notes, e.ID) {
				l.Notes = append(l.Notes, e.ID)
			}
		}
	}

	// A case closed long ago whose ticket agrees rests; a change to the
	// case wakes it.
	l.Active = findings.IsOpen(c.Status) || !conn.agrees(c.Status, l.RemoteStatus) || now.Sub(c.Updated) < quietAfter
	if _, ok := c.Ticket(conn.ID); !ok {
		if err := s.linkCase(ctx, l, now); err != nil {
			note(err)
		}
	}
	if len(l.Comments) > maxSeen {
		l.Comments = l.Comments[len(l.Comments)-maxSeen:]
	}
	l.SyncedAt, l.Updated, l.Server = now, now, s.Server
	switch {
	case problem != nil:
		l.Error, l.ErrorAt = sentence(Scrub(problem.Error(), conn)), now
		if e := errorOf(problem); e != nil && !e.Until.IsZero() {
			s.connFailed(conn, problem, now)
		}
	case l.StatusError != "":
		// Shown until the case's status changes.
		if l.Error != l.StatusError {
			l.Error, l.ErrorAt = l.StatusError, now
		}
	default:
		l.Error, l.ErrorAt = "", time.Time{}
	}
	switch {
	case l.Error != "" && l.Error != before:
		log.Warn("ticket sync: a case and its ticket could not be brought in step; it tries again later", "err", l.Error)
	case l.Error == "" && before != "":
		log.Info("ticket sync: a case and its ticket are in step again")
	}
	s.saveLink(ctx, &l, it.st.Version)
}

// applyInbound adds a ticket's new comments to its case as notes, and
// moves the case to status when it is not "". It returns the case as
// written and the IDs of the notes it added.
func (s *Service) applyInbound(ctx context.Context, conn Connection, l Link, notes []pendingNote, status string, now time.Time) (*cases.Case, []string, error) {
	var added []string
	c, err := s.Cases.Modify(ctx, l.CaseID, func(c *cases.Case) (bool, error) {
		added = added[:0]
		for _, n := range notes {
			if len(c.Entries) >= cases.MaxEntries-analystReserve {
				// The rest of the timeline is kept for analysts.
				s.problem("full "+c.ID, "a case's timeline is nearly full, so new ticket comments are not added to it", "case", c.ID)
				break
			}
			e, err := c.AddEntry(cases.Entry{Kind: cases.KindNote, Text: n.text}, n.author, now)
			if err != nil {
				// The case's timeline is full: the rest are left out.
				s.problem("full "+c.ID, "a case's timeline is full, so new ticket comments are not added to it", "case", c.ID)
				break
			}
			added = append(added, e.ID)
		}
		changed := len(added) > 0
		if status != "" && status != c.Status {
			st := status
			changed = c.Apply(cases.Update{Status: &st}, authorName(conn.Type, l.Key), now) || changed
		}
		return changed, nil
	})
	return c, added, err
}

// saveLink writes a link back over the version it was read at.
func (s *Service) saveLink(ctx context.Context, l *Link, v store.Version) {
	if _, err := s.Links.Update(ctx, l, v); err != nil {
		s.log().Warn("ticket sync: could not record what was synced; the next pass checks again", "case", l.CaseID, "key", l.Key, "err", err)
	}
}
