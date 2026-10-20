// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/ticketing"
)

// Ticketing is what the Ticketing page and the case page's Tickets panel
// work with.
type Ticketing struct {
	Service *ticketing.Service

	testMu sync.Mutex // one test at a time
}

// routeTicketing registers the ticketing routes. Setting connections up
// is admin work, and saving them asks for the password again: they hold
// API tokens and decide where case details go. Opening a ticket from a
// case is analyst work, like the rest of working a case.
func (s *Server) routeTicketing(api *router) {
	api.admin("GET /api/ticketing", s.handleTicketing)
	api.sensitive("PUT /api/ticketing", s.handleTicketingSave)
	api.admin("POST /api/ticketing/test", s.handleTicketingTest)
	api.viewer("GET /api/cases/{id}/tickets", s.handleCaseTickets)
	api.analyst("POST /api/cases/{id}/tickets", s.handleCaseTicketCreate)
}

var errTicketingOff = errors.New("ticketing is not available on this server")

func (s *Server) ticketingOK(w http.ResponseWriter) bool {
	if s.Ticketing == nil || s.Ticketing.Service == nil || s.Ticketing.Service.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, errTicketingOff)
		return false
	}
	return true
}

// errTicketingNoJobs refuses changes on a server that does not sync
// tickets: its ticketing file is not the one the syncing server reads.
var errTicketingNoJobs = errors.New("this server does not sync tickets (detections.scheduler is off here), so connections are set on the Signalith server that runs the background jobs")

// ticketingElsewhere says why connections are not set, and tickets not
// opened, on this server now, or nil. Of the servers that share one
// OpenSearch, only the one that runs the background jobs calls Jira and
// ServiceNow, with its own connections.
func (s *Server) ticketingElsewhere() error {
	if s.conf() == nil || !s.conf().Detections.Scheduler {
		return errTicketingNoJobs
	}
	if s.Cluster == nil || s.Cluster.RunsJobs() {
		return nil
	}
	if holder := s.Cluster.JobHolder(); holder != "" {
		return fmt.Errorf("this server does not sync tickets right now: %s does, with its own connections; set them there", holder)
	}
	return errors.New("this server does not sync tickets right now, and no server runs the background jobs at the moment; the Servers page says why")
}

// connectionView is a connection as the page shows it: its secrets only
// say whether they are set.
type connectionView struct {
	ticketing.Connection
	Label           string `json:"label"`
	TokenSet        bool   `json:"token_set"`
	PasswordSet     bool   `json:"password_set"`
	ClientSecretSet bool   `json:"client_secret_set"`
	Problem         string `json:"problem,omitempty"`
	// Tickets counts the tickets kept in step, and Failing those whose
	// last sync failed.
	Tickets int `json:"tickets"`
	Failing int `json:"failing"`
}

// linkProblem is a ticket whose last sync or opening failed.
type linkProblem struct {
	CaseID     string    `json:"case_id"`
	Connection string    `json:"connection"`
	Key        string    `json:"key,omitempty"`
	State      string    `json:"state"`
	Error      string    `json:"error"`
	ErrorAt    time.Time `json:"error_at"`
}

// errTicketingProvider says why a tenant's own admins see their tenant's
// connections but do not change them.
var errTicketingProvider = errors.New("connections send case details to the addresses they name, so only the provider's users set them up, while in this tenant")

// ticketingView is the page's data, for the request's user. This server's
// connections are its tenant's only (each tenant has a server, and a
// Service, of its own).
func (s *Server) ticketingView(ctx context.Context, r *http.Request, set ticketing.Settings, fileErr error) map[string]any {
	t := s.Ticketing.Service
	out := map[string]any{}
	counts, failing := map[string]int{}, map[string]int{}
	problems := []linkProblem{}
	if t.Links != nil && len(set.Connections) > 0 {
		due, err := t.Links.Due(ctx)
		if err != nil {
			out["links_error"] = "The tickets being kept in step could not be read from OpenSearch: " + err.Error()
		}
		for _, l := range due {
			if l.State == ticketing.StateLinked {
				counts[l.Connection]++
			}
			if l.Error != "" {
				failing[l.Connection]++
				problems = append(problems, linkProblem{CaseID: l.CaseID, Connection: l.Connection, Key: l.Key, State: l.State, Error: l.Error, ErrorAt: l.ErrorAt})
			}
		}
		slices.SortFunc(problems, func(a, b linkProblem) int { return b.ErrorAt.Compare(a.ErrorAt) })
		if len(problems) > 20 {
			problems = problems[:20]
		}
	}
	conns := make([]connectionView, 0, len(set.Connections))
	for _, c := range set.Connections {
		v := connectionView{Connection: c, Label: c.Label(), TokenSet: c.Token != "", PasswordSet: c.Password != "",
			ClientSecretSet: c.ClientSecret != "", Tickets: counts[c.ID], Failing: failing[c.ID]}
		if v.Statuses == nil {
			v.Statuses = map[string]string{}
		}
		if bad := c.Undecrypted(); len(bad) > 0 {
			v.Problem = "The saved " + strings.Join(bad, " and ") + " cannot be decrypted, because the master key changed. Edit the connection and enter it again."
		}
		conns = append(conns, v)
	}
	out["connections"] = conns
	out["problems"] = problems
	out["revision"] = t.Settings.Revision()
	// Where the file is, is how the server runs: the provider's business.
	p := principalOf(r)
	if p.runsServer() {
		out["file"] = fullPath(t.Settings.File)
	}
	out["types"] = ticketing.Types
	out["statuses"] = ticketing.CaseStatuses
	out["severities"] = ticketing.Severities
	out["default_priorities"] = ticketing.DefaultPriorities
	out["default_states"] = ticketing.DefaultStates
	out["marker"] = ticketing.Marker
	pub := strings.TrimSpace(s.conf().Server.PublicURL)
	out["public_url"] = pub
	if fileErr != nil {
		out["file_error"] = fileErr.Error()
	}
	err := s.ticketingElsewhere()
	if p != nil && p.Tenant != "" {
		err = errTicketingProvider
	}
	out["manage"] = fileErr == nil && err == nil
	if err != nil {
		out["manage_why"] = sentence(err.Error())
		switch {
		case errors.Is(err, errTicketingProvider):
			out["provider_only"] = true
		case s.Cluster != nil && !errors.Is(err, errTicketingNoJobs):
			out["runs_on"] = s.Cluster.JobHolder()
		}
	}
	return out
}

func (s *Server) handleTicketing(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOK(w) {
		return
	}
	set, err := s.Ticketing.Service.Settings.Settings()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.ticketingView(ctx, r, set, err))
}

func (s *Server) handleTicketingSave(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOK(w) {
		return
	}
	if err := s.ticketingElsewhere(); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var in ticketing.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	set, err := s.Ticketing.Service.Settings.Save(in)
	var ie *ticketing.InputError
	var fe *ticketing.FileError
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Problems})
		return
	case errors.Is(err, ticketing.ErrChanged), errors.As(err, &fe):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		s.Log.Error("could not save the ticketing connections", "err", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var names, auto, hosts, replaced []string
	for _, c := range set.Connections {
		names = append(names, c.Label())
		hosts = append(hosts, ticketingHost(c.URL))
		if c.AutoCreate {
			auto = append(auto, c.Label())
		}
	}
	for _, c := range in.Connections {
		if secretTyped(c) {
			replaced = append(replaced, c.Name)
		}
	}
	// A connection deleted or given new secrets leaves no token or
	// account of its own in memory.
	s.Ticketing.Service.Forget(set)
	s.audit(r, "ticketing connections changed", "connections", strings.Join(names, ", "), "hosts", strings.Join(hosts, ", "),
		"auto_create", strings.Join(auto, ", "), "secret_replaced", strings.Join(replaced, ", "))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.ticketingView(ctx, r, set, nil))
}

// handleTicketingTest checks a saved connection ({"id"}) or a connection
// being edited ({"connection"}, whose empty secrets are the saved
// connection's with the same ID, when its address is unchanged).
func (s *Server) handleTicketingTest(w http.ResponseWriter, r *http.Request) {
	if !s.ticketingOK(w) {
		return
	}
	if err := s.ticketingElsewhere(); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var req struct {
		ID         string                     `json:"id"`
		Connection *ticketing.ConnectionInput `json:"connection"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	t := s.Ticketing.Service
	var c ticketing.Connection
	if req.Connection != nil {
		conn, err := t.Settings.Check(*req.Connection)
		var ie *ticketing.InputError
		if errors.As(err, &ie) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Problems})
			return
		}
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		c = conn
	} else {
		set, err := t.Settings.Settings()
		conn, ok := set.Connection(strings.TrimSpace(req.ID))
		if err != nil || !ok {
			writeError(w, http.StatusNotFound, errors.New("there is no connection with this ID; reload the page"))
			return
		}
		c = conn
	}
	if !s.Ticketing.testMu.TryLock() {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, errors.New("another connection is being tested; try again in a moment"))
		return
	}
	defer s.Ticketing.testMu.Unlock()
	start := time.Now()
	msg, err := t.Test(r.Context(), c)
	out := map[string]any{"ok": err == nil, "duration_ms": time.Since(start).Milliseconds(), "connection": c.Name}
	typed := req.Connection != nil && secretTyped(*req.Connection)
	if err != nil {
		out["error"] = err.Error()
		s.audit(r, "ticketing connection test failed", "connection", c.Name, "system", c.Type, "host", ticketingHost(c.URL),
			"secret_replaced", typed, "err", err.Error())
	} else {
		out["message"] = msg
		s.audit(r, "ticketing connection test passed", "connection", c.Name, "system", c.Type, "host", ticketingHost(c.URL),
			"secret_replaced", typed)
	}
	writeJSON(w, http.StatusOK, out)
}

// ticketingHost is the host (and port) of a connection's address, for the
// audit log.
func ticketingHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// secretTyped reports whether a connection as the page sent it sets a new
// API token, password or client secret, rather than keeping the saved one.
func secretTyped(c ticketing.ConnectionInput) bool {
	return c.Token != "" || c.Password != "" || c.ClientSecret != ""
}

// ticketView is a case's ticket as the Tickets panel shows it.
type ticketView struct {
	Connection     string    `json:"connection"`
	ConnectionName string    `json:"connection_name"`
	System         string    `json:"system"`
	Key            string    `json:"key,omitempty"`
	URL            string    `json:"url,omitempty"`
	State          string    `json:"state"`
	RemoteStatus   string    `json:"remote_status,omitempty"`
	Error          string    `json:"error,omitempty"`
	ErrorAt        time.Time `json:"error_at,omitzero"`
	SyncedAt       time.Time `json:"synced_at,omitzero"`
	Auto           bool      `json:"auto,omitempty"`
	CreatedBy      string    `json:"created_by,omitempty"`
	Created        time.Time `json:"created"`
}

// safeLink returns a ticket's address when it is a web address, or "".
func safeLink(u string) string {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return u
	}
	return ""
}

func linkView(l ticketing.Link) ticketView {
	// Comments left out of the case show like a problem, when there is
	// none.
	msg := l.Error
	if msg == "" {
		msg = l.Warning
	}
	return ticketView{Connection: l.Connection, ConnectionName: l.ConnectionName, System: l.System, Key: l.Key, URL: safeLink(l.URL),
		State: l.State, RemoteStatus: l.RemoteStatus.Label(l.System), Error: msg, ErrorAt: l.ErrorAt, SyncedAt: l.SyncedAt,
		Auto: l.Auto, CreatedBy: l.CreatedBy, Created: l.Created}
}

type connectionRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// handleCaseTickets lists a case's tickets, how each is kept in step, and
// the connections a ticket can be opened in.
func (s *Server) handleCaseTickets(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	c, err := s.Cases.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCaseError(w, err)
		return
	}
	out := map[string]any{"tickets": []ticketView{}, "connections": []connectionRef{}, "available": false}
	if s.Ticketing == nil || s.Ticketing.Service == nil {
		// The case still lists its tickets.
		list := []ticketView{}
		for _, t := range c.Tickets {
			list = append(list, ticketView{Connection: t.Connection, System: t.System, Key: t.Key, URL: safeLink(t.URL), State: ticketing.StateLinked, CreatedBy: t.CreatedBy, Created: t.Created})
		}
		out["tickets"] = list
		writeJSON(w, http.StatusOK, out)
		return
	}
	t := s.Ticketing.Service
	set, _ := t.Settings.Settings()
	links, err := t.LinksOf(r.Context(), c.ID)
	if err != nil {
		out["links_error"] = "How the tickets are kept in step could not be read from OpenSearch: " + err.Error()
	}
	list := []ticketView{}
	seen := map[string]bool{}
	for _, st := range links {
		l := st.Link
		v := linkView(l)
		if conn, ok := set.Connection(l.Connection); ok {
			v.ConnectionName = conn.Name
		}
		list = append(list, v)
		seen[l.Connection] = true
	}
	for _, tk := range c.Tickets {
		if seen[tk.Connection] {
			continue
		}
		list = append(list, ticketView{Connection: tk.Connection, System: tk.System, Key: tk.Key, URL: safeLink(tk.URL), State: ticketing.StateLinked, CreatedBy: tk.CreatedBy, Created: tk.Created})
	}
	conns := []connectionRef{}
	for _, conn := range set.Connections {
		conns = append(conns, connectionRef{ID: conn.ID, Name: conn.Name, Type: conn.Type, Label: conn.Label()})
	}
	out["tickets"], out["connections"], out["available"] = list, conns, true
	out["public_url_set"] = strings.TrimSpace(s.conf().Server.PublicURL) != ""
	if err := s.ticketingElsewhere(); err != nil && s.Cluster != nil && !errors.Is(err, errTicketingNoJobs) {
		out["runs_on"] = s.Cluster.JobHolder()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCaseTicketCreate opens a ticket for a case. The server that runs
// the background jobs opens it at once; another asks that one to, which
// it does within a minute.
func (s *Server) handleCaseTicketCreate(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) || !s.ticketingOK(w) {
		return
	}
	var req struct {
		Connection string `json:"connection"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	connID := strings.TrimSpace(req.Connection)
	if connID == "" {
		writeError(w, http.StatusBadRequest, errors.New("pick the connection to open the ticket in"))
		return
	}
	t := s.Ticketing.Service
	caseID, user := r.PathValue("id"), userOf(r)
	here := s.ticketingElsewhere() == nil
	var l *ticketing.Link
	var err error
	if here {
		ctx, cancel := context.WithTimeout(r.Context(), 3*ticketing.RequestTimeout)
		defer cancel()
		l, err = t.Create(ctx, caseID, connID, user)
	} else {
		l, err = t.Request(r.Context(), caseID, connID, user)
	}
	var le *ticketing.LinkedError
	var te *ticketing.Error
	var fe *ticketing.FileError
	switch {
	case err == nil:
	case errors.Is(err, ticketing.ErrNoConnection), errors.Is(err, cases.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
		return
	case errors.As(err, &le), errors.Is(err, ticketing.ErrInProgress), errors.As(err, &fe):
		writeError(w, http.StatusConflict, err)
		return
	case errors.As(err, &te):
		writeError(w, http.StatusBadGateway, errors.New("Could not open the ticket. "+te.Msg))
		return
	default:
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if !here {
		writeJSON(w, http.StatusAccepted, map[string]any{"ticket": linkView(*l), "queued": true})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": linkView(*l)})
}
