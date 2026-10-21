// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Settings > Behavior baselines: what each check has learned, and its
// settings and exceptions. The settings are kept in the baselines index,
// so every server shares them; the server that runs the background jobs
// reads them before each round. See docs/baselines.md.
func (s *Server) routeBaselines(api *router) {
	api.admin("GET /api/baselines", s.handleBaselines)
	api.admin("PUT /api/baselines", s.handleSaveBaselines)
	api.admin("POST /api/baselines/{check}/reset", s.handleResetBaseline)
}

// tenantUser reports whether the request is a tenant's user's, not one
// of the provider's own.
func tenantUser(r *http.Request) bool {
	p := principalOf(r)
	return p != nil && p.Tenant != ""
}

var errBaselinesOff = errors.New("behavior baselines need OpenSearch, which this server is not set up with")

// baselineCheck is one check as the page shows it.
type baselineCheck struct {
	baselines.Check
	On       bool  `json:"on"`
	Score    int   `json:"score"`
	Profiles int64 `json:"profiles"`
	// MaxValues is the most values it keeps per user or host.
	MaxValues int `json:"max_values"`
	baselines.CheckState
	// LearningUntil is when the users or hosts seen since the check
	// started have all learned for the learning period.
	LearningUntil time.Time `json:"learning_until,omitzero"`
	// Waiting says why the check cannot learn yet, if it cannot.
	Waiting string `json:"waiting,omitempty"`
}

type baselinesView struct {
	Settings baselines.Settings `json:"settings"`
	Version  string             `json:"version"`
	Checks   []baselineCheck    `json:"checks"`
	// Through is the end of the last hour learned from, LiveFrom when the
	// baselines first ran, LastRun when they last learned, and LastError
	// why the last round failed.
	Through   time.Time `json:"through,omitzero"`
	LiveFrom  time.Time `json:"live_from,omitzero"`
	LastRun   time.Time `json:"last_run,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	// Behind is how far the last hour learned from is behind, in seconds.
	Behind     int64                `json:"behind_s"`
	IPDatabase baselines.IPDBStatus `json:"ip_database"`
	// IPDatabaseFixed is true for a tenant's users: where the IP database
	// comes from is the provider's to choose, since the server fetches it.
	IPDatabaseFixed bool           `json:"ip_database_fixed,omitempty"`
	Defaults        map[string]any `json:"defaults"`
}

func (s *Server) baselinesMissing(w http.ResponseWriter) bool {
	if s.Baselines == nil {
		writeError(w, http.StatusServiceUnavailable, errBaselinesOff)
		return true
	}
	return false
}

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	if s.baselinesMissing(w) {
		return
	}
	v, err := s.baselinesView(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	v.IPDatabaseFixed = tenantUser(r)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) baselinesView(ctx context.Context) (*baselinesView, error) {
	st := s.Baselines
	set, ver, err := st.Settings(ctx)
	if err != nil {
		return nil, err
	}
	state, _, _, err := st.State(ctx)
	if err != nil {
		return nil, err
	}
	ipdb, _, err := st.IPDBStatus(ctx)
	if err != nil {
		return nil, err
	}
	v := &baselinesView{Settings: set, Version: ver.String(), Through: state.Through, LiveFrom: state.LiveFrom,
		LastRun: state.LastRun, LastError: state.LastError, IPDatabase: ipdb,
		Defaults: map[string]any{
			"learning_days": baselines.DefaultLearningDays, "forget_days": baselines.DefaultForgetDays,
			"rare_hosts": baselines.DefaultRareHosts, "min_mb": baselines.DefaultMinMB,
			"ip_database": baselines.DefaultIPDatabase, "max_profiles": baselines.MaxProfiles,
			"max_values": baselines.MaxValues, "max_raised_per_hour": baselines.MaxRaisedPerHour,
			"replay_days": int(baselines.Replay(set) / (24 * time.Hour)),
		}}
	if v.Settings.Checks == nil {
		v.Settings.Checks = map[string]baselines.CheckSettings{}
	}
	if v.Settings.Exceptions == nil {
		v.Settings.Exceptions = []detect.Exception{}
	}
	if !state.Through.IsZero() {
		v.Behind = int64(max(time.Since(state.Through), 0) / time.Second)
	}
	for _, c := range baselines.Checks {
		bc := baselineCheck{Check: c, On: set.On(c.ID), Score: set.Score(c.ID), MaxValues: baselines.ValueLimit(c.ID)}
		if cs := state.Checks[c.ID]; cs != nil {
			bc.CheckState = *cs
		}
		if bc.On && !bc.Started.IsZero() {
			bc.LearningUntil = bc.Started.Add(set.Learning())
			if (!state.LiveFrom.IsZero() && bc.Started.Equal(state.LiveFrom)) || bc.Started.Equal(bc.CheckState.LiveFrom) {
				// The first run, or a check turned on or reset since,
				// learned from the history already stored, so users and
				// hosts with a history are judged at once.
				bc.LearningUntil = time.Time{}
			}
		}
		if bc.On && c.IPDB {
			switch {
			case set.IPSource() == "":
				bc.Waiting = "Needs the IP database, which is off."
			case ipdb.Rows == 0 && ipdb.Error != "":
				bc.Waiting = "Waiting for the IP database: " + ipdb.Error
			case ipdb.Rows == 0 && ipdb.TriedAt.IsZero():
				bc.Waiting = "The IP database is downloaded at the first sign-in from an internet address."
			case ipdb.Rows == 0:
				bc.Waiting = "Waiting for the IP database to download."
			}
		}
		n, err := st.Count(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		bc.Profiles = n
		v.Checks = append(v.Checks, bc)
	}
	return v, nil
}

// handleSaveBaselines saves the settings and exceptions, over the version
// the page read.
func (s *Server) handleSaveBaselines(w http.ResponseWriter, r *http.Request) {
	if s.baselinesMissing(w) {
		return
	}
	var req struct {
		Settings baselines.Settings `json:"settings"`
		Version  string             `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	saved, cur, err := s.Baselines.Settings(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	conflict := errors.New("someone else changed the behavior baseline settings since you opened them; reload to see their changes")
	if req.Version != cur.String() {
		writeError(w, http.StatusConflict, conflict)
		return
	}
	next := req.Settings
	next.IPDatabase = strings.TrimSpace(next.IPDatabase)
	// The server fetches the IP database from where the setting says, so
	// a tenant's users may not point it elsewhere: the provider's network
	// is not theirs to reach (as with the providerManaged routes).
	if tenantUser(r) && next.IPDatabase != saved.IPDatabase {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "Where the IP database comes from is set by the provider that runs Signalith.", "code": "provider_only"})
		return
	}
	// A reset is asked for only with the reset route, and carries over.
	for id, cs := range next.Checks {
		cs.ResetAt = saved.Checks[id].ResetAt
		next.Checks[id] = cs
	}
	for id, cs := range saved.Checks {
		if _, ok := next.Checks[id]; !ok && !cs.ResetAt.IsZero() {
			if next.Checks == nil {
				next.Checks = map[string]baselines.CheckSettings{}
			}
			next.Checks[id] = baselines.CheckSettings{ResetAt: cs.ResetAt}
		}
	}
	next.Exceptions = stampExceptions(next.Exceptions, saved.Exceptions, userOf(r), time.Now().UTC())
	if p := next.Problems(); len(p) > 0 {
		writeError(w, http.StatusBadRequest, errors.New(strings.Join(p, " ")))
		return
	}
	if _, err := s.Baselines.SaveSettings(ctx, next, cur); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, conflict)
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var off []string
	for _, c := range baselines.Checks {
		if !next.On(c.ID) {
			off = append(off, c.ID)
		}
	}
	s.audit(r, "behavior baseline settings saved", "off", next.Off, "checks_off", off,
		"learning_days", next.LearningDays, "ip_database", redactedSource(next.IPDatabase),
		"exceptions", len(next.Exceptions), "exceptions_before", len(saved.Exceptions))
	s.handleBaselines(w, r)
}

// stampExceptions gives new exceptions an ID, who added them and when;
// those already saved keep theirs, whatever the request says.
func stampExceptions(next, saved []detect.Exception, by string, now time.Time) []detect.Exception {
	old := map[string]detect.Exception{}
	for _, e := range saved {
		old[e.ID] = e
	}
	out := make([]detect.Exception, 0, len(next))
	for _, e := range next {
		if prev, ok := old[e.ID]; ok && e.ID != "" {
			e.By, e.Added = prev.By, prev.Added
		} else {
			e.ID, e.By, e.Added = detect.NewExceptionID(), by, now
		}
		e.Comment = strings.TrimSpace(e.Comment)
		for k, v := range e.Match {
			if strings.TrimSpace(v) == "" {
				delete(e.Match, k)
			} else {
				e.Match[k] = strings.TrimSpace(v)
			}
		}
		out = append(out, e)
	}
	return out
}

// redactedSource leaves a download address's host and path out of the
// audit log's query string, which could hold a key.
func redactedSource(v string) string {
	before, _, _ := strings.Cut(v, "?")
	return before
}

// handleResetBaseline asks for a check's profiles to be forgotten: the
// server that runs the background jobs removes them at its next round,
// and the check learns again from then on.
func (s *Server) handleResetBaseline(w http.ResponseWriter, r *http.Request) {
	if s.baselinesMissing(w) {
		return
	}
	id := r.PathValue("check")
	if !slices.ContainsFunc(baselines.Checks, func(c baselines.Check) bool { return c.ID == id }) {
		writeError(w, http.StatusNotFound, errors.New("there is no such check"))
		return
	}
	ctx := r.Context()
	for range 3 {
		set, cur, err := s.Baselines.Settings(ctx)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if set.Checks == nil {
			set.Checks = map[string]baselines.CheckSettings{}
		}
		cs := set.Checks[id]
		cs.ResetAt = time.Now().UTC()
		set.Checks[id] = cs
		if _, err := s.Baselines.SaveSettings(ctx, set, cur); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			writeError(w, http.StatusBadGateway, err)
			return
		}
		s.audit(r, "behavior baseline reset", "check", id)
		s.handleBaselines(w, r)
		return
	}
	writeError(w, http.StatusConflict, errors.New("the settings kept changing; try again"))
}
