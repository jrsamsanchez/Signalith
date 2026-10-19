// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/summary"
	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// Settings > Search: how far each data model's summary indexes reach and
// where they have gaps, for every tenant this server runs. The states
// are read from each tenant's runtime index by its search engine every
// 30 seconds; this only shows the last read. See docs/summaries.md.
func (s *Server) routeSummaries(api *router) {
	api.admin("GET /api/summaries", s.handleSummaries)
}

// summaryModel is one data model's summaries as the card shows them.
type summaryModel struct {
	Model string `json:"model"`
	// Built is false until the summaries of the model were first built.
	Built   bool            `json:"built"`
	From    time.Time       `json:"from,omitzero"`
	Through time.Time       `json:"through,omitzero"`
	Covered []summary.Range `json:"covered,omitempty"`
	Gaps    []summary.Gap   `json:"gaps,omitempty"`
	Rows    int64           `json:"rows"`
	// Behind is how far Through is behind now, in seconds.
	Behind        int64     `json:"behind_s,omitempty"`
	LastBuild     time.Time `json:"last_build,omitzero"`
	CheckedRecent time.Time `json:"checked_recent,omitzero"`
	CheckedAll    time.Time `json:"checked_all,omitzero"`
	Rebuilt       int64     `json:"rebuilt"`
	LastError     string    `json:"last_error,omitempty"`
	Node          string    `json:"node,omitempty"`
}

// summaryTenant is the summaries of one tenant's data.
type summaryTenant struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name,omitempty"`
	// Read is when the states were last read; Error says the last read
	// failed, so searches read events only until a read works again.
	Read   time.Time      `json:"read,omitzero"`
	Error  string         `json:"error,omitempty"`
	Models []summaryModel `json:"models"`
}

type summariesView struct {
	Days    int             `json:"summary_days"`
	Enabled bool            `json:"enabled"`
	Tenants []summaryTenant `json:"tenants"`
}

func (s *Server) handleSummaries(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	v := summariesView{Days: s.Engine.SummaryDays()}
	v.Enabled = v.Days > 0 && s.Engine.Summaries != nil
	servers := []*Server{s}
	if s.TenantRuntime != nil {
		others := s.TenantRuntime.Servers()
		slices.SortFunc(others, func(a, b *Server) int { return cmp.Compare(a.TenantID, b.TenantID) })
		servers = append(servers, others...)
	}
	for _, ts := range servers {
		if ts.Engine == nil || ts.Engine.Summaries == nil {
			continue
		}
		v.Tenants = append(v.Tenants, s.summaryTenant(ts, now))
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) summaryTenant(ts *Server, now time.Time) summaryTenant {
	states, read, err := ts.Engine.Summaries.Status()
	t := summaryTenant{Tenant: ts.TenantID, Read: read, Models: []summaryModel{}}
	if t.Tenant == "" {
		t.Tenant = tenants.Default
	}
	if s.Tenants != nil {
		if x, gerr := s.Tenants.Get(t.Tenant); gerr == nil {
			t.Name = x.Name
		}
	}
	if err != nil {
		// The cause is OpenSearch's own answer; the server's log has it.
		t.Error = "Could not read the summaries' state from OpenSearch."
	}
	for _, m := range summary.Models() {
		st, ok := states[m]
		sm := summaryModel{Model: m, Built: ok && st.Through.After(st.From)}
		if ok {
			sm.From, sm.Through, sm.Gaps, sm.Rows = st.From, st.Through, st.Gaps, st.Rows
			sm.LastBuild, sm.CheckedRecent, sm.CheckedAll = st.LastBuild, st.CheckedRecent, st.CheckedAll
			sm.Rebuilt, sm.LastError, sm.Node = st.Rebuilt, st.LastError, st.Node
			sm.Covered = st.Covered()
			if sm.Built {
				sm.Behind = max(0, int64(now.Sub(st.Through)/time.Second))
			}
		}
		t.Models = append(t.Models, sm)
	}
	return t
}
