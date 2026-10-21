// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/setupguide"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// routeSetupGuide adds the setup guide: the walkthrough Signalith offers
// each user on first use, with what is already done checked off. Each
// user answers for themselves (skip a step, ask me later, don't ask
// again), so both routes are their own, for every role.
func (s *Server) routeSetupGuide(api *router) {
	api.viewer("GET /api/me/setup", s.handleGetSetupGuide)
	api.viewer("PUT /api/me/setup", s.handlePutSetupGuide)
}

// setupStep is one step of the guide. Done is whether Signalith sees it
// done, or the user opened its page from the guide (for a step it cannot
// check); Optional steps are nice to have.
type setupStep struct {
	ID       string `json:"id"`
	Done     bool   `json:"done"`
	Optional bool   `json:"optional,omitempty"`
	// Unknown says Signalith could not tell whether it is done.
	Unknown bool `json:"unknown,omitempty"`
	// Count is a number the step shows: the security checks at risk.
	Count int `json:"count,omitempty"`
	// Attention is the security checks that need attention.
	Attention int `json:"attention,omitempty"`
}

type setupGuideView struct {
	setupguide.Choice
	// Ask says the guide should open on its own now.
	Ask   bool        `json:"ask"`
	Steps []setupStep `json:"steps"`
}

func (s *Server) setupGuide() setupguide.Store {
	if s.SetupGuide != nil {
		return s.SetupGuide
	}
	return &s.setupGuideMem
}

func (s *Server) handleGetSetupGuide(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	p := principalOf(r)
	c, err := s.setupGuide().Get(ctx, p.Username)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("could not read your setup guide choices: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.setupGuideView(ctx, p, c))
}

func (s *Server) handlePutSetupGuide(w http.ResponseWriter, r *http.Request) {
	var c setupguide.Choice
	if err := readJSON(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := c.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	c.At, c.Until = now, nil
	if c.State == setupguide.Later {
		until := now.Add(setupguide.LaterFor)
		c.Until = &until
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	p := principalOf(r)
	if err := s.setupGuide().Put(ctx, p.Username, c); err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("could not save your setup guide choice: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.setupGuideView(ctx, p, c))
}

// setupGuideView is the guide for p: its steps, checked now, and whether
// it should open on its own. It opens on its own only in the user's own
// tenant (a provider admin visiting a tenant is not asked again there),
// and only while a step is left.
func (s *Server) setupGuideView(ctx context.Context, p *principal, c setupguide.Choice) setupGuideView {
	v := setupGuideView{Choice: c, Steps: s.setupSteps(ctx, p, c)}
	left := false
	for _, st := range v.Steps {
		if !st.Done && !slices.Contains(c.Skipped, st.ID) {
			left = true
		}
	}
	home := p.Active == "" || p.Active == p.Tenant || (p.Tenant == "" && p.Active == tenants.Default)
	v.Ask = left && home && c.Ask(time.Now())
	return v
}

// setupSteps lists the guide's steps for p, in order. Everyone secures
// their own sign-in and learns to search; admins also bring in data, get
// alerts, add their team and, on the provider's server, check the
// Security page and (optionally) connect an AI model.
func (s *Server) setupSteps(ctx context.Context, p *principal, c setupguide.Choice) []setupStep {
	opened := func(id string) bool { return slices.Contains(c.Opened, id) }
	var out []setupStep
	// Single sign-on users get two-step sign-in from their identity
	// provider.
	if mfaSource(p.Source) {
		out = append(out, setupStep{ID: "mfa", Done: p.MFA})
	}
	if p.Role.AtLeast(users.Admin) {
		data := setupStep{ID: "data", Unknown: true}
		if s.Sample != nil {
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			seen, err := s.Sample.AnyEventSince(dctx, 7*24*time.Hour)
			cancel()
			data.Done, data.Unknown = seen, err != nil
		}
		out = append(out, data)
		if s.Notify != nil && s.Notify.Settings != nil {
			set, _ := s.Notify.Settings.Settings()
			out = append(out, setupStep{ID: "notify", Done: len(set.Channels) > 0})
		}
		out = append(out, setupStep{ID: "team", Done: s.hasTeam(p)})
		if p.runsServer() {
			sec := setupStep{ID: "security", Unknown: true}
			if rep := s.security().Report(); rep != nil {
				sum := rep.Summary
				sec.Done, sec.Unknown, sec.Count, sec.Attention = sum.Risk == 0 && sum.Attention == 0, false, sum.Risk, sum.Attention
			}
			out = append(out, sec)
			out = append(out, setupStep{ID: "ai", Optional: true, Done: s.conf().Assistant.Provider != "" || opened("ai")})
		}
	} else {
		out = append(out, setupStep{ID: "findings", Done: opened("findings")})
	}
	out = append(out, setupStep{ID: "search", Done: opened("search")})
	return out
}

// hasTeam reports whether p is not the only one who can sign in: another
// user of p's tenant (or of the provider), or directory sign-in.
func (s *Server) hasTeam(p *principal) bool {
	if d := s.dir().Settings(); p.Tenant == "" && d.IsEnabled() {
		return true
	}
	for _, u := range s.userStore().List() {
		if u.Tenant == p.Tenant && !u.Disabled && u.Username != p.Username {
			return true
		}
	}
	return false
}
