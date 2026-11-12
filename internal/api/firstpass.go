// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/investigate"
)

// The AI first pass (assistant.first_pass, off by default): the model
// looks at each new finding of enough urgency, as Investigate with AI
// does but with one round of searches, and its verdict is noted on the
// finding for the analyst. It never changes the finding's status, owner,
// severity or anything else people triage, and it stops for the day at
// assistant.first_pass_daily findings.

var (
	// firstPassEvery is how often the first pass looks for new findings.
	firstPassEvery = time.Minute
	// firstPassBackoff is how long it waits after a model error, so a
	// model that is down does not use up the day's findings on errors.
	firstPassBackoff = 15 * time.Minute
)

// firstPassBatch is the most findings looked at in one go.
const firstPassBatch = 5

// RunAIFirstPass runs the AI first pass until ctx ends. A tenant's
// server runs none: the AI settings are the provider's.
func (s *Server) RunAIFirstPass(ctx context.Context) {
	if s.Findings == nil || s.TenantID != "" {
		return
	}
	t := time.NewTimer(firstPassEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		wait := firstPassEvery
		if m := s.model(); m != nil {
			if _, err := s.firstPass(ctx, time.Now(), m); err != nil && ctx.Err() == nil {
				s.Log.Warn("the AI first pass could not look at a finding; trying again later", "err", err, "retry_in", firstPassBackoff.String())
				wait = firstPassBackoff
			}
		}
		t.Reset(wait)
	}
}

// firstPass looks at up to firstPassBatch new findings with model m. It
// returns how many it looked at, and the model's error that stopped it.
func (s *Server) firstPass(ctx context.Context, now time.Time, m investigate.Model) (int, error) {
	c := s.conf()
	if !c.Assistant.FirstPass || s.Engine == nil {
		return 0, nil
	}
	day := now.UTC().Truncate(24 * time.Hour)
	_, done, err := s.Findings.Search(ctx, findings.Filter{AISince: day, Limit: 1})
	if err != nil {
		return 0, err
	}
	left := min(c.FirstPassDaily()-done, firstPassBatch)
	if left <= 0 {
		return 0, nil
	}
	least := findings.UrgencyRank(c.FirstPassUrgency())
	var urgencies []string
	for _, u := range findings.Severities {
		if findings.UrgencyRank(u) >= least {
			urgencies = append(urgencies, u)
		}
	}
	// Only findings raised in the last day, so turning it on does not
	// send the whole backlog.
	list, _, err := s.Findings.Search(ctx, findings.Filter{Status: []string{findings.StatusNew}, Urgency: urgencies,
		AI: []string{findings.AINone}, Since: now.Add(-24 * time.Hour), Limit: 100})
	if err != nil {
		return 0, err
	}
	list = slices.DeleteFunc(list, func(f *findings.Finding) bool { return f.Sample != "" || f.AI != nil })
	slices.SortStableFunc(list, func(a, b *findings.Finding) int {
		if d := findings.UrgencyRank(b.EffectiveUrgency()) - findings.UrgencyRank(a.EffectiveUrgency()); d != 0 {
			return d
		}
		return a.Created.Compare(b.Created)
	})
	var sentTo string
	if ac, ok := m.(*assistant.Client); ok {
		sentTo = config.Origin(ac.URL)
	}
	n := 0
	for _, f := range list {
		if n == left {
			break
		}
		inv := &investigate.Investigator{Model: m, Search: s.Engine, Findings: s.Findings, Intel: s.Intel,
			Mask: c.Assistant.MaskFields, Rounds: 1}
		rctx, cancel := context.WithTimeout(ctx, c.AssistantInvestigateTimeout())
		res, err := inv.Run(rctx, f, nil)
		cancel()
		if ctx.Err() != nil {
			return n, nil
		}
		note := &findings.AITriage{Model: m.Name(), At: now.UTC()}
		var stopped *investigate.StoppedError
		switch {
		case errors.As(err, &stopped):
			note.Error = "Stopped: the model searched for a masked value."
			s.Log.Warn("AI first pass stopped: the model searched for a masked value", "audit", true, "by", "ai-first-pass",
				"finding", f.ID, "model", m.Name(), "sent_to", sentTo)
		case err != nil:
			note.Error = firstPassError(err)
		default:
			note.Verdict, note.Confidence, note.Summary = res.Verdict, res.Confidence, res.Summary
			note.Injection, note.Caution = res.Injection, res.Caution
		}
		if _, merr := s.Findings.Modify(ctx, f.ID, func(x *findings.Finding) (bool, error) {
			if x.AI != nil {
				return false, nil
			}
			x.AI = note
			return true, nil
		}); merr != nil && !errors.Is(merr, findings.ErrNotFound) {
			return n, merr
		}
		n++
		if err != nil && stopped == nil {
			s.Log.Warn("AI first pass failed", "audit", true, "by", "ai-first-pass", "finding", f.ID, "model", m.Name(), "sent_to", sentTo, "err", err)
			return n, err
		}
		if res != nil {
			s.Log.Info("finding looked at by the AI first pass", "audit", true, "by", "ai-first-pass", "finding", f.ID, "model", res.Model,
				"sent_to", sentTo, "chars_sent", res.Sent, "verdict", res.Verdict, "injection", res.Injection)
		}
	}
	return n, nil
}

// firstPassError is the note kept on a finding the first pass failed on.
func firstPassError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout exceeded"):
		return "The AI model did not answer in time."
	}
	return cmp.Or(cut(err.Error(), 300), "The AI model failed.")
}
