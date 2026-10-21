// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package findings

import (
	"strings"
	"time"
)

// SLA is how soon findings of each urgency should be picked up (first
// response: a person changes their status or owner) and resolved, timed
// from when they were raised. An urgency without a target has no due
// time.
type SLA struct {
	Respond map[string]time.Duration `json:"respond"`
	Resolve map[string]time.Duration `json:"resolve"`
}

// DefaultSLA is the targets a server starts with.
func DefaultSLA() SLA {
	return SLA{
		Respond: map[string]time.Duration{"critical": 15 * time.Minute, "high": time.Hour, "medium": 4 * time.Hour, "low": 24 * time.Hour},
		Resolve: map[string]time.Duration{"critical": 4 * time.Hour, "high": 24 * time.Hour, "medium": 72 * time.Hour, "low": 7 * 24 * time.Hour},
	}
}

// Off reports whether no urgency has a target.
func (s SLA) Off() bool { return len(s.Respond) == 0 && len(s.Resolve) == 0 }

// Due is a finding's due times and whether it missed them.
type Due struct {
	RespondBy *time.Time `json:"respond_by,omitempty"`
	ResolveBy *time.Time `json:"resolve_by,omitempty"`
	// RespondLate and ResolveLate are set once a due time passed before
	// the finding was picked up or resolved.
	RespondLate bool `json:"respond_late,omitempty"`
	ResolveLate bool `json:"resolve_late,omitempty"`
}

// DueOf is f's due times at now, or nil when its urgency has no target.
func (s SLA) DueOf(f *Finding, now time.Time) *Due {
	u := f.EffectiveUrgency()
	rt, st := s.Respond[u], s.Resolve[u]
	if rt <= 0 && st <= 0 {
		return nil
	}
	d := &Due{}
	open := IsOpen(f.Status)
	if rt > 0 {
		by := f.Created.Add(rt).UTC()
		d.RespondBy = &by
		if f.RespondedAt != nil {
			d.RespondLate = f.RespondedAt.After(by)
		} else {
			d.RespondLate = open && now.After(by)
		}
	}
	if st > 0 {
		by := f.Created.Add(st).UTC()
		d.ResolveBy = &by
		if open {
			d.ResolveLate = now.After(by)
		} else {
			d.ResolveLate = resolvedAt(f).After(by)
		}
	}
	return d
}

// resolvedAt is when f was last resolved or closed, or its last change
// for a finding whose history does not say.
func resolvedAt(f *Finding) time.Time {
	for i := len(f.History) - 1; i >= 0; i-- {
		if h := f.History[i]; h.Field == "status" && !IsOpen(h.To) {
			return h.Time
		}
	}
	return f.Updated
}

// dueBy reports whether open finding f has a due time at or before at
// that it has not met: a first response it still owes, or resolving it.
func (s SLA) dueBy(f *Finding, at time.Time) bool {
	if !IsOpen(f.Status) {
		return false
	}
	u := f.EffectiveUrgency()
	if rt := s.Respond[u]; rt > 0 && f.RespondedAt == nil && !f.Created.Add(rt).After(at) {
		return true
	}
	st := s.Resolve[u]
	return st > 0 && !f.Created.Add(st).After(at)
}

// automationPrefix starts the author of changes that automation makes
// (playbooks.Author); they are not a person's first response.
const automationPrefix = "playbook "

// IsAutomation reports whether author is automation, not a person.
func IsAutomation(author string) bool { return strings.HasPrefix(author, automationPrefix) }

// DueWithin keeps open findings with a due time they have not met at or
// before now plus Within: Within 0 is overdue now.
type DueWithin struct {
	SLA    SLA
	Within time.Duration
	Now    time.Time
}
