// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package findings

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestFirstResponseIsAPersons: a person's status or owner change is the
// first response; a playbook's, a note or a severity change is not.
func TestFirstResponseIsAPersons(t *testing.T) {
	now := time.Now().UTC()
	f := &Finding{Status: StatusNew, Severity: "high"}
	owner, sev := "bob", "low"
	f.Apply(Update{Owner: &owner}, "playbook Assign", now)
	f.Apply(Update{Severity: &sev, Comment: "looked"}, "ana", now)
	if f.RespondedAt != nil {
		t.Fatalf("responded at %v", f.RespondedAt)
	}
	st := StatusInProgress
	f.Apply(Update{Status: &st}, "ana", now.Add(time.Minute))
	if f.RespondedAt == nil || !f.RespondedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("responded at %v", f.RespondedAt)
	}
	st = StatusPending
	f.Apply(Update{Status: &st}, "bob", now.Add(time.Hour))
	if !f.RespondedAt.Equal(now.Add(time.Minute)) {
		t.Errorf("a later change moved the first response to %v", f.RespondedAt)
	}
}

func TestDueOf(t *testing.T) {
	sla := DefaultSLA()
	now := time.Now().UTC()
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	for _, c := range []struct {
		name                 string
		f                    Finding
		respondLate, resLate bool
	}{
		{"new and on time", Finding{Urgency: "critical", Status: StatusNew, Created: now.Add(-10 * time.Minute)}, false, false},
		{"new and late", Finding{Urgency: "critical", Status: StatusNew, Created: now.Add(-20 * time.Minute)}, true, false},
		{"picked up late, resolve late", Finding{Urgency: "critical", Status: StatusInProgress, Created: now.Add(-5 * time.Hour), RespondedAt: at(-4*time.Hour - 30*time.Minute)}, true, true},
		{"picked up in time", Finding{Urgency: "critical", Status: StatusInProgress, Created: now.Add(-time.Hour), RespondedAt: at(-55 * time.Minute)}, false, false},
		{"resolved in time", Finding{Urgency: "high", Status: StatusResolved, Created: now.Add(-48 * time.Hour), RespondedAt: at(-47 * time.Hour),
			History: []Change{{Field: "status", To: StatusResolved, Time: now.Add(-30 * time.Hour)}}}, false, false},
		{"resolved late", Finding{Urgency: "high", Status: StatusClosed, Created: now.Add(-48 * time.Hour), RespondedAt: at(-47 * time.Hour),
			History: []Change{{Field: "status", To: StatusClosed, Time: now.Add(-20 * time.Hour)}}}, false, true},
		{"closed and never picked up", Finding{Urgency: "low", Status: StatusClosed, Created: now.Add(-48 * time.Hour), Updated: now.Add(-47 * time.Hour)}, false, false},
	} {
		d := sla.DueOf(&c.f, now)
		if d == nil || d.RespondLate != c.respondLate || d.ResolveLate != c.resLate || d.RespondBy == nil || d.ResolveBy == nil {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	if d := sla.DueOf(&Finding{Urgency: "informational", Status: StatusNew, Created: now}, now); d != nil {
		t.Errorf("informational has due times %+v", d)
	}
}

// TestDueFilter: the due filter keeps open findings late now, or due
// within the time asked, by first response or by resolution.
func TestDueFilter(t *testing.T) {
	m := NewMemory()
	now := time.Now().UTC()
	responded := now.Add(-time.Hour)
	for _, f := range []*Finding{
		{ID: "late-pickup", Urgency: "critical", Status: StatusNew, Created: now.Add(-20 * time.Minute)},
		{ID: "soon-pickup", Urgency: "critical", Status: StatusNew, Created: now.Add(-10 * time.Minute)},
		{ID: "picked-up", Urgency: "critical", Status: StatusInProgress, Created: now.Add(-time.Hour), RespondedAt: &responded},
		{ID: "late-resolve", Urgency: "critical", Status: StatusInProgress, Created: now.Add(-5 * time.Hour), RespondedAt: &responded},
		{ID: "closed-late", Urgency: "critical", Status: StatusClosed, Created: now.Add(-5 * time.Hour)},
		{ID: "info", Urgency: "informational", Status: StatusNew, Created: now.Add(-30 * 24 * time.Hour)},
	} {
		if err := m.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(within time.Duration) []string {
		l, _, _ := m.Search(context.Background(), Filter{Due: &DueWithin{SLA: DefaultSLA(), Within: within, Now: now}})
		var out []string
		for _, f := range l {
			out = append(out, f.ID)
		}
		slices.Sort(out)
		return out
	}
	if got := ids(0); !slices.Equal(got, []string{"late-pickup", "late-resolve"}) {
		t.Errorf("overdue: %v", got)
	}
	if got := ids(10 * time.Minute); !slices.Equal(got, []string{"late-pickup", "late-resolve", "soon-pickup"}) {
		t.Errorf("due within 10m: %v", got)
	}
}
