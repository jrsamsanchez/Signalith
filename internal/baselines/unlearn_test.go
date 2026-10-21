// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// One value one user learned can be forgotten without resetting the
// check for everyone: the check treats it as new again (UEBA-04).
func TestUnlearnOneValue(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1})
	brazil := true
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,src" {
			return nil
		}
		rows := []search.Row{row("user", "alice", "src", "5.5.1.2", "count", 1.0), row("user", "bob", "src", "5.5.1.3", "count", 1.0)}
		if brazil {
			rows = append(rows, row("user", "alice", "src", "177.0.3.4", "count", 1.0), row("user", "bob", "src", "177.0.3.5", "count", 1.0))
		}
		return rows
	}
	r.run()
	ctx := context.Background()
	set, ver, err := r.store.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// One asked before the check started went with a reset; one names
	// a user it never learned.
	st, _, _, _ := r.store.State(ctx)
	started := st.Checks[NewCountry].Started
	set.Checks = map[string]CheckSettings{NewCountry: {Unlearn: []ForgetValue{
		{Entity: "alice", Value: "US", At: started.Add(-time.Hour)},
		{Entity: "Alice", Value: "br", At: r.now.Add(time.Minute), By: "admin"},
		{Entity: "zed", Value: "BR", At: r.now.Add(2 * time.Minute)},
	}}}
	if _, err := r.store.SaveSettings(ctx, set, ver); err != nil {
		t.Fatal(err)
	}
	brazil = false
	// It waits for the hour it was asked in to be learned.
	r.now = r.now.Add(time.Hour)
	r.run()
	if p := r.profile(NewCountry, "alice"); !p.has("BR") {
		t.Errorf("forgotten before its hour was learned: %+v", p.Values)
	}
	r.now = r.now.Add(time.Hour)
	r.run()
	if p := r.profile(NewCountry, "alice"); p.has("BR") || !p.has("US") {
		t.Errorf("alice %+v", p.Values)
	}
	if p := r.profile(NewCountry, "bob"); !p.has("BR") {
		t.Errorf("bob forgot too: %+v", p.Values)
	}
	st, _, _, _ = r.store.State(ctx)
	if got := st.Checks[NewCountry].Unlearned; !got.Equal(r.now.Add(-2 * time.Hour).Add(2 * time.Minute)) {
		t.Errorf("unlearned through %v", got)
	}
	// Brazil is news for alice again, not for bob.
	brazil = true
	r.now = r.now.Add(2 * 24 * time.Hour)
	r.run()
	var who []string
	for _, ev := range r.risk.of(NewCountry) {
		if ev.Fields["baseline_value"] == "BR" {
			who = append(who, ev.Object)
		}
	}
	if len(who) != 1 || who[0] != "alice" {
		t.Errorf("BR raised for %v", who)
	}
}

func TestProfileUnlearn(t *testing.T) {
	vol := &Profile{Check: DataVolume, Mean: 5, Var: 2, Span: 100, HourN: make([]int64, 24)}
	if !vol.unlearn("") || vol.Span != 0 || vol.HourN != nil || vol.unlearn("") {
		t.Errorf("volume %+v", vol)
	}
	hr := &Profile{Check: UnusualHour, Hours: 10, ByHour: make([]int64, 24)}
	hr.ByHour[3], hr.ByHour[9] = 2, 8
	if !hr.unlearn("03:00 UTC") || hr.ByHour[3] != 0 || hr.Hours != 8 || hr.unlearn("03") || hr.unlearn("25") {
		t.Errorf("hour %+v", hr)
	}
	for _, c := range []struct {
		check, entity, value string
		ok                   bool
	}{
		{NewCountry, "alice", "BR", true},
		{NewCountry, "alice", "", false},
		{NewCountry, " - ", "BR", false},
		{UnusualHour, "alice", "3 o'clock", false},
		{UnusualHour, "alice", "03:00 UTC", true},
		{DataVolume, "db-01", "", true},
		{DataVolume, "db-01", "5 GB", false},
		{RareProcess, "db-01", strings.Repeat("x", maxValueLen+1), false},
	} {
		if err := ForgetProblem(c.check, c.entity, c.value); (err == nil) != c.ok {
			t.Errorf("%s %q %q: %v", c.check, c.entity, c.value, err)
		}
	}
}

// A user with no sign-in from the internet on record, or none for a
// month, adds half the check's risk when one comes: how new and unused
// accounts are taken over (UEBA-05).
func TestNewAndReturningUsers(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 2})
	r.e.history = 40 * 24 * time.Hour
	first := r.now.Add(-40 * 24 * time.Hour).Truncate(time.Hour)
	var at time.Time
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,src" {
			return nil
		}
		rows := []search.Row{row("user", "alice", "src", "5.5.1.2", "count", 1.0)}
		if start.Equal(first) {
			rows = append(rows, row("user", "dave", "src", "5.5.1.9", "count", 1.0))
		}
		// Erin is new while the check itself still learns.
		if start.Equal(r.now.Add(-24 * time.Hour).Truncate(time.Hour)) {
			rows = append(rows, row("user", "erin", "src", "5.5.1.8", "count", 1.0))
		}
		if start.Equal(at) {
			rows = append(rows, row("user", "carol", "src", "177.0.3.4", "count", 1.0), row("user", "dave", "src", "5.5.1.9", "count", 1.0))
		}
		return rows
	}
	r.run()
	r.now = r.now.Add(24 * time.Hour)
	r.run()
	if n := len(r.risk.events); n != 0 {
		t.Fatalf("raised %d while learning", n)
	}
	r.now = r.now.Add(2 * 24 * time.Hour)
	at = r.now.Add(-time.Hour - settle).Truncate(time.Hour)
	r.run()
	got := map[string]string{}
	for _, ev := range r.risk.of(NewCountry) {
		got[ev.Object] = ev.Fields["baseline_reason"].(string) + " " + ev.Message
		if ev.Score != 20 || ev.BaseScore != 20 {
			t.Errorf("%s scored %v (base %d)", ev.Object, ev.Score, ev.BaseScore)
		}
	}
	if len(got) != 2 || !strings.HasPrefix(got["carol"], "new First sign-in from the internet on record for carol in the last 42 days, from 177.0.3.4 (Brazil (BR))") ||
		!strings.HasPrefix(got["dave"], "returning dave signed in from the internet after 42 days without a sign-in") {
		t.Errorf("events %v", got)
	}
}

// Sign-ins from the internet that start arriving after the check began
// (an identity provider added later) make every user new: they add no
// risk until they too were learned for the learning period.
func TestArrivalsWaitForData(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 2})
	var from time.Time
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,src" || from.IsZero() || start.Before(from) {
			return nil
		}
		var rows []search.Row
		for i := range 20 {
			rows = append(rows, row("user", fmt.Sprintf("user%02d", i), "src", "5.5.1.2", "count", 1.0))
		}
		if start.After(from.Add(3 * 24 * time.Hour)) {
			rows = append(rows, row("user", "carol", "src", "177.0.3.4", "count", 1.0))
		}
		return rows
	}
	r.run()
	r.now = r.now.Add(5 * 24 * time.Hour)
	from = r.now.Add(-time.Hour - settle).Truncate(time.Hour)
	r.run()
	if n := len(r.risk.of(NewCountry)); n != 0 {
		t.Fatalf("the first internet sign-ins raised %d", n)
	}
	r.now = r.now.Add(4 * 24 * time.Hour)
	r.run()
	var who []string
	for _, ev := range r.risk.of(NewCountry) {
		who = append(who, ev.Object)
	}
	if len(who) != 1 || who[0] != "carol" {
		t.Errorf("raised for %v", who)
	}
}
