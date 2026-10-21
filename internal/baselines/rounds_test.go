// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// One check whose search fails falls behind on its own: the others go
// on learning, and it catches up once its search works again.
func TestFailingCheckWaitsAlone(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	broken := true
	r.runner.fail = func(by string, _ time.Time) error {
		if broken && by == "dest,process_name" {
			return errors.New("mapping conflict on process_name")
		}
		return nil
	}
	r.runner.rows = func(by string, start time.Time) []search.Row {
		switch by {
		case "dest,process_name":
			return []search.Row{row("dest", "h1", "process_name", "a.exe")}
		case "user,command":
			return []search.Row{row("user", "alice", "command", "PutObject")}
		}
		return nil
	}
	ctx := context.Background()
	if _, err := r.e.Round(ctx); err != nil {
		t.Fatalf("round = %v", err)
	}
	r.run()
	st, _, _, _ := r.store.State(ctx)
	cs := st.Checks[RareProcess]
	if cs.Behind.IsZero() || !strings.Contains(cs.Error, "mapping conflict") || !strings.Contains(st.LastError, "mapping conflict") {
		t.Fatalf("rare process state %+v, last error %q", cs, st.LastError)
	}
	if !st.Through.After(cs.Behind) || st.Checks[NewChange].Error != "" || !st.Checks[NewChange].Behind.IsZero() {
		t.Errorf("the other checks waited: through %v, %+v", st.Through, st.Checks[NewChange])
	}
	if p := r.profile(NewChange, "alice"); p == nil || !p.Through.Equal(st.Through) {
		t.Errorf("new change did not learn every hour: %+v", p)
	}
	if p := r.profile(RareProcess, "h1"); p != nil {
		t.Errorf("rare process learned: %+v", p)
	}

	broken = false
	r.run()
	st, _, _, _ = r.store.State(ctx)
	cs = st.Checks[RareProcess]
	if !cs.Behind.IsZero() || cs.Error != "" || st.LastError != "" {
		t.Errorf("did not catch up: %+v %q", cs, st.LastError)
	}
	if p := r.profile(RareProcess, "h1"); p == nil || !p.Through.Equal(st.Through) {
		t.Errorf("rare process after catching up: %+v", p)
	}
}

// A check that cannot learn for over a week skips the older hours, and
// says so.
func TestFailingCheckSkipsAfterAWeek(t *testing.T) {
	r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
	live := r.now.Truncate(time.Hour)
	r.runner.fail = func(by string, start time.Time) error {
		if by == "src" && !start.Before(live) {
			return errors.New("search timed out")
		}
		return nil
	}
	r.run()
	r.now = r.now.Add(2 * time.Hour)
	r.run()
	st, _, _, _ := r.store.State(context.Background())
	if cs := st.Checks[DataVolume]; !cs.Behind.Equal(live) {
		t.Fatalf("not behind: %+v", cs)
	}
	r.now = r.now.Add(9 * 24 * time.Hour)
	r.run()
	st, _, _, _ = r.store.State(context.Background())
	cs := st.Checks[DataVolume]
	oldest := r.now.Add(-maxCatchUp).Truncate(time.Hour)
	if !cs.Skipped.Equal(oldest) || cs.Behind.Before(oldest) {
		t.Errorf("state %+v, oldest %v", cs, oldest)
	}
}

// A reset check learns the stored history again, without adding risk,
// so what a user did last month is not new to it afterwards.
func TestResetReplaysHistory(t *testing.T) {
	r := newRig(t, only(NewChange, Settings{LearningDays: 2, IPDatabase: "off"}))
	monthly := r.now.Truncate(time.Hour).Add(-24 * time.Hour)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,command" {
			return nil
		}
		rows := []search.Row{row("user", "alice", "command", "PutObject")}
		if start.Equal(monthly) {
			rows = append(rows, row("user", "alice", "command", "RotateKeys"))
		}
		return rows
	}
	r.run()
	ctx := context.Background()
	set, v, _ := r.store.Settings(ctx)
	r.now = r.now.Add(time.Minute)
	set.Checks[NewChange] = CheckSettings{ResetAt: r.now}
	if _, err := r.store.SaveSettings(ctx, set, v); err != nil {
		t.Fatal(err)
	}
	r.run()
	p := r.profile(NewChange, "alice")
	if p == nil || !p.has("RotateKeys") || !p.has("PutObject") {
		t.Fatalf("history not learned again: %+v", p)
	}
	if n := len(r.risk.of(NewChange)); n != 0 {
		t.Errorf("the replay raised %d", n)
	}
	st, _, _, _ := r.store.State(ctx)
	// LiveFrom stays once caught up, so the page does not show the check
	// learning again.
	if cs := st.Checks[NewChange]; !cs.Behind.IsZero() || !cs.Started.Equal(r.now) || !cs.LiveFrom.Equal(r.now) {
		t.Errorf("state %+v", cs)
	}
	// The next time is not new.
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,command" {
			return nil
		}
		return []search.Row{row("user", "alice", "command", "RotateKeys")}
	}
	r.now = r.now.Add(2 * time.Hour)
	r.run()
	if n := len(r.risk.of(NewChange)); n != 0 {
		t.Errorf("a known change raised %d", n)
	}
}

// A busy admin with hundreds of kinds of change does not make the ones
// seen longest ago new again.
func TestManyValuesStayKnown(t *testing.T) {
	r := newRig(t, only(NewChange, Settings{LearningDays: 1, IPDatabase: "off"}))
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "user,command" {
			return nil
		}
		// 300 kinds of change, 25 an hour, round and round.
		var rows []search.Row
		base := int(start.Unix()/3600) * 25
		for i := range 25 {
			rows = append(rows, row("user", "admin", "command", fmt.Sprintf("Action%03d", (base+i)%300)))
		}
		return rows
	}
	r.run()
	r.now = r.now.Add(24 * time.Hour)
	r.run()
	if n := len(r.risk.of(NewChange)); n != 0 {
		t.Errorf("known changes raised %d", n)
	}
}

// Searches read more rows than an analyst's search, and a search that
// still had more says after which user or host it stopped.
func TestTruncatedSearchSaysWhere(t *testing.T) {
	r := newRig(t, only(RareProcess, Settings{LearningDays: 1, IPDatabase: "off"}))
	r.runner.truncated = true
	r.runner.rows = func(by string, _ time.Time) []search.Row {
		if by != "dest,process_name" {
			return nil
		}
		return []search.Row{row("dest", "a-host", "process_name", "x.exe"), row("dest", "m-host", "process_name", "y.exe")}
	}
	r.run()
	if r.runner.maxRows != searchRows {
		t.Errorf("searches asked for %d rows", r.runner.maxRows)
	}
	st, _, _, _ := r.store.State(context.Background())
	if cs := st.Checks[RareProcess]; cs.Truncated.IsZero() || cs.TruncatedAfter != "m-host" {
		t.Errorf("state %+v", cs)
	}
}

// countingRunner counts the searches running at once.
type countingRunner struct {
	*fakeRunner
	now, peak atomic.Int32
}

func (c *countingRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	n := c.now.Add(1)
	defer c.now.Add(-1)
	for p := c.peak.Load(); n > p && !c.peak.CompareAndSwap(p, n); p = c.peak.Load() {
	}
	time.Sleep(time.Millisecond)
	return c.fakeRunner.Execute(ctx, q)
}

// Every engine in the process, one per tenant, shares searchSlots, as
// each search can hold searchRows rows.
func TestSearchesShareSlots(t *testing.T) {
	c := &countingRunner{fakeRunner: &fakeRunner{}}
	var rigs []*rig
	for range 4 {
		r := newRig(t, Settings{LearningDays: 1, IPDatabase: "off"})
		r.e.Search = c
		rigs = append(rigs, r)
	}
	var wg sync.WaitGroup
	for _, r := range rigs {
		wg.Go(func() {
			if _, err := r.e.Round(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p := c.peak.Load(); p > 2 || p == 0 {
		t.Errorf("%d searches at once", p)
	}
}
