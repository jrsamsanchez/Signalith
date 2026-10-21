// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// Hosts that send in bulk at the same hour every night or every week
// are judged against that hour of the day, so their backups and syncs
// never add risk; a host that sends a lot at an hour it never does, or
// far more than it ever does, still does. Sixty days: thirty of history,
// thirty live.
func TestDataVolumeByHourOfDay(t *testing.T) {
	r := newRig(t, only(DataVolume, Settings{LearningDays: 14, IPDatabase: "off"}))
	r.e.history = 30 * 24 * time.Hour
	live := r.now.Truncate(time.Hour)
	steadySpike := live.Add(10*24*time.Hour + 5*time.Hour)
	quietSpike := live.Add(20*24*time.Hour + 15*time.Hour).Truncate(24 * time.Hour).Add(3 * time.Hour)
	r.runner.rows = func(by string, start time.Time) []search.Row {
		if by != "src" {
			return nil
		}
		var rows []search.Row
		add := func(src string, bytes float64) {
			if bytes > 0 {
				rows = append(rows, row("src", src, "bytes", bytes))
			}
		}
		h := start.Hour()
		// A backup server: 1 GB at 02:00, nothing else.
		if h == 2 {
			add("10.0.0.1", 1e9)
		}
		// The same with a trickle all day.
		add("10.0.0.2", map[bool]float64{true: 1e9, false: 1e6}[h == 2])
		// An office PC that syncs 1 GB every Friday afternoon.
		office := 0.0
		if h >= 9 && h < 17 && start.Weekday() != time.Saturday && start.Weekday() != time.Sunday {
			office = 30e6
		}
		if start.Weekday() == time.Friday && h == 14 {
			office = 1e9
		}
		add("10.0.0.3", office)
		// A steady server with one 3 GB hour.
		add("10.0.0.4", map[bool]float64{true: 3e9, false: 200e6}[start.Equal(steadySpike)])
		// A quiet host that sends 2 GB at 03:00, once.
		add("10.0.0.5", map[bool]float64{true: 2e9, false: 5e6}[start.Equal(quietSpike)])
		return rows
	}
	r.run()
	for range 30 {
		r.now = r.now.Add(24 * time.Hour)
		r.run()
	}
	by := map[string]int{}
	for _, ev := range r.risk.of(DataVolume) {
		by[ev.Object]++
	}
	for host, want := range map[string]int{"10.0.0.1": 0, "10.0.0.2": 0, "10.0.0.3": 0, "10.0.0.4": 1, "10.0.0.5": 1} {
		if by[host] != want {
			t.Errorf("%s raised %d times, want %d", host, by[host], want)
		}
	}
	for _, ev := range r.risk.of(DataVolume) {
		if ev.Object == "10.0.0.5" && !strings.Contains(ev.Message, "between 03:00 and 04:00 UTC") {
			t.Errorf("message %q", ev.Message)
		}
	}
}

// A profile from before the hours of the day were kept learns them
// before it can raise again.
func TestVolumeHoursLearnFirst(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p := &Profile{Check: DataVolume, Mean: 20e6, Var: 1e12, Span: 500, Through: at}
	if u := p.usual(at); u.HourN != 0 || u.HourLimit != 0 {
		t.Fatalf("usual = %+v", u)
	}
	for d := range 8 {
		h := at.Add(time.Duration(d) * 24 * time.Hour)
		p.addVolume(20e6, h)
		p.Through = h.Add(time.Hour)
	}
	u := p.usual(at.Add(8 * 24 * time.Hour))
	if u.HourN < minHourDays || u.HourMean < 19e6 || u.HourMean > 21e6 {
		t.Errorf("usual = %+v", u)
	}
	// The other hours were empty days.
	if u := p.usual(at.Add(8*24*time.Hour + 5*time.Hour)); u.HourN < minHourDays || u.HourMean != 0 {
		t.Errorf("usual at 05:00 = %+v", u)
	}
}
