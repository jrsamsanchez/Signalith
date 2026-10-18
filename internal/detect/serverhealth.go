package detect

import (
	"slices"
	"time"
)

// healthWindow is how far back a run counts towards a server's detection
// health: a rule last run longer ago (its server stopped, or the rule
// moved) says nothing about how that server keeps up now.
const healthWindow = 24 * time.Hour

// ServerHealth is how one server keeps up with the detections it runs,
// from the run state of each rule it ran last (DetState.Node), for the
// Servers page. Times are in milliseconds.
type ServerHealth struct {
	// Rules is how many rules this server ran last within healthWindow.
	Rules int `json:"rules"`
	// DurationP50 and DurationP95 are over each rule's last run time.
	DurationP50 int64 `json:"duration_p50_ms"`
	DurationP95 int64 `json:"duration_p95_ms"`
	// LagP50 and LagP95 are over how long after its slot ended each
	// rule's last scheduled run started.
	LagP50 int64 `json:"lag_p50_ms"`
	LagP95 int64 `json:"lag_p95_ms"`
	// LateHour is how many of its rules started a run more than one
	// schedule interval late in the last hour.
	LateHour int `json:"late_hour,omitempty"`
	// Skipped is how many slots of its rules were skipped in the last
	// 24 hours, as older than detections.catch_up, and SkippedHour how
	// many of them in the last hour.
	Skipped     int `json:"skipped,omitempty"`
	SkippedHour int `json:"skipped_hour,omitempty"`
	// TimedOut is how many of its rules' last runs were stopped for
	// taking too long.
	TimedOut int `json:"timed_out,omitempty"`
	// Behind says its detections are falling behind, and Why says how.
	Behind bool   `json:"behind,omitempty"`
	Why    string `json:"why,omitempty"`
}

// behindLate is the share of a server's rules that must have run late in
// the last hour, and behindLateMin the fewest, before it counts as
// falling behind: one rule running late now and then is a slow query, not
// a server that cannot keep up.
const (
	behindLate    = 0.05
	behindLateMin = 3
)

// HealthByServer works out, per server node ID, how it keeps up with the
// detections it runs, from every rule's run state as StatusCtx returns
// it. now is the cluster's clock.
func HealthByServer(states map[string]RunState, now time.Time) map[string]ServerHealth {
	type acc struct {
		h        ServerHealth
		dur, lag []int64
	}
	by := map[string]*acc{}
	for _, st := range states {
		if st.Node == "" || st.LastRun.IsZero() || now.Sub(st.LastRun) > healthWindow {
			continue
		}
		a := by[st.Node]
		if a == nil {
			a = &acc{}
			by[st.Node] = a
		}
		a.h.Rules++
		a.dur = append(a.dur, max(st.LastDuration, 0))
		a.lag = append(a.lag, max(st.Lag, 0))
		if !st.LastLate.IsZero() && now.Sub(st.LastLate) < time.Hour {
			a.h.LateHour++
		}
		if sk := st.Skipped; sk != nil && sk.Count > 0 && now.Sub(sk.At) < healthWindow {
			a.h.Skipped += sk.Count
			if now.Sub(sk.At) < time.Hour {
				a.h.SkippedHour += sk.Count
			}
		}
		if st.TimedOut {
			a.h.TimedOut++
		}
	}
	out := make(map[string]ServerHealth, len(by))
	for node, a := range by {
		h := a.h
		h.DurationP50, h.DurationP95 = percentile(a.dur, 50), percentile(a.dur, 95)
		h.LagP50, h.LagP95 = percentile(a.lag, 50), percentile(a.lag, 95)
		switch {
		case h.SkippedHour > 0:
			h.Behind, h.Why = true, "slots were skipped in the last hour because they were older than the catch-up limit"
		case h.LateHour >= max(behindLateMin, int(float64(h.Rules)*behindLate+0.999)):
			h.Behind, h.Why = true, "many rules started late in the last hour because every detection worker was busy"
		}
		out[node] = h
	}
	return out
}

// percentile returns the p-th percentile of v (nearest rank), 0 for none.
// It sorts v.
func percentile(v []int64, p int) int64 {
	if len(v) == 0 {
		return 0
	}
	slices.Sort(v)
	i := (len(v)*p + 99) / 100
	return v[min(max(i-1, 0), len(v)-1)]
}
