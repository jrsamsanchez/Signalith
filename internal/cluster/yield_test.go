package cluster

import (
	"testing"
	"time"
)

func TestYieldTarget(t *testing.T) {
	timing := Timing{YieldSettle: time.Minute, YieldEvery: 10 * time.Minute}
	now := 10 * time.Minute
	zero := int64(0)
	self := Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "1.5.0", LevelMax: 8, MaxRev: 40}
	cand := func(name, version string, mod ...func(*yieldCandidate)) yieldCandidate {
		c := yieldCandidate{hb: Heartbeat{NodeID: "n_" + name, Name: name, Version: version, State: StateReady, LeaderEligible: true,
			ClockOffsetMS: &zero, LevelMax: 8, MaxRev: 40}, readySince: now - 2*time.Minute}
		for _, m := range mod {
			m(&c)
		}
		return c
	}
	far := int64(45000)
	for _, tc := range []struct {
		name  string
		cands []yieldCandidate
		want  string
	}{
		{"newer ready server", []yieldCandidate{cand("siem-b", "1.6.0")}, "siem-b"},
		{"same version", []yieldCandidate{cand("siem-b", "1.5.0")}, ""},
		{"older version", []yieldCandidate{cand("siem-b", "1.4.0")}, ""},
		{"not ready long enough", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.readySince = now - 30*time.Second })}, ""},
		{"not ready", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.State = StateDraining })}, ""},
		{"gone", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.gone = true })}, ""},
		{"not eligible", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.LeaderEligible = false })}, ""},
		{"shared says not eligible", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.NotEligible = "importing" })}, ""},
		{"files differ", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.CannotTakeOver = "its retention policies differ" })}, ""},
		{"clock unknown", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.ClockOffsetMS = nil })}, ""},
		{"clock off", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.ClockOffsetMS = &far })}, ""},
		{"reads lower level", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.LevelMax = 7 })}, ""},
		{"behind on shared settings", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.MaxRev = 39 })}, ""},
		{"revision unknown counts as caught up", []yieldCandidate{cand("siem-b", "1.6.0", func(c *yieldCandidate) { c.hb.MaxRev = 0 })}, "siem-b"},
		{"dev is never newer", []yieldCandidate{cand("siem-b", "dev")}, ""},
		{"level decides first", []yieldCandidate{cand("siem-b", "1.4.0", func(c *yieldCandidate) { c.hb.LevelMax = 9 })}, "siem-b"},
		{"self is skipped", []yieldCandidate{cand("a", "1.6.0")}, ""},
		{"newest wins", []yieldCandidate{cand("siem-b", "1.6.0"), cand("siem-c", "1.7.0"), cand("siem-d", "1.6.1")}, "siem-c"},
		{"ties by name", []yieldCandidate{cand("siem-d", "1.6.0"), cand("siem-b", "1.6.0"), cand("siem-c", "1.6.0")}, "siem-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := yieldTarget(self, tc.cands, now, timing)
			if ok != (tc.want != "") || got.Name != tc.want {
				t.Errorf("target %q (%v), want %q", got.Name, ok, tc.want)
			}
		})
	}
}
