// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

func everyModel(string) bool { return true }

// A data model allowed by ByMonth is stored in its month's index, from
// before the first check; one ByMonth refuses, a month another server
// already stores by day, a month whose index is full and a month the
// check does not cover are stored by day.
func TestRolloverStoresQuietModelsByMonth(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	c := &catIndices{}
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return at },
		ByMonth: func(model string) bool { return model != "Endpoint" }}
	if got := r.IndexFor("sig", "Network", at); got != "sig-network-2026.11" {
		t.Errorf("before the first check: %s", got)
	}
	if got := r.IndexFor("sig", "Endpoint", at); got != "sig-endpoint-2026.11.15" {
		t.Errorf("a model kept by day: %s", got)
	}
	c.rows = []map[string]any{
		row("sig-network-2026.11", 1, 3),
		row("sig-web-2026.11", 2, 81),         // 40.5 GB a shard: full
		row("sig-dns-2026.11.14", 1, 1),       // stored by day this month
		row("sig-auth-2026.11", 1, 1),         // stored by month,
		row("sig-auth-2026.11.15", 1, 1),      // but another server went daily
		row("sig-file-2026.10", 1, 50),        // last month: not checked
		row("sig-registry-2026.11", 1, 0),     // replaced below
		row("other-network-2026.11.15", 1, 1), // another prefix
	}
	c.rows[6]["pri.store.size"] = nil // a red index: size unknown, not full
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for model, want := range map[string]string{
		"Network":  "sig-network-2026.11",
		"Web":      "sig-web-2026.11.15",
		"DNS":      "sig-dns-2026.11.15",
		"Auth":     "sig-auth-2026.11.15",
		"Registry": "sig-registry-2026.11",
		"New":      "sig-new-2026.11",
		"Endpoint": "sig-endpoint-2026.11.15",
	} {
		if got := r.IndexFor("sig", model, at); got != want {
			t.Errorf("%s: writes to %s, want %s", model, got, want)
		}
	}
	// Last month's and older events go to their day.
	if got := r.IndexFor("sig", "Network", at.AddDate(0, -1, 0)); got != "sig-network-2026.10.15" {
		t.Errorf("last month: %s", got)
	}
	// Each check lists the days, and the months' indices themselves.
	if len(c.paths) != 1 || !strings.Contains(c.paths[0], "sig-%2A-2026.11.14%2A,sig-%2A-2026.11.15%2A,sig-%2A-2026.11.16%2A,sig-%2A-2026.11?") {
		t.Errorf("asked %v", c.paths)
	}

	// A month this server closed for its field names stays closed until
	// the daily indices that follow show it to every server.
	if !r.CloseMonth("sig-network-2026.11") || r.CloseMonth("sig-network-2026.11") || r.CloseMonth("sig-network-2026.11.15") {
		t.Error("CloseMonth: want true once, then false, and false for a daily index")
	}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.IndexFor("sig", "Network", at); got != "sig-network-2026.11.15" {
		t.Errorf("after CloseMonth and a check: %s", got)
	}

	// Without ByMonth, and on a nil Rollover, every model is stored by day.
	r.ByMonth = nil
	if got := r.IndexFor("sig", "New", at); got != "sig-new-2026.11.15" {
		t.Errorf("no ByMonth: %s", got)
	}
	var none *Rollover
	if got := none.IndexFor("sig", "New", at); got != "sig-new-2026.11.15" || none.CloseMonth("sig-new-2026.11") {
		t.Errorf("nil rollover: %s", got)
	}
}

// At midnight on the 1st, last month is still checked (yesterday's) and
// a new month starts by month whatever the last one did.
func TestRolloverNewMonthStartsByMonth(t *testing.T) {
	at := time.Date(2026, 12, 1, 0, 5, 0, 0, time.UTC)
	c := &catIndices{rows: []map[string]any{
		row("sig-network-2026.11", 1, 41),   // full last month,
		row("sig-network-2026.11.30", 1, 2), // so it went daily
	}}
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return at }, ByMonth: everyModel}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.IndexFor("sig", "Network", at); got != "sig-network-2026.12" {
		t.Errorf("the 1st: %s", got)
	}
	if got := r.IndexFor("sig", "Network", at.Add(-time.Hour)); got != "sig-network-2026.11.30" {
		t.Errorf("late events of the 30th: %s", got)
	}
}

// A monthly index whose mapping reaches MonthFieldsClose takes no more
// events: the rest of the month goes to daily indices, which start with
// room for new names: a day's new names fit as they would if every day
// had its own index.
func TestMonthWithManyFieldNamesGoesDaily(t *testing.T) {
	m := &mappedIndices{}
	r := &Rollover{Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return now }, ByMonth: everyModel}
	p := &Pipeline{Store: m, Prefix: "sig", Now: func() time.Time { return now }, FieldCount: m.count, Rollover: r}
	p.counter.ttl = -1
	newNames(t, p, "a", 24, 50)
	month := datamodel.MonthIndexName("sig", "Other", datamodel.MonthOf(now))
	day := datamodel.IndexName("sig", "Other", dayOf(now))
	m.mu.Lock()
	inMonth, inDay := len(m.paths[month]), len(m.paths[day])
	m.mu.Unlock()
	if inMonth < MonthFieldsClose || inMonth > MonthFieldsClose+50 {
		t.Errorf("the monthly index has %d fields, want about %d", inMonth, MonthFieldsClose)
	}
	if inDay == 0 {
		t.Errorf("no events went to %s", day)
	}
	if got := namesFrom(m, "a"); got != 24*50 {
		t.Errorf("%d of %d new names were kept", got, 24*50)
	}
	if m.refused > 0 {
		t.Errorf("OpenSearch refused %d events", m.refused)
	}
}
