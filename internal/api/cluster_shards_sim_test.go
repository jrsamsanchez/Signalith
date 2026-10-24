// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// shardSim is what simulateShards saw over the days it ran.
type shardSim struct {
	maxUsed, maxShards int
	// firstWarn is the first day the Servers page warned, firstNear the
	// first the cluster held ingest.ShardRoomWarn of its limit (the
	// template check's log warning), firstFull the first it held the limit
	// itself (OpenSearch refuses the next day's indices); -1 when never.
	firstWarn, firstNear, firstFull int
	warning                         string
}

// simulateShards runs one OpenSearch node with the default shard limit
// (1,000) for n days, with models written every day and kept keepDays
// (retention deletes a day's indices once they are older than that), and
// the indices a single server keeps besides: findings, cases, threat
// intel, the shared settings, the servers' runtime index and a monthly
// audit index. Each day's indices get the shards the index template gives
// them, with automatic shards (fitShards), and each day the Servers page's
// shard projection and warning are worked out as handleClusterOpenSearch
// does.
func simulateShards(t *testing.T, models []string, keepDays, n int) shardSim {
	t.Helper()
	ctx := context.Background()
	const prefix = "signalith"
	fake := ostest.New(t)
	fake.SetDataNodes(1)
	cl := store.New(store.Config{URL: fake.URL})
	// Midday, so no simulated day starts near midnight; relative to now.
	start := time.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	fixed := []string{prefix + "_findings", prefix + "_cases", prefix + "_intel", prefix + "_config", prefix + "_runtime"}
	shardsOf := map[string]int{} // index name -> its shard copies
	out := shardSim{firstWarn: -1, firstNear: -1, firstFull: -1}
	for d := range n {
		now := start.AddDate(0, 0, d)
		// Retention: today and the keepDays before it.
		var held []indexCopies
		used := 0
		add := func(name string, copies int) {
			held = append(held, indexCopies{Index: name, Copies: copies})
			used += copies
		}
		for _, name := range fixed {
			add(name, 1)
		}
		months := map[string]bool{}
		for back := 0; back <= min(d, 400); back++ {
			months[audit.IndexName(prefix, now.AddDate(0, 0, -back))] = true
		}
		for name := range months {
			add(name, 1)
		}
		for back := 1; back <= min(d, keepDays); back++ {
			day := now.AddDate(0, 0, -back).Format("2006.01.02")
			for _, m := range models {
				name := prefix + "-" + m + "-" + day
				add(name, shardsOf[name])
			}
		}
		// Today's indices take the template the server put with the
		// shards in use before them.
		fake.SetShardsUsed(used)
		auto := map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": store.AutoShards}
		if err := ingest.PutIndexTemplate(ctx, cl, prefix, auto, nil); err != nil {
			t.Fatal(err)
		}
		shards := templateShards(t, fake.Template(prefix))
		out.maxShards = max(out.maxShards, shards)
		today := now.Format("2006.01.02")
		for _, m := range models {
			name := prefix + "-" + m + "-" + today
			shardsOf[name] = shards // one node: no replica
			add(name, shards)
		}

		limit := 1000
		card := osCard{ShardsUsed: &used, ShardLimit: &limit}
		p := projectShards(prefix, held, used, limit, func(string) int { return keepDays }, now)
		card.ShardsPerDay, card.ShardsProjected, card.ShardsFullInDays, card.keepDays = &p.PerDay, &p.Projected, p.FullInDays, p.KeepDays
		out.maxUsed = max(out.maxUsed, used)
		if w := shardWarning(card); w != "" && out.firstWarn < 0 {
			out.firstWarn, out.warning = d, w
		}
		if ingest.NearShardLimit(used, limit) && out.firstNear < 0 {
			out.firstNear = d
		}
		if used >= limit && out.firstFull < 0 {
			out.firstFull = d
		}
	}
	return out
}

// templateShards reads number_of_shards from an index template as put:
// one when it is left out.
func templateShards(t *testing.T, raw json.RawMessage) int {
	t.Helper()
	var tpl struct {
		Template struct {
			Settings map[string]any `json:"settings"`
		} `json:"template"`
	}
	if err := json.Unmarshal(raw, &tpl); err != nil {
		t.Fatalf("template %s: %v", raw, err)
	}
	set := tpl.Template.Settings
	if ix, ok := set["index"].(map[string]any); ok {
		set = ix
	}
	v, ok := set["number_of_shards"]
	if !ok {
		return 1
	}
	var n int
	if _, err := fmt.Sscan(fmt.Sprint(v), &n); err != nil {
		t.Fatalf("number_of_shards %v", v)
	}
	return n
}

// One node with the default 90 days kept, simulated past the point where
// retention starts deleting (SS-02): with the data models of a small
// fleet it stays under the shard limit, and under the warning, on every
// day, the 1st of each month included, when the audit index of a new
// month appears. With the twelve models of a Windows and Sysmon fleet,
// which would reach the limit before day 90, the Servers page warns on
// the first day, months ahead, and the template check warns in the log
// before OpenSearch refuses a day's indices; keeping 60 days, as the
// warning advises, keeps it under.
func TestShardRoom90DaysOnOneNode(t *testing.T) {
	const days = 130
	eightModels := twelveModels[:8]

	s := simulateShards(t, eightModels, 90, days)
	if s.maxShards != 1 {
		t.Errorf("eight models: a day's index got %d shards on one node, want 1", s.maxShards)
	}
	if s.maxUsed >= 800 || s.firstWarn >= 0 || s.firstFull >= 0 {
		t.Errorf("eight models kept 90 days: at most %d shards, warned on day %d (%q), full on day %d; want under 800 and no warning",
			s.maxUsed, s.firstWarn, s.warning, s.firstFull)
	}
	if want := 8*91 + 5; s.maxUsed < want {
		t.Errorf("eight models: at most %d shards, want at least %d once 90 days are kept", s.maxUsed, want)
	}

	s = simulateShards(t, twelveModels, 90, days)
	if s.firstFull < 0 {
		t.Fatalf("twelve models kept 90 days never reached the limit (at most %d shards)", s.maxUsed)
	}
	if s.firstWarn != 0 {
		t.Errorf("twelve models: the Servers page first warned on day %d, want day 0 (full on day %d)", s.firstWarn, s.firstFull)
	}
	if s.firstNear < 0 || s.firstNear >= s.firstFull {
		t.Errorf("twelve models: the log warned on day %d, full on day %d", s.firstNear, s.firstFull)
	}
	if s.maxShards != 1 {
		t.Errorf("twelve models: a day's index got %d shards on one node, want 1", s.maxShards)
	}

	s = simulateShards(t, twelveModels, 60, days)
	if s.maxUsed >= 800 || s.firstWarn >= 0 || s.firstFull >= 0 {
		t.Errorf("twelve models kept 60 days: at most %d shards, warned on day %d (%q), full on day %d", s.maxUsed, s.firstWarn, s.warning, s.firstFull)
	}
}

// The audit records' monthly index adds one index a month: on the 1st,
// when this month's is new, it is not projected as a day's index kept
// for the audit's 400 days.
func TestProjectShardsMonthlyIndex(t *testing.T) {
	now := time.Now().UTC()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 12, 0, 0, 0, time.UTC)
	held := append(days(twelveModels[:2], 3, 1, firstOfMonth),
		indexCopies{Index: audit.IndexName("signalith", firstOfMonth), Copies: 1},
		indexCopies{Index: audit.IndexName("signalith", firstOfMonth.AddDate(0, -1, 0)), Copies: 1})
	p := projectShards("signalith", held, 8, 1000, func(string) int { return 90 }, firstOfMonth)
	if p.PerDay != 2 || p.Projected != 8-6+2*91 {
		t.Errorf("%+v, want 2 shards a day and %d projected", p, 8-6+2*91)
	}
}
