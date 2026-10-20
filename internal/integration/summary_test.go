// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/summary"
)

// TestSummaries builds summary indexes from real events and checks that
// searches reading them return what searches of the events return, also
// after an event arrives late.
func TestSummaries(t *testing.T) {
	cl, raw, prefix := setup(t)
	ctx := context.Background()
	t.Cleanup(func() {
		names, _ := cl.ListIndices(ctx, summary.IndexPattern(prefix))
		for _, n := range names {
			_ = cl.DeleteIndex(ctx, n)
		}
	})
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	now := time.Now()
	send := func(lines []string) {
		t.Helper()
		var batch []map[string]any
		for _, l := range lines {
			batch = append(batch, map[string]any{"log": l})
		}
		if res, err := p.Ingest(ctx, "linux.auth", batch); err != nil || len(res.Errors) > 0 {
			t.Fatalf("ingest: %v %+v", err, res)
		}
		if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	var lines []string
	for i := 0; i < 240; i++ {
		at := syslogTime(now.Add(-10*time.Minute - time.Duration(i)*73*time.Second))
		switch i % 4 {
		case 0, 1:
			lines = append(lines, fmt.Sprintf("%s web%d sshd[%d]: Failed password for invalid user u%d from 203.0.113.%d port %d ssh2", at, i%3, 100+i, i%5, i%7, 40000+i))
		case 2:
			lines = append(lines, fmt.Sprintf("%s web%d sshd[%d]: Accepted password for alice from 10.20.0.%d port %d ssh2", at, i%3, 100+i, i%4, 50000+i))
		default:
			lines = append(lines, fmt.Sprintf("%s web%d cron[%d]: (root) CMD (run-parts /etc/cron.hourly)", at, i%3, 100+i))
		}
	}
	send(lines)

	runtime := prefix + "_runtime"
	clock := now
	b := &summary.Builder{
		Client: cl, Prefix: prefix, Runtime: runtime,
		Days:          func() int { return 1 },
		Now:           func() time.Time { return clock },
		IndexSettings: func() map[string]any { return map[string]any{"number_of_replicas": 0} },
		FieldType:     ingest.FieldType,
		Node:          "test",
	}
	build := func() {
		t.Helper()
		for i := 0; i < 4; i++ {
			if err := b.Tick(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// The builder does not wait for its state to be searchable.
		if err := cl.Do(ctx, http.MethodPost, "/"+runtime+"/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	build()
	cov := &summary.Coverage{Client: cl, Runtime: runtime}
	cov.Refresh(ctx)
	if len(cov.Ranges("Authentication")) == 0 {
		t.Fatal("no Authentication summaries were built")
	}
	fast := &search.Engine{Store: cl, Opt: search.Options{IndexPrefix: prefix, DefaultEarliest: "-24h", SummaryDays: 1}, Summaries: cov}

	queries := []string{
		`datamodel=Authentication earliest=-6h | stats count by action, src`,
		`datamodel=Authentication action=failure earliest=-6h | stats count by user, host`,
		`datamodel=Authentication earliest=-6h | timechart span=1h count by action`,
		`datamodel=Authentication earliest=-6h | stats count`,
		`| tstats count from datamodel=Authentication where earliest=-6h by Authentication.src`,
		`earliest=-6h | stats count by sourcetype, datamodel`,
		`earliest=-6h | timechart span=30m count`,
	}
	same := func(when string) {
		t.Helper()
		for _, q := range queries {
			want, got := run(t, raw, q), run(t, fast, q)
			if !slices.Contains(got.Summaries, "Authentication") {
				t.Errorf("%s: %s did not read summaries", when, q)
			}
			if w, g := sortedRows(want.Rows), sortedRows(got.Rows); !reflect.DeepEqual(w, g) {
				t.Errorf("%s: %s\n events:    %v\n summaries: %v", when, q, w, g)
			}
			if want.Matched != got.Matched {
				t.Errorf("%s: %s matched %d from events, %d with summaries", when, q, want.Matched, got.Matched)
			}
		}
	}
	same("built")
	for _, q := range []string{
		`datamodel=Authentication "failed password" earliest=-6h | stats count`,
		`datamodel=Authentication earliest=-6h | stats count by process_id`,
		`datamodel=Authentication earliest=-6h | timechart span=1m count`,
	} {
		want, got := run(t, raw, q), run(t, fast, q)
		if len(got.Summaries) > 0 {
			t.Errorf("%s read summaries it cannot answer from", q)
		}
		if w, g := sortedRows(want.Rows), sortedRows(got.Rows); !reflect.DeepEqual(w, g) {
			t.Errorf("%s: %v != %v", q, w, g)
		}
	}

	// A gap (an hour too varied to summarize) reads its events.
	rs := cov.Ranges("Authentication")
	last := rs[len(rs)-1]
	hole := last.To.Add(-3 * time.Hour).Truncate(time.Hour)
	cov.Set(map[string][]summary.Range{"Authentication": {
		{From: rs[0].From, To: hole}, {From: hole.Add(time.Hour), To: last.To},
	}})
	same("with a gap")

	// A late event in a slot already summarized is counted once the
	// next check rebuilds that slot.
	send([]string{syslogTime(now.Add(-3*time.Hour)) + " web9 sshd[999]: Failed password for root from 198.51.100.77 port 1 ssh2"})
	clock = now.Add(11 * time.Minute)
	build()
	cov.Refresh(ctx)
	same("after a late event")

	// A day whose events are deleted early (a size cap, the disk guard)
	// takes its summaries along.
	day := now.Add(-3 * time.Hour).UTC()
	if err := cl.DeleteIndex(ctx, prefix+"-authentication-"+day.Format("2006.01.02")); err != nil {
		t.Fatal(err)
	}
	build()
	cov.Refresh(ctx)
	from := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	if n := summaryRows(t, cl, prefix, from, from.Add(24*time.Hour)); n != 0 {
		t.Errorf("%d rows of a day whose events are gone are left", n)
	}
	for _, q := range queries {
		want, got := run(t, raw, q), run(t, fast, q)
		if w, g := sortedRows(want.Rows), sortedRows(got.Rows); !reflect.DeepEqual(w, g) {
			t.Errorf("after a day was deleted: %s\n events:    %v\n summaries: %v", q, w, g)
		}
	}

	// Summaries reach back summary_days at most: as the range moves on,
	// rows it left behind go, and searches read those hours' events.
	for _, ahead := range []time.Duration{22 * time.Hour, 23*time.Hour + 10*time.Minute} {
		clock = now.Add(ahead)
		build()
	}
	cov.Refresh(ctx)
	if rs := cov.Ranges("Authentication"); len(rs) == 0 || rs[0].From.Before(now.Add(-2*time.Hour)) {
		t.Fatalf("summaries still start at %v", rs)
	}
	if n := summaryRows(t, cl, prefix, time.Time{}, now.Add(-2*time.Hour).Truncate(time.Hour)); n != 0 {
		t.Errorf("%d rows older than the summaries' start are left", n)
	}
	for _, q := range queries {
		want, got := run(t, raw, q), run(t, fast, q)
		if w, g := sortedRows(want.Rows), sortedRows(got.Rows); !reflect.DeepEqual(w, g) {
			t.Errorf("after the range moved: %s\n events:    %v\n summaries: %v", q, w, g)
		}
	}
}

// sortedRows renders rows in a stable order.
func sortedRows(rows []search.Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = fmt.Sprint(r)
	}
	slices.Sort(out)
	return out
}

// summaryRows counts the summary rows in [from, to).
func summaryRows(t *testing.T, cl *store.Client, prefix string, from, to time.Time) int64 {
	t.Helper()
	r := map[string]any{"lt": to.Format(time.RFC3339)}
	if !from.IsZero() {
		r["gte"] = from.Format(time.RFC3339)
	}
	resp, err := cl.Search(context.Background(), summary.IndexPattern(prefix), map[string]any{"size": 0, "track_total_hits": true,
		"query": map[string]any{"range": map[string]any{"@timestamp": r}}})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := resp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)
	return int64(n)
}
