// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestSearchFiltersAndPages(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	ctx := context.Background()
	base := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, srv := range []struct{ name, node string }{{"a", "na"}, {"b", "nb"}} {
		s := newTestSink(t, SinkOptions{Dir: filepath.Join(t.TempDir(), "spool"), Client: c, Prefix: testPrefix, Server: srv.name, NodeID: srv.node})
		for i := range 5 {
			user := "alice"
			if i%2 == 1 {
				user = "bob"
			}
			action := "users.create"
			if i == 4 {
				action = "feeds.delete"
			}
			// Both servers log at the same instants: the sort must still
			// page through every event once.
			s.Add(Event{Time: base.Add(time.Duration(i) * time.Minute), User: user, Action: action, Message: action})
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}

	check := func(q Query, want int) *Page {
		t.Helper()
		p, err := Search(ctx, c, testPrefix, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Events) != want {
			t.Errorf("%+v: %d events, want %d", q, len(p.Events), want)
		}
		return p
	}
	check(Query{}, 10)
	for _, h := range check(Query{Server: "b"}, 5).Events {
		if h.Server != "b" || h.ID == "" || h.Index != testPrefix+"_audit-2026.10" {
			t.Errorf("hit %+v", h)
		}
	}
	check(Query{Server: "a", User: "bob"}, 2)
	check(Query{Action: "feeds.delete"}, 2)
	check(Query{From: base.Add(time.Minute), To: base.Add(3 * time.Minute)}, 4)
	if p := check(Query{}, 10); p.Total != 10 || !p.Events[0].Time.Equal(base.Add(4*time.Minute)) {
		t.Errorf("newest first: total %d, first %v", p.Total, p.Events[0].Time)
	}

	seen := map[string]bool{}
	var last time.Time
	q := Query{Size: 3}
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("paging does not end")
		}
		p, err := Search(ctx, c, testPrefix, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range p.Events {
			if seen[h.ID] {
				t.Errorf("%s twice", h.ID)
			}
			seen[h.ID] = true
			if !last.IsZero() && h.Time.After(last) {
				t.Errorf("out of order: %v after %v", h.Time, last)
			}
			last = h.Time
		}
		if p.Next == nil {
			break
		}
		// Next survives a trip through JSON, as from a browser.
		b, _ := json.Marshal(p.Next)
		q.After = nil
		if err := json.Unmarshal(b, &q.After); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 10 {
		t.Errorf("paged through %d events, want 10", len(seen))
	}
}

func TestSearchWithoutIndices(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	p, err := Search(context.Background(), c, testPrefix, Query{User: "x"})
	if err != nil || len(p.Events) != 0 || p.Next != nil {
		t.Errorf("page %+v, err %v", p, err)
	}
	p, err = Search(context.Background(), stubSearcher{err: &store.Error{Status: 404, Body: `{"error":{"type":"index_not_found_exception"}}`}}, testPrefix, Query{})
	if err != nil || len(p.Events) != 0 {
		t.Errorf("page %+v, err %v", p, err)
	}
}

func TestActionPrefixAndText(t *testing.T) {
	var got map[string]any
	st := stubSearcher{res: map[string]any{}, body: &got}
	if _, err := Search(context.Background(), st, testPrefix, Query{Action: "users.", Text: "bob", Size: 9999}); err != nil {
		t.Fatal(err)
	}
	f := got["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	want := []any{
		map[string]any{"prefix": map[string]any{"action": "users."}},
		map[string]any{"simple_query_string": map[string]any{"query": "bob", "fields": []string{"message", "user", "target"}, "default_operator": "and"}},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("filters %#v", f)
	}
	if got["size"] != MaxSize {
		t.Errorf("size %v", got["size"])
	}
}

func TestServers(t *testing.T) {
	st := stubSearcher{res: map[string]any{"aggregations": map[string]any{"servers": map[string]any{
		"buckets": []any{map[string]any{"key": "a", "doc_count": 3}, map[string]any{"key": "b", "doc_count": 1}}}}}}
	got, err := Servers(context.Background(), st, testPrefix)
	if err != nil || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("servers %v, err %v", got, err)
	}
}

type stubSearcher struct {
	res  map[string]any
	err  error
	body *map[string]any
}

func (s stubSearcher) Search(_ context.Context, index string, body map[string]any) (map[string]any, error) {
	if s.body != nil {
		*s.body = body
	}
	return s.res, s.err
}

// startingSearcher answers that all shards failed a few times, as
// OpenSearch does while a just-created index's shard starts.
type startingSearcher struct {
	fails int
	calls int
}

func (s *startingSearcher) Search(context.Context, string, map[string]any) (map[string]any, error) {
	s.calls++
	if s.calls <= s.fails {
		return nil, &store.Error{Status: 503, Body: `{"error":{"type":"search_phase_execution_exception","reason":"all shards failed"}}`}
	}
	return map[string]any{"aggregations": map[string]any{"servers": map[string]any{
		"buckets": []any{map[string]any{"key": "siem-a"}}}}}, nil
}

func TestSearchWaitsForStartingShards(t *testing.T) {
	s := &startingSearcher{fails: 2}
	names, err := Servers(context.Background(), s, testPrefix)
	if err != nil || len(names) != 1 || s.calls != 3 {
		t.Fatalf("Servers = %v, %v after %d calls; want siem-a after 3", names, err, s.calls)
	}

	old := starting
	starting = 0
	defer func() { starting = old }()
	s = &startingSearcher{fails: 100}
	if _, err := Servers(context.Background(), s, testPrefix); err == nil || s.calls != 1 {
		t.Fatalf("with no time to wait: err %v after %d calls; want the error after 1", err, s.calls)
	}
}

// TestVerifyNoRecordsLeft: with every audit index deleted, or every record
// in them, the check reports records removed when servers sign theirs,
// and stays clean when none does yet, or when the range is before they
// started or too short to hold a checkpoint.
func TestVerifyNoRecordsLeft(t *testing.T) {
	now := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC)
	old := verifyNow
	verifyNow = func() time.Time { return now }
	defer func() { verifyNow = old }()
	gone := stubSearcher{err: &store.Error{Status: 404, Body: `{"error":{"type":"index_not_found_exception"}}`}}
	empty := stubSearcher{res: map[string]any{"hits": map[string]any{"hits": []any{}}}}
	signed := map[string]time.Time{"n1": now.Add(-30 * 24 * time.Hour)}
	// Everything deleted, and one record of a made-up server put in.
	other := stubSearcher{res: map[string]any{"hits": map[string]any{"hits": []any{map[string]any{
		"_index": testPrefix + "_audit-2026.10", "_id": "x1", "sort": []any{1},
		"_source": map[string]any{"@timestamp": now.Add(-time.Hour).Format(time.RFC3339Nano), "node_id": "x", "server": "x",
			"chain": "c", "seq": 1, "action": "user.login", "message": "hello"},
	}}}}}
	for _, tc := range []struct {
		name     string
		c        Searcher
		q        VerifyQuery
		tampered bool
	}{
		{"indices deleted", gone, VerifyQuery{SignedSince: signed}, true},
		{"records deleted", empty, VerifyQuery{SignedSince: signed, From: now.Add(-24 * time.Hour)}, true},
		{"another server's record left", other, VerifyQuery{SignedSince: signed}, true},
		{"nobody signs yet", gone, VerifyQuery{}, false},
		{"started signing an hour ago", empty, VerifyQuery{SignedSince: map[string]time.Time{"n1": now.Add(-time.Hour)}}, false},
		{"range before signing", empty, VerifyQuery{SignedSince: signed, To: now.Add(-40 * 24 * time.Hour)}, false},
		{"range an hour long", empty, VerifyQuery{SignedSince: signed, From: now.Add(-time.Hour)}, false},
		// Retention may have deleted months before this one, unless it
		// keeps them (SCC-04).
		{"last month only", empty, VerifyQuery{SignedSince: signed, From: now.Add(-25 * 24 * time.Hour), To: now.Add(-20 * 24 * time.Hour)}, false},
		{"last month, kept", empty, VerifyQuery{SignedSince: signed, From: now.Add(-25 * 24 * time.Hour), To: now.Add(-20 * 24 * time.Hour), KeptFrom: now.Add(-400 * 24 * time.Hour)}, true},
		{"last month, past keep_days", empty, VerifyQuery{SignedSince: signed, From: now.Add(-25 * 24 * time.Hour), To: now.Add(-20 * 24 * time.Hour), KeptFrom: now.Add(-10 * 24 * time.Hour)}, false},
	} {
		r, err := Verify(context.Background(), tc.c, testPrefix, tc.q, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.name == "another server's record left" && r.Records != 1 {
			t.Errorf("%s: read %d records, want the one put in", tc.name, r.Records)
		}
		if r.Tampered() != tc.tampered {
			t.Errorf("%s: tampered = %v, want %v: %+v", tc.name, r.Tampered(), tc.tampered, r.Problems)
		}
		if tc.tampered && (r.Truncated != 1 || r.Problems[len(r.Problems)-1].Kind != ProblemTruncated || !strings.Contains(r.Problems[len(r.Problems)-1].Detail, "removed")) {
			t.Errorf("%s: problems = %+v", tc.name, r.Problems)
		}
	}
}

// TestVerifyMonthRemoved: with the current month's records there, a past
// month that retention keeps and that holds no record is reported
// removed; one retention may have deleted is not (SCC-04).
func TestVerifyMonthRemoved(t *testing.T) {
	now := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC)
	signed := map[string]time.Time{"n1": time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	hit := func(t time.Time) Hit { var h Hit; h.NodeID, h.Time = "n1", t; return h }
	// July and October hold records; August and September were removed.
	hits := []Hit{hit(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)), hit(now.Add(-time.Hour))}
	for _, tc := range []struct {
		name    string
		kept    time.Time
		missing []string
	}{
		{"kept forever", time.Unix(1, 0), []string{"2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z"}},
		// keep_days 60: August ended before 08-21, so may be gone.
		{"keep 60 days", now.Add(-60 * 24 * time.Hour), []string{"2026-09-01T00:00:00Z"}},
		{"not known", time.Time{}, nil},
	} {
		r := &Report{}
		noneLeft(r, VerifyQuery{SignedSince: signed, KeptFrom: tc.kept}, hits, now, false)
		var got []string
		for _, p := range r.Problems {
			got = append(got, p.Time.UTC().Format(time.RFC3339))
		}
		if strings.Join(got, ",") != strings.Join(tc.missing, ",") || r.Truncated != int64(len(tc.missing)) {
			t.Errorf("%s: removed %v (%d), want %v", tc.name, got, r.Truncated, tc.missing)
		}
	}
}
