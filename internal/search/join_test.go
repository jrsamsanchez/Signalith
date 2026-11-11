// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
)

const joinMain = `{"hits":{"total":{"value":4},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"amy","host":"h1"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","user":"bob","host":"h2"}},
	{"_source":{"@timestamp":"2026-10-15T09:00:00Z","user":"cat","host":"h3"}},
	{"_source":{"@timestamp":"2026-10-15T08:00:00Z","host":"h4"}}]}}`

const joinSub = `{"hits":{"total":{"value":3}},"aggregations":{"groups":{"buckets":[
	{"key":{"k0":"amy"},"doc_count":5},
	{"key":{"k0":"bob"},"doc_count":2}]}}}`

func joinEngine(responses ...string) (*Engine, *fakeStore) {
	fs := &fakeStore{responses: append(responses, `{"hits":{"total":{"value":0}},"aggregations":{"groups":{"buckets":[]}}}`)}
	st, _ := lookuptables.Open("")
	_, _ = st.Put("owners", []byte("host,owner\nh1,Ana\nh1,Kim\nh2,Lee\n"))
	return &Engine{Store: fs, Lookups: st}, fs
}

func TestJoinWithSubsearch(t *testing.T) {
	e, fs := joinEngine(joinMain, joinSub)
	res, err := e.Run(context.Background(), `* earliest=-7d | join user [search datamodel=Change | stats count as changes by user]`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[any]any{}
	for _, r := range res.Rows {
		got[r["user"]] = r["changes"]
	}
	if want := map[any]any{"amy": int64(5), "bob": int64(2)}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if !strings.Contains(strings.Join(res.Columns, ","), "changes") {
		t.Errorf("columns = %v", res.Columns)
	}
	// The subsearch searched the outer time range, in its data model.
	if len(fs.indexes) < 2 || !namesDays(fs.indexes[1], "signalith-change-") || !strings.Contains(asJSON(fs.bodies[1]), `"gte":"now-7d"`) {
		t.Errorf("subsearch = %v %v", fs.indexes, fs.bodies)
	}

	e, _ = joinEngine(joinMain, joinSub)
	res, err = e.Run(context.Background(), `* | join type=left user [search * | stats count as changes by user] | table user changes`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 4 || res.Rows[2]["user"] != "cat" || res.Rows[2]["changes"] != nil {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestJoinMatchesAndLookupSubsearch(t *testing.T) {
	for src, want := range map[string][]string{
		// h1 has two owners: the first is joined unless max= says more.
		`* | join host [search | inputlookup owners] | table host owner`:       {"h1 Ana", "h2 Lee"},
		`* | join max=0 host [search | inputlookup owners] | table host owner`: {"h1 Ana", "h1 Kim", "h2 Lee"},
		`* | join max=2 host [search | inputlookup owners] | table host owner`: {"h1 Ana", "h1 Kim", "h2 Lee"},
	} {
		e, fs := joinEngine(joinMain)
		res, err := e.Run(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		var got []string
		for _, r := range res.Rows {
			got = append(got, r["host"].(string)+" "+r["owner"].(string))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v", src, got)
		}
		if len(fs.bodies) != 1 {
			t.Errorf("%s: %d searches, want only the outer one", src, len(fs.bodies))
		}
	}
}

func TestJoinErrors(t *testing.T) {
	e, _ := joinEngine(joinMain)
	var qe *QueryError
	if _, err := e.Run(context.Background(), `* | join host [search | inputlookup nope]`); !errors.As(err, &qe) {
		t.Errorf("err = %v", err)
	}
	if _, err := e.Run(context.Background(), `* | join host [search index=other-*]`); err == nil || !strings.Contains(err.Error(), "outside Signalith") {
		t.Errorf("err = %v", err)
	}
}

// A join that copies wide subsearch rows onto many rows stops at the
// search's budget instead of building gigabytes.
func TestJoinCountsAgainstTheBudget(t *testing.T) {
	big := strings.Repeat("x", 600<<10)
	var outer, sub strings.Builder
	outer.WriteString(`{"hits":{"total":{"value":600},"hits":[`)
	for i := range 600 {
		if i > 0 {
			outer.WriteString(",")
		}
		outer.WriteString(`{"_source":{"@timestamp":"2026-10-15T10:00:00Z","k":"a"}}`)
	}
	outer.WriteString(`]}}`)
	sub.WriteString(`{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T10:00:00Z","k":"a","wide":"` + big + `"}}]}}`)
	e := &Engine{Store: &fakeStore{responses: []string{outer.String(), sub.String()}}}
	_, err := e.Run(context.Background(), `* | sort k | join k [search *]`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("err = %v", err)
	}
}

// A plain event search inside join, append, union, multisearch or set
// takes up to search.max_events, not the newest 100, and marks the result
// Sampled when more match.
func TestSubsearchEventsAreNotCappedAt100(t *testing.T) {
	const many = `{"hits":{"total":{"value":100000},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"amy"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","user":"bob"}}]}}`
	for _, tc := range []struct {
		q     string
		outer int // the outer search's size, when it has one of its own
	}{
		// An inner join drops the outer events without a match, so the
		// outer search takes them all too.
		{`* | join user [search datamodel=Authentication]`, 10000},
		{`* | append [search datamodel=Authentication] | stats count by user`, 10000},
		{`* | union [search datamodel=Authentication] [search datamodel=Change]`, 100},
		{`| multisearch [search datamodel=Authentication] [search datamodel=Change] | stats count by user`, 0},
		{`| set union [search datamodel=Authentication | fields user] [search datamodel=Change | fields user]`, 0},
	} {
		q := tc.q
		fs := &fakeStore{responses: []string{many}}
		e := &Engine{Store: fs, Opt: Options{MaxEvents: 10000}}
		res, err := e.Run(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if len(fs.bodies) < 2 {
			t.Fatalf("%s: %d searches", q, len(fs.bodies))
		}
		for i, b := range fs.bodies {
			want := 10000
			if i == 0 && tc.outer > 0 {
				want = tc.outer
			}
			if size, _ := b["size"].(int); size != want {
				t.Errorf("%s: search %d size = %v, want %d", q, i, b["size"], want)
			}
		}
		if res.Sampled != 2 {
			t.Errorf("%s: sampled = %d", q, res.Sampled)
		}
	}
}
