// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func runRows(t *testing.T, e *Engine, src string, fields ...string) []string {
	t.Helper()
	res, err := e.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	var out []string
	for _, r := range res.Rows {
		parts := make([]string, len(fields))
		for i, f := range fields {
			parts[i] = fmt.Sprint(r[f])
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func TestStreamStats(t *testing.T) {
	e := &Engine{}
	const rows = `| makeresults count=6 | streamstats count as n | eval g=if(n%2=0, "even", "odd"), v=n*10`
	for src, want := range map[string][]string{
		rows + ` | streamstats sum(v) as s, avg(v) as a, max(v) as m, dc(g) as d`: {
			"10 10 10 1", "30 15 20 2", "60 20 30 2", "100 25 40 2", "150 30 50 2", "210 35 60 2"},
		rows + ` | streamstats current=f sum(v) as s, avg(v) as a, max(v) as m, dc(g) as d`: {
			"<nil> <nil> <nil> 0", "10 10 10 1", "30 15 20 2", "60 20 30 2", "100 25 40 2", "150 30 50 2"},
		rows + ` | streamstats window=2 sum(v) as s, avg(v) as a, max(v) as m, dc(g) as d`: {
			"10 10 10 1", "30 15 20 2", "50 25 30 2", "70 35 40 2", "90 45 50 2", "110 55 60 2"},
		rows + ` | streamstats current=f window=2 sum(v) as s, avg(v) as a, max(v) as m, dc(g) as d`: {
			"<nil> <nil> <nil> 0", "10 10 10 1", "30 15 20 2", "50 25 30 2", "70 35 40 2", "90 45 50 2"},
	} {
		if got := runRows(t, e, src, "s", "a", "m", "d"); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", src, got, want)
		}
	}
	got := runRows(t, e, rows+` | streamstats window=2 count, first(v) as f, last(v) as l, min(v) as lo, range(v) as r by g`, "g", "count", "f", "l", "lo", "r")
	want := []string{"odd 1 10 10 10 0", "even 1 20 20 20 0", "odd 2 10 30 10 20", "even 2 20 40 20 20", "odd 2 30 50 30 20", "even 2 40 60 40 20"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("by g:\n got %v\nwant %v", got, want)
	}
}

func TestStreamStatsWindowMinMax(t *testing.T) {
	// Values that fall then rise make min and max change sides of the
	// window; each answer is checked against a plain scan.
	vals := []int{5, 3, 8, 1, 9, 2, 7, 7, 0, 6}
	src := `| makeresults count=10 | streamstats count as n | eval v=case(` +
		func() string {
			var parts []string
			for i, v := range vals {
				parts = append(parts, fmt.Sprintf("n=%d, %d", i+1, v))
			}
			return strings.Join(parts, ", ")
		}() + `) | streamstats window=3 min(v) as lo, max(v) as hi`
	got := runRows(t, &Engine{}, src, "lo", "hi")
	for i := range vals {
		lo, hi := vals[i], vals[i]
		for j := max(0, i-2); j <= i; j++ {
			lo, hi = min(lo, vals[j]), max(hi, vals[j])
		}
		if w := fmt.Sprintf("%d %d", lo, hi); got[i] != w {
			t.Errorf("row %d: got %s, want %s", i, got[i], w)
		}
	}
}

func TestBin(t *testing.T) {
	const events = `{"hits":{"total":{"value":3},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:59:59Z","bytes":250,"epoch":1760529599}},
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","bytes":99.5}},
	{"_source":{"@timestamp":"2026-10-14T23:30:00.5Z","bytes":-1}}]}}`
	for src, want := range map[string][]string{
		`* | bin span=1h _time | table _time`:         {"2026-10-15T11:00:00Z", "2026-10-15T11:00:00Z", "2026-10-14T23:00:00Z"},
		`* | bucket _time span=1d | table _time`:      {"2026-10-15T00:00:00Z", "2026-10-15T00:00:00Z", "2026-10-14T00:00:00Z"},
		`* | bin span=1w _time | table _time`:         {"2026-10-11T00:00:00Z", "2026-10-11T00:00:00Z", "2026-10-11T00:00:00Z"},
		`* | bin span=15m _time AS slot | table slot`: {"2026-10-15T11:45:00Z", "2026-10-15T11:00:00Z", "2026-10-14T23:30:00Z"},
		`* | bin span=100 bytes | table bytes`:        {"200-300", "0-100", "-100-0"},
		`* | bin span=0.5 bytes AS b | table b`:       {"250-250.5", "99.5-100", "-1--0.5"},
		`* | bin span=1h epoch | table epoch`:         {"1760526000", "<nil>", "<nil>"},
	} {
		e := &Engine{Store: &fakeStore{responses: []string{events}}}
		if got := runRows(t, e, src, strings.Fields(src[strings.LastIndex(src, "table")+6:])...); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", src, got, want)
		}
	}
}

func TestRegexCommand(t *testing.T) {
	const events = `{"hits":{"total":{"value":3},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","process":"powershell -EncodedCommand AAA","_raw":"one"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","process":"cmd /c dir","_raw":"two"}},
	{"_source":{"@timestamp":"2026-10-15T09:00:00Z","_raw":"three"}}]}}`
	for src, want := range map[string][]string{
		`* | regex process="(?i)-enc(odedcommand)?\s" | table _raw`: {"one"},
		`* | regex process!="(?i)-enc" | table _raw`:                {"two", "three"},
		`* | regex "^t" | table _raw`:                               {"two", "three"},
	} {
		e := &Engine{Store: &fakeStore{responses: []string{events}}}
		if got := runRows(t, e, src, "_raw"); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", src, got, want)
		}
	}
	// regex filters, so it looks at every event, not the newest few.
	if a, b := compile(t, `* | regex "x"`).Body["size"], compile(t, `*`).Body["size"]; a == b {
		t.Errorf("size = %v, as without regex", a)
	}
}

func TestFieldsRemoveAndMakeResults(t *testing.T) {
	e := &Engine{Store: &fakeStore{responses: []string{joinMain}}}
	res, err := e.Run(context.Background(), `* | eval tmp_a=1, tmp_b=2 | fields - tmp_*, host`)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Columns {
		if strings.HasPrefix(c, "tmp_") || c == "host" {
			t.Errorf("columns = %v", res.Columns)
		}
	}
	for _, r := range res.Rows {
		if _, ok := r["tmp_a"]; ok {
			t.Errorf("row = %v", r)
		}
		if _, ok := r["host"]; ok {
			t.Errorf("row = %v", r)
		}
	}

	e = &Engine{}
	res, err = e.Run(context.Background(), `| makeresults count=3 | eval user="test"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 3 || res.Rows[0]["user"] != "test" || res.Rows[0]["_time"] == nil {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestAppendAndAppendPipe(t *testing.T) {
	e, fs := joinEngine(joinMain, joinSub)
	got := runRows(t, e, `* earliest=-7d | table user | append [search datamodel=Change | stats count as changes by user]`, "user", "changes")
	want := []string{"amy <nil>", "bob <nil>", "cat <nil>", "<nil> <nil>", "amy 5", "bob 2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("append:\n got %v\nwant %v", got, want)
	}
	// The subsearch searched the outer time range, in its data model.
	if len(fs.indexes) < 2 || !namesDays(fs.indexes[1], "signalith-change-") || !strings.Contains(asJSON(fs.bodies[1]), `"gte":"now-7d"`) {
		t.Errorf("subsearch = %v %v", fs.indexes, fs.bodies)
	}

	e, _ = joinEngine(joinMain)
	got = runRows(t, e, `* | table user host | appendpipe [stats count by host | eval user="TOTAL"] | where user="TOTAL" OR user="amy"`, "user", "host", "count")
	want = []string{"amy h1 <nil>", "TOTAL h1 1", "TOTAL h2 1", "TOTAL h3 1", "TOTAL h4 1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("appendpipe:\n got %v\nwant %v", got, want)
	}

	// The copy appendpipe works on is its own: changes to it do not reach
	// the rows before it.
	e, _ = joinEngine(joinMain)
	got = runRows(t, e, `* | table user | appendpipe [eval user="x"] | stats count by user`, "user", "count")
	want = []string{"amy 1", "bob 1", "cat 1", "x 4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("copy:\n got %v\nwant %v", got, want)
	}

	e, _ = joinEngine(joinMain)
	got = runRows(t, e, `* | head 1 | append [search | inputlookup owners] | table host owner`, "host", "owner")
	want = []string{"h1 <nil>", "h1 Ana", "h1 Kim", "h2 Lee"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("append inputlookup:\n got %v\nwant %v", got, want)
	}
}

func TestAppendSubsearchMustCompile(t *testing.T) {
	e, fs := joinEngine(joinMain)
	_, err := e.Run(context.Background(), `* | appendpipe [append [search * | threatmatch]]`)
	if !errors.Is(err, errIntelOff) || len(fs.bodies) != 0 {
		t.Fatalf("err = %v, searches = %d", err, len(fs.bodies))
	}
}

// budgetEvents is one event with a 600 KB field and 499 small ones.
func budgetEvents() string {
	var b strings.Builder
	b.WriteString(`{"hits":{"total":{"value":500},"hits":[`)
	b.WriteString(`{"_source":{"@timestamp":"2026-10-15T10:00:00Z","wide":"` + strings.Repeat("x", 600<<10) + `"}}`)
	for range 499 {
		b.WriteString(`,{"_source":{"@timestamp":"2026-10-15T10:00:00Z","k":"a"}}`)
	}
	b.WriteString(`]}}`)
	return b.String()
}

func TestAppendPipeCountsAgainstTheBudget(t *testing.T) {
	// Each appendpipe copies every row, so the wide field is copied
	// 511 times: past the search's 256 MB.
	e := &Engine{Store: &fakeStore{responses: []string{budgetEvents()}}}
	_, err := e.Run(context.Background(), `* | sort k`+strings.Repeat(` | appendpipe [head 100000]`, 9))
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamStatsCountsAgainstTheBudget(t *testing.T) {
	// first() writes the wide value into all 500 rows.
	e := &Engine{Store: &fakeStore{responses: []string{budgetEvents()}}}
	_, err := e.Run(context.Background(), `* | streamstats first(wide) as w`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("err = %v", err)
	}
}

func TestBinCountsAgainstTheBudget(t *testing.T) {
	// A bucket of 1e308 is about 620 bytes; 10,000 rows of them written
	// to 300 fields is past the search's 256 MB.
	var b strings.Builder
	b.WriteString(`| makeresults count=10000 | eval x=1e308`)
	for i := range 300 {
		fmt.Fprintf(&b, ` | bin span=1 x as a%d`, i)
	}
	_, err := (&Engine{}).Run(context.Background(), b.String())
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("err = %v", err)
	}
}

// FuzzStreamCommands runs streamstats, bin, regex, append, appendpipe and
// the other commands that run in the server with any arguments over a few events: a bad query fails with an error,
// never with an internal one.
func FuzzStreamCommands(f *testing.F) {
	for _, s := range []string{
		`streamstats current=f window=2 count, sum(v) as s, min(v), max(v), range(v), dc(g), first(g), last(v) by g`,
		`bin span=1h _time`, `bin span=0.25 v AS b`, `bucket _time span=1w`,
		`regex g="^o"`, `regex v!="1"`, `fields - g, v*`,
		`appendpipe [stats count by g | eval g="all"]`, `append [| makeresults count=2]`,
		`chart limit=1 sum(v) over n by g | untable n g s | xyseries n g s`, `eval j="{\"a\":[{\"b\":1},{\"b\":2}]}" | spath input=j path=a{}.b`,
		`eval j="{\"a\":{\"b\":[1,{\"c\":true}]}}" | spath input=j`,
		`top 2 useother=t countfield=c g by n | search c>1 OR g=o*`, `rename * as x_* | rename x_g as v`,
		`eval m=split("a,b,,c", ",") | mvexpand m limit=2 | makemv delim="b" m | reverse`,
		`eval s="a1b22c" | makemv tokenizer="(\d+)" s | addtotals col=t labelfield=g v n | addcoltotals`,
		`eval u="A\\b" | rex field=u mode=sed "s/(\w)\\\\(\w)/\2&/g" | rex field=g mode=sed "y/oe/OE/"`,
		`eval t=n*86400, d="1+00:00:05" | convert timeformat="%Y-%m-%d" ctime(t) AS day, dur2sec(d), num(*), none(g) | tail 4 | uniq`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		e := &Engine{Store: &fakeStore{responses: []string{joinMain}}}
		_, err := e.Run(context.Background(), `| makeresults count=20 | streamstats count as n | eval g=if(n%3=0, "odd", "even"), v=n*1.5 - 7 | `+cmd)
		if errors.Is(err, ErrInternal) {
			t.Fatalf("%q: %v", cmd, err)
		}
	})
}
