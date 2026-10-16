package search

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const round5Events = `{"hits":{"total":{"value":5},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","host":"h1","user":"a","src_ip":"10.0.0.1","bytes_in":10,"bytes_out":1,"r":"x,y,,z"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","host":"h1","user":"a","src_ip":"10.0.0.2","bytes_in":20,"bytes_out":2}},
	{"_source":{"@timestamp":"2026-10-15T09:00:00Z","host":"h1","user":"b","bytes_in":30,"bytes_out":3.5}},
	{"_source":{"@timestamp":"2026-10-15T08:00:00Z","host":"h2","user":"c","bytes_in":40,"bytes_out":"4"}},
	{"_source":{"@timestamp":"2026-10-15T07:00:00Z","host":"h1","user":"d","bytes_in":50,"bytes_out":"n/a"}}]}}`

func runRound5(t *testing.T, src string) *Result {
	t.Helper()
	e := &Engine{Store: &fakeStore{responses: []string{round5Events}}}
	res, err := e.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	return res
}

func rowsOf(res *Result, cols ...string) []string {
	var out []string
	for _, r := range res.Rows {
		vals := make([]any, len(cols))
		for i, c := range cols {
			vals[i] = r[c]
		}
		out = append(out, strings.TrimSuffix(fmt.Sprintln(vals...), "\n"))
	}
	return out
}

func TestTopOptions(t *testing.T) {
	res := runRound5(t, `* | head 100 | top 2 useother=t countfield=n percentfield=p user by host`)
	if want := []string{"host", "user", "n", "p"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	if got, want := rowsOf(res, "host", "user", "n", "p"), []string{"h1 a 2 50", "h1 OTHER 1 25", "h2 c 1 100"}; len(got) != 4 || got[0] != want[0] || got[2] != want[1] || got[3] != want[2] {
		t.Errorf("rows = %q", got)
	}
	res = runRound5(t, `* | head 100 | rare showcount=f showperc=f host`)
	if want := []string{"host"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	if got := rowsOf(res, "host"); !reflect.DeepEqual(got, []string{"h2", "h1"}) {
		t.Errorf("rows = %q", got)
	}
	// A field named count no longer clashes with the count column.
	res = runRound5(t, `* | head 100 | eval count=host | top count`)
	if got := rowsOf(res, "count", "percent"); !reflect.DeepEqual(got, []string{"4 80", "1 20"}) {
		t.Errorf("rows = %q", got)
	}
}

func TestSearchCommandFilters(t *testing.T) {
	res := runRound5(t, `* | head 100 | stats count by user | search count>1 OR user=d*`)
	if got := rowsOf(res, "user", "count"); !reflect.DeepEqual(got, []string{"a 2", "d 1"}) {
		t.Errorf("rows = %q", got)
	}
}

func TestRenameWildcard(t *testing.T) {
	res := runRound5(t, `* | head 100 | table host, src_ip, bytes_in | eval src=1 | rename *_ip as * bytes_* as b_*`)
	if want := []string{"host", "src", "b_in"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	// src_ip replaced the src set by eval; rows without src_ip keep theirs.
	if got := rowsOf(res, "src", "b_in"); got[0] != "10.0.0.1 10" || got[2] != "1 30" {
		t.Errorf("rows = %q", got)
	}
}

func TestMakeMVAndMVExpand(t *testing.T) {
	res := runRound5(t, `* | head 1 | makemv delim="," r | mvexpand r | table r`)
	if got := rowsOf(res, "r"); !reflect.DeepEqual(got, []string{"x", "y", "z"}) {
		t.Errorf("rows = %q", got)
	}
	res = runRound5(t, `* | head 1 | makemv delim="," allowempty=t r | mvexpand r limit=3 | table r`)
	if got := rowsOf(res, "r"); !reflect.DeepEqual(got, []string{"x", "y", ""}) {
		t.Errorf("allowempty rows = %q", got)
	}
	res = runRound5(t, `* | head 1 | makemv tokenizer="([a-z]),?" r | eval n=mvcount(r)`)
	if got := rowsOf(res, "n"); !reflect.DeepEqual(got, []string{"3"}) {
		t.Errorf("tokenizer rows = %q", got)
	}
	// Rows without the field are dropped.
	res = runRound5(t, `* | head 100 | mvexpand r`)
	if len(res.Rows) != 1 {
		t.Errorf("rows = %d", len(res.Rows))
	}
}

func TestMVExpandCapsRows(t *testing.T) {
	src := `| makeresults count=200 | eval m=split("` + strings.Repeat("v,", 999) + `v", ",") | mvexpand m`
	e := &Engine{Store: &fakeStore{}}
	res, err := e.Run(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != maxAppendRows || !res.Truncated {
		t.Errorf("rows = %d, truncated = %v", len(res.Rows), res.Truncated)
	}
}

func TestReverseAndAddTotals(t *testing.T) {
	res := runRound5(t, `* | head 100 | table user, bytes_in, bytes_out | reverse | addtotals col=t labelfield=user label=All`)
	if want := []string{"user", "bytes_in", "bytes_out", "Total"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	got := rowsOf(res, "user", "bytes_in", "bytes_out", "Total")
	want := []string{"d 50 n/a 50", "c 40 4 44", "b 30 3.5 33.5", "a 20 2 22", "a 10 1 11", "All 150 10.5 160.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %q", got)
	}
	res = runRound5(t, `* | head 100 | table user, bytes_in, bytes_out | addcoltotals bytes_in`)
	if n := len(res.Rows); n != 6 || res.Rows[5]["bytes_in"] != int64(150) || res.Rows[5]["bytes_out"] != nil || res.Rows[0]["Total"] != nil {
		t.Errorf("addcoltotals = %v", res.Rows)
	}
}

func TestCompilePushesLeadingSearchIntoOpenSearch(t *testing.T) {
	p := compile(t, `search user=root | search dest=web* | stats count by src`)
	got := asJSON(p.Body["query"])
	for _, want := range []string{`"value":"root"`, `{"wildcard":{"dest":{"case_insensitive":true,"value":"web*"}}}`} {
		if !strings.Contains(got, want) {
			t.Errorf("query missing %s\nin %s", want, got)
		}
	}
	if p.Mode != "stats" {
		t.Errorf("mode = %s", p.Mode)
	}
}
