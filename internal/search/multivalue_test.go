package search

import (
	"context"
	"errors"
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

func TestRexSed(t *testing.T) {
	src := `| makeresults | eval u="CORP\\alice", m=split("a1,b22", ",")`
	for cmd, want := range map[string]string{
		`rex field=u mode=sed "s/^CORP\\\\//"`:           "alice",
		`rex field=u mode=sed "s/(\w+)\\\\(\w+)/\2@\1/"`: "alice@CORP",
		`rex field=u mode=sed "s/[a-z]/X/g"`:             `CORP\XXXXX`,
		`rex field=u mode=sed "s/[a-z]/X/2"`:             `CORP\aXice`,
		`rex field=u mode=sed "s/i/[&]/"`:                `CORP\al[i]ce`,
		`rex field=u mode=sed "y/CORP/corp/"`:            `corp\alice`,
	} {
		res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | "+cmd)
		if err != nil {
			t.Errorf("%s: %v", cmd, err)
			continue
		}
		if got := res.Rows[0]["u"]; got != want {
			t.Errorf("%s: u = %v, want %s", cmd, got, want)
		}
	}
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+` | rex field=m mode=sed "s/\d+/#/"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Rows[0]["m"]; !reflect.DeepEqual(got, []any{"a#", "b#"}) {
		t.Errorf("multivalue = %v", got)
	}
}

func TestRexSedSizeLimit(t *testing.T) {
	// Every character becomes ten copies of itself: past 1 MB.
	events := `{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T11:00:00Z","s":"` + strings.Repeat("ab", 100000) + `"}}]}}`
	e := &Engine{Store: &fakeStore{responses: []string{events}}}
	_, err := e.Run(context.Background(), `* | head 1 | rex field=s mode=sed "s/./&&&&&&&&&&/g"`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Errorf("err = %v", err)
	}
}

func TestConvert(t *testing.T) {
	src := `| makeresults | eval t=1760000000, d="1+02:03:04", ms="01:02.5", mem="2m", c="1,234", u="12.5kb", x="abc", a_count="7", b_count="8"`
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+
		` | convert timeformat="%Y-%m-%d" ctime(t) AS day, dur2sec(d), mstime(ms), memk(mem), rmcomma(c), rmunit(u), num(x), auto(*_count), none(b_count)`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	for k, want := range map[string]any{"day": "2025-10-09", "t": int64(1760000000), "d": int64(93784), "ms": 62.5, "mem": int64(2048), "c": int64(1234), "u": 12.5, "a_count": int64(7), "b_count": "8"} {
		if !reflect.DeepEqual(r[k], want) {
			t.Errorf("%s = %#v, want %#v", k, r[k], want)
		}
	}
	if _, ok := r["x"]; ok {
		t.Errorf("num kept x = %v", r["x"])
	}
	res, err = (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval s="2026-10-15 08:00" | convert timeformat="%Y-%m-%d %H:%M" mktime(s)`)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Rows[0]["s"]; got != int64(1792051200) {
		t.Errorf("mktime = %#v", got)
	}
}

func TestTailAndUniq(t *testing.T) {
	res := runRound5(t, `* | head 100 | table user | tail 3`)
	if got := rowsOf(res, "user"); !reflect.DeepEqual(got, []string{"d", "c", "b"}) {
		t.Errorf("tail = %q", got)
	}
	res = runRound5(t, `* | head 100 | table host | uniq`)
	if got := rowsOf(res, "host"); !reflect.DeepEqual(got, []string{"h1", "h2", "h1"}) {
		t.Errorf("uniq = %q", got)
	}
}
