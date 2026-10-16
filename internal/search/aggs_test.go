package search

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestCompileStatsFunctions(t *testing.T) {
	p := compile(t, `* | stats median(bytes), perc95(bytes), stdev(bytes), range(bytes), values(user), mode(user), list(user), first(user), earliest(user) by src`)
	got := asJSON(p.Body["aggs"])
	for _, want := range []string{
		`"m0":{"percentiles":{"field":"bytes","keyed":false,"percents":[50]}}`,
		`"m1":{"percentiles":{"field":"bytes","keyed":false,"percents":[95]}}`,
		`"m2":{"extended_stats":{"field":"bytes"}}`,
		`"m3":{"stats":{"field":"bytes"}}`,
		`"m4":{"terms":{"field":"user","order":{"_key":"asc"},"size":100}}`,
		`"m5":{"terms":{"field":"user","size":1}}`,
		`"m6":{"aggs":{"h":{"top_hits":{"_source":{"includes":["user"]},"size":100,"sort":[{"@timestamp":{"order":"desc","unmapped_type":"date"}}]}}},"filter":{"exists":{"field":"user"}}}`,
		`"order":"asc"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("aggs missing %s\nin %s", want, got)
		}
	}
}

func TestStatsFunctionsReadOpenSearchResults(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":4}},"aggregations":{
		"m0":{"values":[{"key":50.0,"value":20}]},
		"m1":{"values":[{"key":95.0,"value":97.5}]},
		"m2":{"count":4,"variance":2.0},
		"m3":{"min":3,"max":10},
		"m4":{"buckets":[{"key":"amy","doc_count":1},{"key":"bob","doc_count":3}]},
		"m5":{"buckets":[{"key":"bob","doc_count":3}]},
		"m6":{"doc_count":2,"h":{"hits":{"hits":[{"_source":{"user":"bob"}},{"_source":{"user":"amy"}}]}}},
		"m7":{"doc_count":2,"h":{"hits":{"hits":[{"_source":{"src":{"ip":"10.0.0.1"}}}]}}},
		"m8":{"doc_count":0,"h":{"hits":{"hits":[]}}}}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `* | stats median(bytes), p95(bytes) as slow, var(bytes), range(bytes), values(user), mode(user), list(user), latest(src.ip), last(x)`)
	if err != nil {
		t.Fatal(err)
	}
	want := Row{
		"median(bytes)": int64(20), "slow": 97.5, "var(bytes)": 2.6666666666666665, "range(bytes)": int64(7),
		"values(user)": []any{"amy", "bob"}, "mode(user)": "bob", "list(user)": []any{"bob", "amy"},
		"latest(src.ip)": "10.0.0.1", "last(x)": nil,
	}
	if !reflect.DeepEqual(res.Rows[0], want) {
		t.Errorf("row = %#v\nwant %#v", res.Rows[0], want)
	}
	if res.Columns[1] != "slow" {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestStatsFunctionsInMemory(t *testing.T) {
	rows := []Row{
		{"_time": "2026-10-11T10:00:00Z", "g": "a", "n": int64(1), "u": "bob"},
		{"_time": "2026-10-11T08:00:00Z", "g": "a", "n": int64(2), "u": "amy"},
		{"_time": "2026-10-11T09:00:00Z", "g": "a", "n": int64(3), "u": "bob"},
		{"_time": "2026-10-11T07:00:00Z", "g": "a", "n": int64(10), "u": "cat"},
	}
	q, err := query.Parse(`* | stats median(n), perc75(n), stdev(n), range(n), values(u), mode(u), list(u), first(u), last(u), earliest(u), latest(u), dc(u) by g`)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := goStats(context.Background(), rows, q.Commands[0].(*query.Stats))
	if err != nil {
		t.Fatal(err)
	}
	want := Row{
		"g": "a", "median(n)": 2.5, "perc75(n)": 4.75, "stdev(n)": 4.08248290463863, "range(n)": int64(9),
		"values(u)": []any{"amy", "bob", "cat"}, "mode(u)": "bob", "list(u)": []any{"bob", "amy", "bob", "cat"},
		"first(u)": "bob", "last(u)": "cat", "earliest(u)": "cat", "latest(u)": "bob", "dc(u)": int64(3),
	}
	if !reflect.DeepEqual(out[0], want) {
		t.Errorf("row = %#v\nwant %#v", out[0], want)
	}
}

func TestPercentileNames(t *testing.T) {
	for in, want := range map[string]int{"perc95": 95, "p95": 95, "perc1": 1, "p99": 99, "perc0": 0, "perc100": 0, "perc": 0, "pct": 0, "p05": 0} {
		if got := query.Percentile(in); got != want {
			t.Errorf("Percentile(%q) = %d, want %d", in, got, want)
		}
	}
}
