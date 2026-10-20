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
	"time"
)

func TestChartXYSeriesUntable(t *testing.T) {
	const events = `{"hits":{"total":{"value":5},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","host":"h1","action":"allow","bytes":10}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","host":"h1","action":"deny","bytes":20}},
	{"_source":{"@timestamp":"2026-10-15T09:00:00Z","host":"h2","action":"allow","bytes":30}},
	{"_source":{"@timestamp":"2026-10-15T08:00:00Z","host":"h2","action":"allow","bytes":40}},
	{"_source":{"@timestamp":"2026-10-15T07:00:00Z","host":"h3","action":"drop","bytes":50}}]}}`
	run := func(src string) *Result {
		t.Helper()
		e := &Engine{Store: &fakeStore{responses: []string{events}}}
		res, err := e.Run(context.Background(), src)
		if err != nil {
			t.Fatalf("Run(%q): %v", src, err)
		}
		return res
	}
	res := run(`* | head 100 | chart count over host by action`)
	if want := []string{"host", "allow", "deny", "drop"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	var got []string
	for _, r := range res.Rows {
		got = append(got, fmt.Sprintln(r["host"], r["allow"], r["deny"], r["drop"]))
	}
	if want := []string{"h1 1 1 <nil>\n", "h2 2 <nil> <nil>\n", "h3 <nil> <nil> 1\n"}; !reflect.DeepEqual(got, want) {
		t.Errorf("chart rows = %v", got)
	}

	// limit= keeps the split values with the largest totals.
	res = run(`* | head 100 | chart limit=1 sum(bytes) by host, action`)
	if want := []string{"host", "allow"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("limit columns = %v", res.Columns)
	}

	res = run(`* | head 100 | stats count, sum(bytes) as b by host, action | xyseries host action count b`)
	if !strings.Contains(strings.Join(res.Columns, ","), "count: allow") || res.Rows[0]["b: deny"] == nil {
		t.Errorf("xyseries = %v %v", res.Columns, res.Rows)
	}

	res = run(`* | head 100 | chart count over host by action | untable host action count`)
	got = nil
	for _, r := range res.Rows {
		got = append(got, fmt.Sprintln(r["host"], r["action"], r["count"]))
	}
	if want := []string{"h1 allow 1\n", "h1 deny 1\n", "h2 allow 2\n", "h3 drop 1\n"}; !reflect.DeepEqual(got, want) {
		t.Errorf("untable = %v", got)
	}
}

func TestChartRunsInOpenSearch(t *testing.T) {
	p := compile(t, `* | chart count over host by action`)
	if p.Mode != "stats" || !strings.Contains(asJSON(p.Body), `"composite"`) {
		t.Errorf("plan = %s %s", p.Mode, asJSON(p.Body))
	}
}

func TestTstatsCompiles(t *testing.T) {
	p := compile(t, `| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest`)
	if p.Mode != "stats" || !namesDays(p.Index, "signalith-endpoint-") || !strings.Contains(asJSON(p.Body), `"process_name"`) {
		t.Errorf("plan = %s %s %s", p.Mode, p.Index, asJSON(p.Body))
	}
}

func TestTstatsFillnullValue(t *testing.T) {
	// Events without a by field group under the fill value, in OpenSearch.
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":3}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"amy"},"doc_count":2},{"key":{"k0":null},"doc_count":1}]}}}`}}
	e := &Engine{Store: fs}
	got := runRows(t, e, `| tstats fillnull_value=unknown count from datamodel=Web by Web.user`, "Web.user", "count")
	if !reflect.DeepEqual(got, []string{"amy 2", "unknown 1"}) {
		t.Errorf("rows = %v", got)
	}
	if !strings.Contains(asJSON(fs.bodies[0]), `"missing_bucket":true`) {
		t.Errorf("body = %s", asJSON(fs.bodies[0]))
	}
	// A fillnull of other fields stays in memory.
	if p := compile(t, `* | fillnull value=x host | stats count by user`); p.Mode == "stats" {
		t.Errorf("fillnull of a non-by field ran in OpenSearch: %s", asJSON(p.Body))
	}
}

func TestSpath(t *testing.T) {
	const events = `{"hits":{"total":{"value":2},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","message":"{\"actor\":{\"user\":\"amy\",\"roles\":[\"admin\",\"dev\"]},\"items\":[{\"id\":1},{\"id\":2}],\"ok\":true,\"n\":null}"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","message":"not json"}}]}}`
	for src, want := range map[string]map[string]any{
		`* | spath`:                            {"actor.user": "amy", "actor.roles{}": []any{"admin", "dev"}, "items{}.id": []any{int64(1), int64(2)}, "ok": "true"},
		`* | spath output=who path=actor.user`: {"who": "amy"},
		`* | spath path=items{}.id`:            {"items{}.id": []any{int64(1), int64(2)}},
		`* | spath path=actor`:                 {"actor": `{"roles":["admin","dev"],"user":"amy"}`},
	} {
		e := &Engine{Store: &fakeStore{responses: []string{events}}}
		res, err := e.Run(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		for k, v := range want {
			if got := res.Rows[0][k]; !reflect.DeepEqual(got, v) {
				t.Errorf("%s: %s = %#v, want %#v", src, k, got, v)
			}
		}
		if _, ok := res.Rows[0]["n"]; ok {
			t.Errorf("%s: null became a field", src)
		}
		if len(res.Rows[1]) > 3 {
			t.Errorf("%s: non-JSON row = %v", src, res.Rows[1])
		}
	}
}

func TestSpathCountsAgainstTheBudget(t *testing.T) {
	// 10 events of 600 KB, extracted 50 times: past the search's 256 MB.
	var b strings.Builder
	b.WriteString(`{"hits":{"total":{"value":10},"hits":[`)
	for i := range 10 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"_source":{"@timestamp":"2026-10-15T10:00:00Z","message":"{\"a\":\"` + strings.Repeat("x", 600<<10) + `\"}"}}`)
	}
	b.WriteString(`]}}`)
	src := "*"
	for i := range 50 {
		src += fmt.Sprintf(" | spath output=a%d path=a", i)
	}
	e := &Engine{Store: &fakeStore{responses: []string{b.String()}}}
	_, err := e.Run(context.Background(), src)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Errorf("err = %v", err)
	}
}

func TestSpathCapsFieldNames(t *testing.T) {
	// Every row has 100 keys of its own: 300,000 names in all.
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf(`\"k%dQN\":1`, i)
	}
	src := `| makeresults count=3000 | streamstats count as n | eval j=replace("{` + strings.Join(keys, ",") + `}", "QN", tostring(n)) | spath input=j`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (&Engine{}).Run(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Columns) > maxSpathNames+10 {
		t.Errorf("truncated = %v, %d columns", res.Truncated, len(res.Columns))
	}
}
