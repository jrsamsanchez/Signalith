package search

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// fakeStore returns canned responses in order and records requests.
type fakeStore struct {
	responses []string
	indexes   []string
	bodies    []map[string]any
}

func (f *fakeStore) Search(_ context.Context, index string, body map[string]any) (map[string]any, error) {
	f.indexes = append(f.indexes, index)
	f.bodies = append(f.bodies, body)
	raw := f.responses[0]
	if len(f.responses) > 1 {
		f.responses = f.responses[1:]
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		panic(err)
	}
	return out, nil
}

func compile(t *testing.T, src string) *Plan {
	t.Helper()
	q, err := query.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Opt: Options{DefaultEarliest: "-24h"}}
	p, err := e.Compile(q)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func asJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSpace(buf.String())
}

func TestCompileSearch(t *testing.T) {
	p := compile(t, `datamodel=Authentication action=failure user=adm* NOT src=10.0.0.1 dest_port>=1024 "failed password" earliest=-7d@d`)
	if p.Index != "signalith-authentication-*" {
		t.Errorf("index = %s", p.Index)
	}
	got := asJSON(p.Body["query"])
	for _, want := range []string{
		`{"term":{"action":{"case_insensitive":true,"value":"failure"}}}`,
		`{"wildcard":{"user":{"case_insensitive":true,"value":"adm*"}}}`,
		`{"bool":{"must_not":[{"term":{"src":{"case_insensitive":true,"value":"10.0.0.1"}}}]}}`,
		`{"range":{"dest_port":{"gte":1024}}}`,
		`{"match_phrase":{"message":"failed password"}}`,
		`{"range":{"@timestamp":{"gte":"now-7d/d"}}}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("query missing %s\nin %s", want, got)
		}
	}
	if p.Mode != "events" || p.Body["size"] != 100 {
		t.Errorf("mode=%s size=%v", p.Mode, p.Body["size"])
	}
}

func TestWildcardEscapesBackslash(t *testing.T) {
	p := compile(t, `process_path="*\\powershell.exe"`)
	got := asJSON(p.Body["query"])
	if !strings.Contains(got, `"value":"*\\\\powershell.exe"`) {
		t.Errorf("backslash not escaped: %s", got)
	}
}

func TestCompilePushesLeadingWhereIntoOpenSearch(t *testing.T) {
	p := compile(t, `* | where bytes > 100 | stats sum(bytes) by src`)
	got := asJSON(p.Body["query"])
	if !strings.Contains(got, `{"range":{"bytes":{"gt":100}}}`) {
		t.Errorf("where not pushed down: %s", got)
	}
	if len(p.post) != 0 {
		t.Errorf("post = %v", p.post)
	}
}

func TestToDateMath(t *testing.T) {
	cases := map[string]string{
		"-24h":                 "now-24h",
		"-7d@d":                "now-7d/d",
		"@w":                   "now/w",
		"now":                  "now",
		"-1mon":                "now-1M",
		"-15minutes":           "now-15m",
		"2026-10-01T00:00:00Z": "2026-10-01T00:00:00Z",
		"1700000000000":        "1700000000000",
	}
	for in, want := range cases {
		if got := toDateMath(in); got != want {
			t.Errorf("toDateMath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatsByRunsCompositeAndPages(t *testing.T) {
	fs := &fakeStore{responses: []string{
		`{"hits":{"total":{"value":40}},"aggregations":{"groups":{"after_key":{"k0":"b"},"buckets":[
			{"key":{"k0":"a"},"doc_count":30,"m1":{"value":3}},
			{"key":{"k0":"b"},"doc_count":5,"m1":{"value":1}}]}}}`,
		`{"hits":{"total":{"value":40}},"aggregations":{"groups":{"after_key":{"k0":"c"},"buckets":[
			{"key":{"k0":"c"},"doc_count":5,"m1":{"value":2}}]}}}`,
		`{"hits":{"total":{"value":40}},"aggregations":{"groups":{"buckets":[]}}}`,
	}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `datamodel=Authentication | stats count, dc(user) as users by src | where count > 4 | sort -users | head 2`)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.bodies) != 3 {
		t.Fatalf("pages fetched = %d", len(fs.bodies))
	}
	comp := fs.bodies[1]["aggs"].(map[string]any)["groups"].(map[string]any)["composite"].(map[string]any)
	if !reflect.DeepEqual(comp["after"], map[string]any{"k0": "b"}) {
		t.Errorf("second page after = %v", comp["after"])
	}
	if !reflect.DeepEqual(res.Columns, []string{"src", "count", "users"}) {
		t.Errorf("columns = %v", res.Columns)
	}
	want := []Row{
		{"src": "a", "count": int64(30), "users": int64(3)},
		{"src": "c", "count": int64(5), "users": int64(2)},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	if res.Matched != 40 {
		t.Errorf("matched = %d", res.Matched)
	}
}

func TestStatsWithoutBy(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":12}},"aggregations":{"m1":{"value":2048.5}}}`}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `* | stats count, avg(bytes)`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{{"count": int64(12), "avg(bytes)": 2048.5}}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestEventsFlattenAndPostProcess(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":3},"hits":[
		{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"bob","src":{"ip":"1.1.1.1"},"bytes":10,"message":"x"}},
		{"_source":{"@timestamp":"2026-10-11T09:00:00Z","user":"amy","src":{"ip":"2.2.2.2"},"bytes":300,"message":"y"}},
		{"_source":{"@timestamp":"2026-10-11T08:00:00Z","user":"cat","src":{"ip":"3.3.3.3"},"bytes":50,"message":"z"}}]}}`}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `* | where bytes >= 50 | sort user | table user, src.ip`)
	if err != nil {
		t.Fatal(err)
	}
	// where before the first transform runs in OpenSearch, so the fake
	// returns all three; only the in-memory sort and table apply here.
	if fs.bodies[0]["size"] != 10000 {
		t.Errorf("size = %v, want MaxEvents for a sort", fs.bodies[0]["size"])
	}
	want := []Row{{"user": "amy", "src.ip": "2.2.2.2"}, {"user": "bob", "src.ip": "1.1.1.1"}, {"user": "cat", "src.ip": "3.3.3.3"}}
	if !reflect.DeepEqual(res.Rows, want) || res.Kind != "table" {
		t.Errorf("rows = %v kind=%s", res.Rows, res.Kind)
	}
}

func TestEventColumnsOrder(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":1},"hits":[
		{"_source":{"@timestamp":"t","zeta":1,"alpha":2,"message":"r"}}]}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `*`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Columns, []string{"_time", "alpha", "zeta", "_raw"}) {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestTimechartByPivotsColumns(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":9}},"aggregations":{"time":{"buckets":[
		{"key_as_string":"2026-10-11T00:00:00.000Z","doc_count":4,"by":{"buckets":[{"key":"failure","doc_count":3},{"key":"success","doc_count":1}]}},
		{"key_as_string":"2026-10-11T01:00:00.000Z","doc_count":5,"by":{"buckets":[{"key":"success","doc_count":5}]}}]}}}`}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `* earliest=-24h | timechart span=1h count by action`)
	if err != nil {
		t.Fatal(err)
	}
	hist := fs.bodies[0]["aggs"].(map[string]any)["time"].(map[string]any)["date_histogram"].(map[string]any)
	if hist["fixed_interval"] != "1h" {
		t.Errorf("interval = %v", hist)
	}
	if !reflect.DeepEqual(res.Columns, []string{"_time", "success", "failure"}) {
		t.Errorf("columns = %v", res.Columns)
	}
	if res.Rows[1]["failure"] != int64(0) {
		t.Errorf("missing value should be 0, got %v", res.Rows[1]["failure"])
	}
}

func TestTopComputesPercent(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":10}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"a"},"doc_count":2},{"key":{"k0":"b"},"doc_count":6},{"key":{"k0":"c"},"doc_count":2}]}}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `* | top limit=2 user`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["user"] != "b" || res.Rows[0]["percent"] != 60.0 {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestGoStatsAfterStats(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":10}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"a","k1":"x"},"doc_count":2},{"key":{"k0":"a","k1":"y"},"doc_count":6},{"key":{"k0":"b","k1":"x"},"doc_count":2}]}}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `* | stats count by src, dest | stats dc(dest) as dests, sum(count) as total by src`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{{"src": "a", "dests": int64(2), "total": int64(8)}, {"src": "b", "dests": int64(1), "total": int64(2)}}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestAutoSpan(t *testing.T) {
	if autoSpan("-24h") != "30m" || autoSpan("-7d") != "3h" || autoSpan("-60m") != "1m" || autoSpan("") != "1h" {
		t.Error("autoSpan mismatch")
	}
}

func TestWhereWildcardAndIn(t *testing.T) {
	r := Row{"user": "Administrator", "path": "/usr/bin/sudo", "n": int64(5)}
	for src, want := range map[string]bool{
		`* | where user=admin*`:            true,
		`* | where path=*bin*`:             true,
		`* | where n IN (1, 5)`:            true,
		`* | where n > 10 OR user!=bob`:    true,
		`* | where NOT (n > 1 AND n < 10)`: false,
		`* | where missing=1`:              false,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := (&matcher{}).eval(q.Commands[0].(*query.Where).Expr, r); got != want {
			t.Errorf("%s = %v, want %v", src, got, want)
		}
	}
}

func TestEnrichAddsAssetAndIdentityContext(t *testing.T) {
	a, _ := assets.NewStore("")
	if _, err := a.SetAssets([]byte("host,owner,priority,category\nDC01,it-ops,critical,dc|pci\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetIdentities([]byte("identity,name,priority,watchlist\nbob,Bob Smith,high,true\n")); err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":3},"hits":[
		{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"bob","dest":"DC01","message":"x"}},
		{"_source":{"@timestamp":"2026-10-11T09:00:00Z","user":"bob","dest":"WS9","message":"y"}},
		{"_source":{"@timestamp":"2026-10-11T08:00:00Z","user":"amy","dest":"dc01.corp.local","message":"z"}}]}}`}}
	e := &Engine{Store: fs, Assets: a}
	res, err := e.Run(context.Background(), `* | enrich | where dest_priority="critical" | stats count, dc(user) as users by dest_owner`)
	if err != nil {
		t.Fatal(err)
	}
	// DC01 and dc01.corp.local are the same asset; WS9 is unknown.
	if len(res.Rows) != 1 || res.Rows[0]["dest_owner"] != "it-ops" || res.Rows[0]["count"] != int64(2) || res.Rows[0]["users"] != int64(2) {
		t.Errorf("rows = %v", res.Rows)
	}
	if fs.bodies[0]["size"] != 10000 {
		t.Errorf("enrich before stats must fetch all events, size = %v", fs.bodies[0]["size"])
	}

	fs = &fakeStore{responses: []string{`{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"bob","dest":"DC01","message":"x"}}]}}`}}
	e = &Engine{Store: fs, Assets: a}
	res, err = e.Run(context.Background(), `* | enrich user | table user, user_watchlist, dest_owner`)
	if err != nil || res.Rows[0]["user_watchlist"] != "true" || res.Rows[0]["dest_owner"] != nil {
		t.Errorf("enrich user = %v %v", res.Rows, err)
	}
	if _, err := (&Engine{Store: fs}).Run(context.Background(), `* | enrich`); err == nil {
		t.Error("enrich without lists should explain it is not configured")
	}
}

func TestDefaultPatternExcludesRisk(t *testing.T) {
	e := &Engine{Opt: Options{IndexPrefix: "sig"}}
	if got, err := e.IndexPattern(&query.Query{}); got != "sig-*,-sig-risk-*" || err != nil {
		t.Errorf("pattern = %s %v", got, err)
	}
	if got, err := e.IndexPattern(&query.Query{Datamodel: "Risk"}); got != "sig-risk-*" || err != nil {
		t.Errorf("risk pattern = %s %v", got, err)
	}
}

func TestCIDRValues(t *testing.T) {
	cases := map[string]string{
		"src=10.0.0.0/8":     `{"prefix":{"src":{"value":"10."}}}`,
		"src=203.0.113.0/24": `{"prefix":{"src":{"value":"203.0.113."}}}`,
		"src=192.168.4.0/23": `{"regexp":{"src":{"value":"192\\.168\\.(4|5)\\..*"}}}`,
		"src=10.0.0.9/31":    `{"regexp":{"src":{"value":"10\\.0\\.0\\.(8|9)"}}}`,
		"src=172.16.0.0/12":  `{"regexp":{"src":{"value":"172\\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\\..*"}}}`,
		"src=10.1.2.3/32":    `{"term":{"src":{"value":"10.1.2.3"}}}`,
	}
	for in, want := range cases {
		c := &query.Compare{Field: "src", Op: "=", Value: strings.TrimPrefix(in, "src=")}
		got, err := compareQuery(c)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if string(b) != want {
			t.Errorf("%s\n got %s\nwant %s", in, b, want)
		}
	}
}

// "All time" on the Search page sends earliest 0, which no default time
// range replaces; only a search sent without one gets the default.
func TestAllTimeIsNotTheDefault(t *testing.T) {
	e := &Engine{Opt: Options{DefaultEarliest: "-15m"}}
	for earliest, want := range map[string]bool{"0": false, "": true, "-1h": true} {
		q, err := query.Parse("*")
		if err != nil {
			t.Fatal(err)
		}
		q.Earliest = earliest
		p, err := e.Compile(q)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(asJSON(p.Body["query"]), `"@timestamp"`); got != want {
			t.Errorf("earliest %q: time range %v, want %v: %s", earliest, got, want, asJSON(p.Body["query"]))
		}
	}
}
