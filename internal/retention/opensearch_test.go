// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// scripted is a Doer that answers each "METHOD path" (the query left out
// unless the script names one with it) from a script, and records the
// requests and their bodies.
type scripted struct {
	mu     sync.Mutex
	script map[string][]answer // consumed in order; the last one repeats
	calls  []string
	bodies map[string]any
}

type answer struct {
	body string
	err  error
}

func ok(body string) answer { return answer{body: body} }
func fail(err error) answer { return answer{err: err} }
func status(n int) answer {
	return answer{err: &store.Error{Status: n, Body: `{"error":{"type":"x","reason":"y"}}`}}
}
func statusBody(n int, b string) answer { return answer{err: &store.Error{Status: n, Body: b}} }

func newScripted(script map[string][]answer) *scripted {
	return &scripted{script: script, bodies: map[string]any{}}
}

func (s *scripted) Do(_ context.Context, method, path string, body any, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	full := method + " " + path
	s.calls = append(s.calls, full)
	if body != nil {
		if b, ok := body.([]byte); ok {
			s.bodies[full] = string(b)
		} else {
			raw, _ := json.Marshal(body)
			var v any
			_ = json.Unmarshal(raw, &v)
			s.bodies[full] = v
		}
	}
	key := full
	as, found := s.script[key]
	if !found {
		short, _, _ := strings.Cut(full, "?")
		key = short
		as, found = s.script[key]
	}
	if !found {
		return fmt.Errorf("scripted: unexpected %s", full)
	}
	a := as[0]
	if len(as) > 1 {
		s.script[key] = as[1:]
	}
	if a.err != nil {
		return a.err
	}
	if out != nil && a.body != "" {
		return json.Unmarshal([]byte(a.body), out)
	}
	return nil
}

func (s *scripted) called(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (s *scripted) body(prefix string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.bodies {
		if strings.HasPrefix(k, prefix) {
			return v
		}
	}
	return nil
}

func TestOpenSearchIndices(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{
		"GET /_cat/indices/sig-%2A": {ok(`[
			{"index":"sig-authentication-2026.01.02","uuid":"u1","health":"green","pri":"2","rep":"1","docs.count":"10","store.size":"400","pri.store.size":"200","segments.count":"4"},
			{"index":"sig-network_traffic-2026.01.02","uuid":"u2","health":"red","pri":"1","rep":"0","docs.count":null,"store.size":null},
			{"index":"sig-endpoint-2026.01.02","uuid":"u3","health":"green","pri":"1","rep":"0","docs.count":"1","store.size":"5"}
		]`)},
		"GET /sig-%2A/_settings/index.blocks.*,index.store.type,index.searchable_snapshot.*": {ok(`{
			"sig-authentication-2026.01.02":{"settings":{"index.blocks.write":"true"}},
			"sig-network_traffic-2026.01.02":{"settings":{"index.blocks.read_only_allow_delete":"true"}},
			"sig-endpoint-2026.01.02":{"settings":{"index.store.type":"remote_snapshot","index.searchable_snapshot.repository":"sig-cold","index.searchable_snapshot.snapshot_id.name":"snap1"}},
			"other":{"settings":{}}
		}`)},
		"GET /sig-%2A/_mapping": {ok(`{
			"sig-authentication-2026.01.02":{"mappings":{"_meta":{"signalith":{"restored_until":"2026-02-01","restored_from":["a1","a2"]}}}},
			"gone":{"mappings":{}}
		}`)},
	})
	o := NewOpenSearch(s)
	got, err := o.Indices(ctx, "sig-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d indices", len(got))
	}
	a := got[0]
	if a.Name != "sig-authentication-2026.01.02" || a.UUID != "u1" || a.Docs != 10 || a.Bytes != 400 || a.PrimaryBytes != 200 ||
		a.Segments != 4 || a.Copies != 4 || !a.WriteBlocked || a.DiskBlocked || a.Unavailable ||
		a.RestoredUntil != "2026-02-01" || !slices.Equal(a.RestoredFrom, []string{"a1", "a2"}) || a.Cold != nil {
		t.Errorf("authentication = %+v", a)
	}
	if n := got[1]; !n.Unavailable || !n.DiskBlocked || n.WriteBlocked {
		t.Errorf("red index = %+v", n)
	}
	if e := got[2]; e.Cold == nil || e.Cold.Repository != "sig-cold" || e.Cold.Snapshot != "snap1" || e.Unavailable {
		t.Errorf("cold index = %+v", e)
	}

	// No index: no error, and nothing else asked.
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {status(404)}})
	if got, err := NewOpenSearch(s).Indices(ctx, "x"); err != nil || got != nil || len(s.calls) != 1 {
		t.Errorf("not found: %v %v %v", got, err, s.calls)
	}
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {ok(`[]`)}})
	if got, err := NewOpenSearch(s).Indices(ctx, "x"); err != nil || len(got) != 0 || len(s.calls) != 1 {
		t.Errorf("empty: %v %v", got, err)
	}
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {fail(errors.New("down"))}})
	if _, err := NewOpenSearch(s).Indices(ctx, "x"); err == nil {
		t.Error("cat error ignored")
	}
	one := `[{"index":"x","docs.count":"1"}]`
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {ok(one)}, "GET /x/_settings/index.blocks.*,index.store.type,index.searchable_snapshot.*": {fail(errors.New("settings down"))}})
	if _, err := NewOpenSearch(s).Indices(ctx, "x"); err == nil || !strings.Contains(err.Error(), "settings down") {
		t.Errorf("settings error: %v", err)
	}
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {ok(one)},
		"GET /x/_settings/index.blocks.*,index.store.type,index.searchable_snapshot.*": {status(404)},
		"GET /x/_mapping": {fail(errors.New("mapping down"))}})
	if _, err := NewOpenSearch(s).Indices(ctx, "x"); err == nil || !strings.Contains(err.Error(), "mapping down") {
		t.Errorf("mapping error: %v", err)
	}
	s = newScripted(map[string][]answer{"GET /_cat/indices/x": {ok(one)},
		"GET /x/_settings/index.blocks.*,index.store.type,index.searchable_snapshot.*": {status(404)},
		"GET /x/_mapping": {status(404)}})
	if got, err := NewOpenSearch(s).Indices(ctx, "x"); err != nil || len(got) != 1 || got[0].Docs != 1 {
		t.Errorf("index gone between requests: %v %v", got, err)
	}
}

func TestOpenSearchDisk(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{"GET /_nodes/stats/fs": {ok(`{"nodes":{
		"n1":{"name":"one","roles":["data","ingest"],"fs":{"data":[{"path":"/a","total_in_bytes":100,"available_in_bytes":50},{"path":"/b","total_in_bytes":100,"available_in_bytes":10}]}},
		"n2":{"name":"two","roles":["cluster_manager"],"fs":{"data":[{"path":"/c","total_in_bytes":100,"available_in_bytes":1}]}},
		"n3":{"name":"three","roles":[],"fs":{"total":{"path":"/d","total_in_bytes":100,"available_in_bytes":20}}},
		"n4":{"name":"four","roles":["data_hot"],"fs":{"data":[{"path":"/e","total_in_bytes":0,"available_in_bytes":0}]}}
	}}`)}})
	d, err := NewOpenSearch(s).Disk(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Node != "one" || d.Path != "/b" || d.Percent() != 90 {
		t.Errorf("worst disk = %+v", d)
	}
	b, err := json.Marshal(*d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["used_bytes"] != 90.0 || m["percent"] != 90.0 || m["node"] != "one" || m["total_bytes"] != 100.0 {
		t.Errorf("disk JSON = %s", b)
	}
	if (Disk{}).Percent() != 0 {
		t.Error("an empty disk is in use")
	}

	s = newScripted(map[string][]answer{"GET /_nodes/stats/fs": {ok(`{"nodes":{"n2":{"name":"m","roles":["master"]}}}`)}})
	if _, err := NewOpenSearch(s).Disk(ctx); err == nil || !strings.Contains(err.Error(), "no data disks") {
		t.Errorf("no data node: %v", err)
	}
	s = newScripted(map[string][]answer{"GET /_nodes/stats/fs": {fail(errors.New("down"))}})
	if _, err := NewOpenSearch(s).Disk(ctx); err == nil {
		t.Error("error ignored")
	}
}

func TestOpenSearchNodeBytes(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{"GET /_cat/shards/sig-%2A": {ok(`[
		{"index":"a","node":"one","store":"10"},{"index":"a","node":"one","store":"5"},
		{"index":"a","node":"two","store":"100"},{"index":"b","node":"one","store":null},
		{"index":"c","node":null,"store":"7"},{"index":null,"node":"one"}
	]`)}})
	got, err := NewOpenSearch(s).NodeBytes(ctx, "sig-*", "one")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["a"] != 15 || got["b"] != 0 {
		t.Errorf("NodeBytes = %v", got)
	}
	s = newScripted(map[string][]answer{"GET /_cat/shards/x": {status(404)}})
	if got, err := NewOpenSearch(s).NodeBytes(ctx, "x", "one"); err != nil || len(got) != 0 {
		t.Errorf("not found: %v %v", got, err)
	}
	s = newScripted(map[string][]answer{"GET /_cat/shards/x": {status(500)}})
	if _, err := NewOpenSearch(s).NodeBytes(ctx, "x", "one"); err == nil {
		t.Error("error ignored")
	}
}

func TestOpenSearchSimpleCalls(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{
		"PUT /ix/_settings":           {ok(``)},
		"DELETE /ix":                  {ok(``), status(404), status(500)},
		"GET /ix/_count":              {ok(`{"count":42}`)},
		"PUT /ix":                     {ok(``), statusBody(400, `{"error":{"type":"resource_already_exists_exception"}}`), status(400)},
		"PUT /ix/_mapping":            {ok(``)},
		"POST /ix/_refresh":           {ok(``)},
		"DELETE /_snapshot/repo/snap": {ok(``), status(404), status(500)},
	})
	o := NewOpenSearch(s)
	if err := o.BlockWrites(ctx, "ix", true); err != nil {
		t.Fatal(err)
	}
	if got := s.body("PUT /ix/_settings"); !jsonEqual(got, map[string]any{"index.blocks.write": true}) {
		t.Errorf("block body = %v", got)
	}
	if err := o.BlockWrites(ctx, "ix", false); err != nil {
		t.Fatal(err)
	}
	if got := s.body("PUT /ix/_settings"); !jsonEqual(got, map[string]any{"index.blocks.write": nil}) {
		t.Errorf("unblock body = %v", got)
	}
	for i, wantErr := range []bool{false, false, true} {
		if err := o.DeleteIndex(ctx, "ix"); (err != nil) != wantErr {
			t.Errorf("DeleteIndex %d: %v", i, err)
		}
	}
	if n, err := o.Count(ctx, "ix"); err != nil || n != 42 {
		t.Errorf("Count = %d, %v", n, err)
	}
	for i, wantErr := range []bool{false, false, true} {
		if err := o.CreateIndex(ctx, "ix"); (err != nil) != wantErr {
			t.Errorf("CreateIndex %d: %v", i, err)
		}
	}
	if err := o.MarkRestored(ctx, "ix", "2026-02-01", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"_meta": map[string]any{"signalith": map[string]any{"restored_until": "2026-02-01", "restored_from": []any{"a"}}}}
	if got := s.body("PUT /ix/_mapping"); !jsonEqual(got, want) {
		t.Errorf("mapping body = %v", got)
	}
	if err := o.Refresh(ctx, "ix"); err != nil {
		t.Fatal(err)
	}
	for i, wantErr := range []bool{false, false, true} {
		if err := o.DeleteSnapshot(ctx, "repo", "snap"); (err != nil) != wantErr {
			t.Errorf("DeleteSnapshot %d: %v", i, err)
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestOpenSearchForceMergeWaitsForTheTask(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{
		"POST /ix/_forcemerge": {ok(`{"task":"node:1"}`)},
		"GET /_tasks/node:1":   {ok(`{"completed":false}`), ok(`{"completed":true,"response":{}}`)},
		"POST /ix/_refresh":    {ok(``)},
	})
	o := &OpenSearch{Client: s, Poll: time.Millisecond}
	if err := o.ForceMerge(ctx, "ix"); err != nil {
		t.Fatal(err)
	}
	if n := s.called("GET /_tasks/"); n != 2 {
		t.Errorf("task checked %d times", n)
	}
	if s.called("POST /ix/_refresh") != 1 {
		t.Error("no refresh after the merge")
	}

	// A merge that answers at once has no task to wait for.
	s = newScripted(map[string][]answer{"POST /ix/_forcemerge": {ok(`{}`)}, "POST /ix/_refresh": {ok(``)}})
	if err := (&OpenSearch{Client: s}).ForceMerge(ctx, "ix"); err != nil || s.called("GET /_tasks") != 0 {
		t.Errorf("no task: %v %v", err, s.calls)
	}

	s = newScripted(map[string][]answer{"POST /ix/_forcemerge": {fail(errors.New("refused"))}})
	if err := (&OpenSearch{Client: s}).ForceMerge(ctx, "ix"); err == nil {
		t.Error("merge error ignored")
	}
	s = newScripted(map[string][]answer{
		"POST /ix/_forcemerge": {ok(`{"task":"t"}`)},
		"GET /_tasks/t":        {ok(`{"completed":true,"error":{"type":"oom","reason":"too big"}}`)},
	})
	if err := (&OpenSearch{Client: s}).ForceMerge(ctx, "ix"); err == nil || !strings.Contains(err.Error(), "oom: too big") {
		t.Errorf("task error: %v", err)
	}
	s = newScripted(map[string][]answer{
		"POST /ix/_forcemerge": {ok(`{"task":"t"}`)},
		"GET /_tasks/t":        {fail(errors.New("gone"))},
	})
	if err := (&OpenSearch{Client: s}).ForceMerge(ctx, "ix"); err == nil || !strings.Contains(err.Error(), "checking OpenSearch task t") {
		t.Errorf("task check error: %v", err)
	}
	// A cancelled wait ends.
	s = newScripted(map[string][]answer{"GET /_tasks/t": {ok(`{"completed":false}`)}})
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (&OpenSearch{Client: s}).waitTask(cctx, "t"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait: %v", err)
	}
}

func TestOpenSearchExportScrolls(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{
		"POST /ix/_search?scroll=5m": {ok(`{"_scroll_id":"s1","hits":{"hits":[{"_id":"1","_source":{"a":1}},{"_id":"2","_source":{"a":2}}]}}`)},
		"POST /_search/scroll":       {ok(`{"hits":{"hits":[{"_id":"3","_source":{"a":3}}]}}`), ok(`{"_scroll_id":"s2","hits":{"hits":[]}}`)},
		"DELETE /_search/scroll":     {ok(``)},
	})
	o := &OpenSearch{Client: s, PageSize: 2}
	var ids []string
	if err := o.Export(ctx, "ix", func(d Doc) error { ids = append(ids, d.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []string{"1", "2", "3"}) {
		t.Errorf("exported %v", ids)
	}
	if got := s.body("POST /ix/_search"); !jsonEqual(got, map[string]any{"size": 2, "sort": []any{"_doc"}}) {
		t.Errorf("first page body = %v", got)
	}
	if got := s.body("DELETE /_search/scroll"); !jsonEqual(got, map[string]any{"scroll_id": []any{"s2"}}) {
		t.Errorf("scroll freed with %v", got)
	}

	// The callback's error stops the export, and the scroll is freed.
	s = newScripted(map[string][]answer{
		"POST /ix/_search?scroll=5m": {ok(`{"_scroll_id":"s1","hits":{"hits":[{"_id":"1","_source":{}}]}}`)},
		"DELETE /_search/scroll":     {ok(``)},
	})
	stop := errors.New("stop")
	if err := (&OpenSearch{Client: s}).Export(ctx, "ix", func(Doc) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Export = %v", err)
	}
	if s.called("DELETE /_search/scroll") != 1 {
		t.Error("scroll not freed")
	}
	if got := s.body("POST /ix/_search"); !jsonEqual(got, map[string]any{"size": 500, "sort": []any{"_doc"}}) {
		t.Errorf("default page size: %v", got)
	}

	// A failed next page frees the scroll it had.
	s = newScripted(map[string][]answer{
		"POST /ix/_search?scroll=5m": {ok(`{"_scroll_id":"s1","hits":{"hits":[{"_id":"1","_source":{}}]}}`)},
		"POST /_search/scroll":       {fail(errors.New("page down"))},
		"DELETE /_search/scroll":     {ok(``)},
	})
	if err := (&OpenSearch{Client: s}).Export(ctx, "ix", func(Doc) error { return nil }); err == nil {
		t.Error("page error ignored")
	}
	if got := s.body("DELETE /_search/scroll"); !jsonEqual(got, map[string]any{"scroll_id": []any{"s1"}}) {
		t.Errorf("scroll freed with %v", got)
	}
	s = newScripted(map[string][]answer{"POST /ix/_search?scroll=5m": {fail(errors.New("down"))}})
	if err := (&OpenSearch{Client: s}).Export(ctx, "ix", func(Doc) error { return nil }); err == nil || s.called("DELETE") != 0 {
		t.Errorf("first page error: %v %v", err, s.calls)
	}
}

func TestOpenSearchImport(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{"POST /_bulk": {ok(`{"errors":false}`)}})
	o := NewOpenSearch(s)
	if err := o.Import(ctx, "ix", nil); err != nil || len(s.calls) != 0 {
		t.Errorf("empty import: %v %v", err, s.calls)
	}
	docs := []Doc{{ID: "a", Source: json.RawMessage(`{ "x" : 1 }`)}, {Source: json.RawMessage(`{"y":2}`)}}
	if err := o.Import(ctx, "ix", docs); err != nil {
		t.Fatal(err)
	}
	want := `{"index":{"_id":"a","_index":"ix"}}` + "\n" + `{"x":1}` + "\n" + `{"index":{"_index":"ix"}}` + "\n" + `{"y":2}` + "\n"
	if got := s.body("POST /_bulk"); got != want {
		t.Errorf("bulk body:\n%q\nwant\n%q", got, want)
	}
	if err := o.Import(ctx, "ix", []Doc{{ID: "bad", Source: json.RawMessage(`{`)}}); err == nil || !strings.Contains(err.Error(), "document bad is not valid JSON") {
		t.Errorf("invalid JSON: %v", err)
	}
	s = newScripted(map[string][]answer{"POST /_bulk": {ok(`{"errors":true,"items":[
		{"index":{"_id":"a"}},
		{"index":{"_id":"b","error":{"type":"mapper_parsing_exception","reason":"bad field"}}},
		{"index":{"_id":"c","error":{"type":"other","reason":"x"}}}]}`)}})
	err := NewOpenSearch(s).Import(ctx, "ix", []Doc{{ID: "a", Source: json.RawMessage(`{}`)}, {ID: "b", Source: json.RawMessage(`{}`)}, {ID: "c", Source: json.RawMessage(`{}`)}})
	if err == nil || !strings.Contains(err.Error(), "rejected 2 of 3") || !strings.Contains(err.Error(), "mapper_parsing_exception: bad field") {
		t.Errorf("rejected items: %v", err)
	}
	s = newScripted(map[string][]answer{"POST /_bulk": {fail(errors.New("down"))}})
	if err := NewOpenSearch(s).Import(ctx, "ix", docs); err == nil {
		t.Error("bulk error ignored")
	}
}

func TestOpenSearchClosedRecords(t *testing.T) {
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Hour)
	s := newScripted(map[string][]answer{
		"POST /fx/_count":           {ok(`{"count":7}`), status(404)},
		"POST /fx/_delete_by_query": {ok(`{"task":"t1"}`), status(404), fail(errors.New("down")), ok(`{"task":"t2"}`), ok(`{"task":"t3"}`)},
		"GET /_tasks/t1":            {ok(`{"completed":true,"response":{"deleted":5}}`)},
		"GET /_tasks/t2":            {ok(`{"completed":true,"response":{"deleted":3,"failures":[{"id":"x"}]}}`)},
		"GET /_tasks/t3":            {ok(`{"completed":true,"response":"not an object"}`)},
	})
	o := NewOpenSearch(s)
	if n, err := o.CountClosed(ctx, "fx", before, []string{"c1"}); err != nil || n != 7 {
		t.Errorf("CountClosed = %d, %v", n, err)
	}
	q := s.body("POST /fx/_count").(map[string]any)["query"].(map[string]any)["bool"].(map[string]any)
	if q["must_not"] == nil || len(q["filter"].([]any)) != 2 {
		t.Errorf("query = %v", q)
	}
	if !strings.Contains(fmt.Sprint(q["filter"]), before.Format(time.RFC3339Nano)) {
		t.Errorf("query has no cutoff: %v", q)
	}
	if n, err := o.CountClosed(ctx, "fx", before, nil); err != nil || n != 0 {
		t.Errorf("CountClosed of no index = %d, %v", n, err)
	}
	if q := closedQuery(before, nil)["bool"].(map[string]any); q["must_not"] != nil {
		t.Errorf("must_not without cases: %v", q)
	}
	if n, err := o.DeleteClosed(ctx, "fx", before, nil); err != nil || n != 5 {
		t.Errorf("DeleteClosed = %d, %v", n, err)
	}
	if n, err := o.DeleteClosed(ctx, "fx", before, nil); err != nil || n != 0 {
		t.Errorf("DeleteClosed of no index = %d, %v", n, err)
	}
	if _, err := o.DeleteClosed(ctx, "fx", before, nil); err == nil {
		t.Error("start error ignored")
	}
	if n, err := o.DeleteClosed(ctx, "fx", before, nil); err == nil || n != 3 || !strings.Contains(err.Error(), "1 failures") {
		t.Errorf("failures: %d, %v", n, err)
	}
	if _, err := o.DeleteClosed(ctx, "fx", before, nil); err == nil {
		t.Error("an unreadable task response is accepted")
	}
	s = newScripted(map[string][]answer{"POST /fx/_delete_by_query": {ok(`{"task":"t"}`)}, "GET /_tasks/t": {fail(errors.New("x"))}})
	if _, err := NewOpenSearch(s).DeleteClosed(ctx, "fx", before, nil); err == nil {
		t.Error("task error ignored")
	}
}

func TestOpenSearchCaseIDs(t *testing.T) {
	ctx := context.Background()
	s := newScripted(map[string][]answer{
		"POST /cx/_search?scroll=1m": {ok(`{"_scroll_id":"s","hits":{"hits":[{"_id":"c1"},{"_id":"c2"}]}}`)},
		"POST /_search/scroll":       {ok(`{"hits":{"hits":[{"_id":"c3"}]}}`), ok(`{"hits":{"hits":[]}}`)},
		"DELETE /_search/scroll":     {ok(``)},
	})
	ids, err := NewOpenSearch(s).CaseIDs(ctx, "cx")
	if err != nil || !slices.Equal(ids, []string{"c1", "c2", "c3"}) {
		t.Errorf("CaseIDs = %v, %v", ids, err)
	}
	if s.called("DELETE /_search/scroll") != 1 {
		t.Error("scroll not freed")
	}
	s = newScripted(map[string][]answer{"POST /cx/_search?scroll=1m": {status(404)}})
	if ids, err := NewOpenSearch(s).CaseIDs(ctx, "cx"); err != nil || ids != nil {
		t.Errorf("no index: %v %v", ids, err)
	}
	s = newScripted(map[string][]answer{"POST /cx/_search?scroll=1m": {status(500)}})
	if _, err := NewOpenSearch(s).CaseIDs(ctx, "cx"); err == nil {
		t.Error("error ignored")
	}
	s = newScripted(map[string][]answer{
		"POST /cx/_search?scroll=1m": {ok(`{"_scroll_id":"s","hits":{"hits":[{"_id":"c1"}]}}`)},
		"POST /_search/scroll":       {fail(errors.New("down"))},
		"DELETE /_search/scroll":     {ok(``)},
	})
	if _, err := NewOpenSearch(s).CaseIDs(ctx, "cx"); err == nil || s.called("DELETE /_search/scroll") != 1 {
		t.Errorf("page error: %v, %v", err, s.calls)
	}
	// Too many cases to protect is an error, not a partial list.
	var b strings.Builder
	b.WriteString(`{"_scroll_id":"s","hits":{"hits":[`)
	for i := range maxCaseIDs + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"_id":"c%d"}`, i)
	}
	b.WriteString(`]}}`)
	s = newScripted(map[string][]answer{"POST /cx/_search?scroll=1m": {ok(b.String())}, "DELETE /_search/scroll": {ok(``)}})
	if _, err := NewOpenSearch(s).CaseIDs(ctx, "cx"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too many cases: %v", err)
	}
}

func TestOpenSearchRecordRange(t *testing.T) {
	ctx := context.Background()
	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	nw := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	s := newScripted(map[string][]answer{"POST /fx/_search": {
		ok(fmt.Sprintf(`{"aggregations":{"oldest":{"value":%d},"newest":{"value":%d}}}`, old.UnixMilli(), nw.UnixMilli())),
		ok(`{"aggregations":{"oldest":{"value":null},"newest":{"value":null}}}`),
		status(404), status(500),
	}})
	o := NewOpenSearch(s)
	a, b, err := o.RecordRange(ctx, "fx")
	if err != nil || !a.Equal(old) || !b.Equal(nw) {
		t.Errorf("RecordRange = %v %v %v", a, b, err)
	}
	if a, b, err := o.RecordRange(ctx, "fx"); err != nil || !a.IsZero() || !b.IsZero() {
		t.Errorf("empty = %v %v %v", a, b, err)
	}
	if a, b, err := o.RecordRange(ctx, "fx"); err != nil || !a.IsZero() || !b.IsZero() {
		t.Errorf("no index = %v %v %v", a, b, err)
	}
	if _, _, err := o.RecordRange(ctx, "fx"); err == nil {
		t.Error("error ignored")
	}
}

func TestOpenSearchColdState(t *testing.T) {
	ctx := context.Background()
	warm := `{"nodes":{"a":{"roles":["data"]},"b":{"roles":["warm"]}}}`
	s := newScripted(map[string][]answer{
		"GET /_snapshot/sig-cold": {ok(`{"sig-cold":{"type":"s3"}}`)},
		"GET /_nodes":             {ok(warm)},
		"GET /_snapshot/sig-cold/sig-%2A": {ok(`{"snapshots":[
			{"snapshot":"sig-authentication-2026.01.02.uuid1","state":"SUCCESS","indices":["sig-authentication-2026.01.02"]},
			{"snapshot":"sig-network_traffic-2026.01.02.uuid2","indices":[]},
			{"snapshot":"sig-network_traffic-2026.01.03.uuid3","state":"IN_PROGRESS"},
			{"snapshot":"sig-network_traffic-2026.01.04.uuid4","state":"SUCCESS","indices":["other"]},
			{"snapshot":"sig-bogus.x","state":"SUCCESS"},
			{"snapshot":"nodot","state":"SUCCESS"}
		]}`)},
	})
	st, err := NewOpenSearch(s).ColdState(ctx, "sig-cold", "sig")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Registered || st.Type != "s3" || !st.Mountable || !st.Ready() || st.Missing("sig") != "nothing is missing" {
		t.Errorf("state = %+v", st)
	}
	want := []ColdSnapshot{{Name: "sig-authentication-2026.01.02.uuid1", Index: "sig-authentication-2026.01.02"}, {Name: "sig-network_traffic-2026.01.02.uuid2", Index: "sig-network_traffic-2026.01.02"}}
	if !slices.Equal(st.Snapshots, want) {
		t.Errorf("snapshots = %v", st.Snapshots)
	}

	// Not registered: the snapshots are not listed.
	s = newScripted(map[string][]answer{"GET /_snapshot/sig-cold": {status(404)}, "GET /_nodes": {ok(`{"nodes":{"a":{"roles":["data"]}}}`)}})
	st, err = NewOpenSearch(s).ColdState(ctx, "sig-cold", "sig")
	if err != nil || st.Registered || st.Mountable || st.Ready() || s.called("GET /_snapshot/sig-cold/") != 0 {
		t.Errorf("unregistered = %+v, %v", st, err)
	}
	if !strings.Contains(st.Missing("sig"), "no snapshot repository named sig-cold") {
		t.Errorf("Missing = %q", st.Missing("sig"))
	}
	st.Registered = true
	if !strings.Contains(st.Missing("sig"), "warm role") {
		t.Errorf("Missing = %q", st.Missing("sig"))
	}

	s = newScripted(map[string][]answer{"GET /_snapshot/sig-cold": {status(403)}})
	st, err = NewOpenSearch(s).ColdState(ctx, "sig-cold", "sig")
	if err != nil || !st.Forbidden || !strings.Contains(st.Missing("sig"), "signalith_cold_storage") {
		t.Errorf("forbidden = %+v, %v", st, err)
	}
	var none *ColdState
	if none.Ready() || !strings.Contains(none.Missing("sig"), "could not be asked") {
		t.Error("nil ColdState")
	}

	for name, script := range map[string]map[string][]answer{
		"repository": {"GET /_snapshot/sig-cold": {status(500)}},
		"nodes":      {"GET /_snapshot/sig-cold": {ok(`{}`)}, "GET /_nodes": {status(500)}},
		"snapshots": {"GET /_snapshot/sig-cold": {ok(`{"sig-cold":{"type":"fs"}}`)}, "GET /_nodes": {ok(warm)},
			"GET /_snapshot/sig-cold/sig-%2A": {status(500)}},
	} {
		if _, err := NewOpenSearch(newScripted(script)).ColdState(ctx, "sig-cold", "sig"); err == nil {
			t.Errorf("%s error ignored", name)
		}
	}
	s = newScripted(map[string][]answer{"GET /_snapshot/sig-cold": {ok(`{"sig-cold":{"type":"fs"}}`)}, "GET /_nodes": {ok(warm)},
		"GET /_snapshot/sig-cold/sig-%2A": {status(404)}})
	if st, err := NewOpenSearch(s).ColdState(ctx, "sig-cold", "sig"); err != nil || len(st.Snapshots) != 0 {
		t.Errorf("no snapshots: %+v %v", st, err)
	}
}

func TestOpenSearchSnapshotIndex(t *testing.T) {
	ctx := context.Background()
	const ix = "sig-authentication-2026.01.02"
	path := "GET /_snapshot/repo/snap"
	done := fmt.Sprintf(`{"snapshots":[{"state":"SUCCESS","indices":[%q],"shards":{"total":2,"failed":0}}]}`, ix)
	s := newScripted(map[string][]answer{
		"PUT /_snapshot/repo/snap": {ok(``)},
		path:                       {ok(`{"snapshots":[{"state":"INIT"}]}`), ok(`{"snapshots":[{"state":"IN_PROGRESS"}]}`), ok(done)},
	})
	if err := (&OpenSearch{Client: s, Poll: time.Millisecond}).SnapshotIndex(ctx, "repo", "snap", ix); err != nil {
		t.Fatal(err)
	}
	if got := s.body("PUT /_snapshot/repo/snap"); !jsonEqual(got, map[string]any{"ignore_unavailable": false, "include_global_state": false, "indices": ix, "partial": false}) {
		t.Errorf("snapshot body = %v", got)
	}
	for name, c := range map[string]struct {
		answers []answer
		want    string
	}{
		"failed shards": {[]answer{ok(fmt.Sprintf(`{"snapshots":[{"state":"SUCCESS","indices":[%q],"shards":{"total":2,"failed":1}}]}`, ix))}, "incomplete (1 of 2"},
		"other index":   {[]answer{ok(`{"snapshots":[{"state":"SUCCESS","indices":["x"],"shards":{"total":1}}]}`)}, "incomplete"},
		"failed":        {[]answer{ok(`{"snapshots":[{"state":"FAILED","reason":"no space"}]}`)}, "ended FAILED: no space"},
		"missing":       {[]answer{ok(`{"snapshots":[]}`)}, "did not report"},
		"check error":   {[]answer{fail(errors.New("down"))}, "checking the snapshot: down"},
	} {
		s := newScripted(map[string][]answer{"PUT /_snapshot/repo/snap": {ok(``)}, path: c.answers})
		if err := (&OpenSearch{Client: s, Poll: time.Millisecond}).SnapshotIndex(ctx, "repo", "snap", ix); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	s = newScripted(map[string][]answer{"PUT /_snapshot/repo/snap": {status(500)}})
	if err := NewOpenSearch(s).SnapshotIndex(ctx, "repo", "snap", ix); err == nil {
		t.Error("start error ignored")
	}
	s = newScripted(map[string][]answer{"PUT /_snapshot/repo/snap": {ok(``)}, path: {ok(`{"snapshots":[{"state":"STARTED"}]}`)}})
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := NewOpenSearch(s).SnapshotIndex(cctx, "repo", "snap", ix); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestOpenSearchMountSnapshot(t *testing.T) {
	ctx := context.Background()
	const ix = "sig-authentication-2026.01.02"
	health := "GET /_cluster/health/" + ix
	for name, c := range map[string]struct {
		restore, health answer
		want            string
	}{
		"mounted":       {ok(``), ok(`{"status":"green"}`), ""},
		"restore fails": {status(500), ok(``), "x: y"},
		"health fails":  {ok(``), fail(errors.New("down")), "checking the mounted index"},
		"timed out":     {ok(``), ok(`{"status":"yellow","timed_out":true}`), "within 60 seconds"},
		"red":           {ok(``), ok(`{"status":"red"}`), "within 60 seconds"},
	} {
		s := newScripted(map[string][]answer{"POST /_snapshot/repo/snap/_restore": {c.restore}, health: {c.health}})
		err := NewOpenSearch(s).MountSnapshot(ctx, "repo", "snap", ix)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			b := s.body("POST /_snapshot/repo/snap/_restore").(map[string]any)
			if b["storage_type"] != "remote_snapshot" || b["indices"] != ix {
				t.Errorf("restore body = %v", b)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestColdIndexNames(t *testing.T) {
	for _, c := range []struct {
		name, ix string
		ok       bool
	}{
		{"sig-authentication-2026.01.02.abc", "sig-authentication-2026.01.02", true},
		{"sig-authentication-2026.01.02", "", false}, // the day's dots
		{"other-authentication-2026.01.02.abc", "", false},
		{".abc", "", false},
		{"sig-nope-2026.01.02.abc", "", false},
	} {
		ix, ok := coldIndex("sig", c.name)
		if ix != c.ix || ok != c.ok {
			t.Errorf("coldIndex(%q) = %q, %v", c.name, ix, ok)
		}
	}
	if got := ColdSnapshotName("Sig-A", "UUID"); got != "sig-a.uuid" {
		t.Errorf("ColdSnapshotName = %q", got)
	}
}
