package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
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
