package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// scriptDoer answers each request with what answer returns, and records
// the requests.
type scriptDoer struct {
	mu     sync.Mutex
	calls  []string
	bodies []any
	answer func(n int, method, path string, body any) (string, error)
}

func (d *scriptDoer) Do(_ context.Context, method, path string, body, out any) error {
	d.mu.Lock()
	n := len(d.calls)
	d.calls = append(d.calls, method+" "+path)
	d.bodies = append(d.bodies, body)
	d.mu.Unlock()
	if d.answer == nil {
		return nil
	}
	s, err := d.answer(n, method, path, body)
	if err != nil || out == nil || s == "" {
		return err
	}
	return json.Unmarshal([]byte(s), out)
}

// hitsPage is a search answer of n hits, numbered from start.
func hitsPage(start, n int) string {
	var b strings.Builder
	b.WriteString(`{"hits":{"hits":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"_id":"i%d","_source":{"id":"i%d","type":"ip","value":"192.0.2.1"},"sort":["i%d"]}`, start+i, start+i, start+i)
	}
	b.WriteString(`]}}`)
	return b.String()
}

func TestOpenSearchIndex(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{}
	o := NewOpenSearch(d, "sig")
	if err := o.EnsureIndex(ctx); err != nil || d.calls[0] != "PUT /sig_intel" {
		t.Fatalf("ensure = %v %v", err, d.calls)
	}
	if err := o.Upgrade(ctx); err != nil || d.calls[1] != "PUT /sig_intel/_mapping" {
		t.Errorf("upgrade = %v %v", err, d.calls)
	}
	d.answer = func(int, string, string, any) (string, error) {
		return "", &store.Error{Status: 400, Body: "resource_already_exists_exception"}
	}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Errorf("existing = %v", err)
	}
	boom := errors.New("opensearch down")
	d.answer = func(int, string, string, any) (string, error) { return "", boom }
	if err := o.EnsureIndex(ctx); !errors.Is(err, boom) {
		t.Errorf("ensure error = %v", err)
	}
	if err := o.Replicate(ctx); !errors.Is(err, boom) {
		t.Errorf("replicate error = %v", err)
	}
	if err := o.Put(ctx, []Indicator{{ID: "a"}}); !errors.Is(err, boom) {
		t.Errorf("put error = %v", err)
	}
	if err := o.Delete(ctx, []string{"a"}); !errors.Is(err, boom) {
		t.Errorf("delete error = %v", err)
	}
	if _, err := o.All(ctx); !errors.Is(err, boom) {
		t.Errorf("all error = %v", err)
	}
	if _, err := o.SourceIDs(ctx, "feed"); !errors.Is(err, boom) {
		t.Errorf("source IDs error = %v", err)
	}
	if _, err := o.Version(ctx); !errors.Is(err, boom) {
		t.Errorf("version error = %v", err)
	}
}

func TestOpenSearchBulk(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{}
	o := NewOpenSearch(d, "sig")
	// More than one bulk request's worth goes in two.
	inds := make([]Indicator, bulkSize+1)
	for i := range inds {
		inds[i] = Indicator{ID: fmt.Sprintf("i%d", i), Type: "ip", Value: "192.0.2.1"}
	}
	if err := o.Put(ctx, inds); err != nil || len(d.calls) != 2 || d.calls[0] != "POST /_bulk?refresh=wait_for" {
		t.Fatalf("put = %v %v", err, d.calls)
	}
	first := d.bodies[0].([]byte)
	if n := bytes.Count(first, []byte("\n")); n != 2*bulkSize || !bytes.Contains(first, []byte(`{"index":{"_id":"i0","_index":"sig_intel"}}`)) {
		t.Errorf("first bulk has %d lines: %.200s", n, first)
	}

	// Rejected items are counted; a delete of one already gone is not.
	d.answer = func(int, string, string, any) (string, error) {
		return `{"errors":true,"items":[{"index":{"status":201}},{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad weight"}}},` +
			`{"index":{"status":400,"error":{"type":"other","reason":"x"}}},{"delete":{"status":404,"error":{"type":"not_found","reason":"gone"}}}]}`, nil
	}
	err := o.Put(ctx, inds[:4])
	if err == nil || err.Error() != "2 of 4 indicators were rejected: mapper_parsing_exception: bad weight" {
		t.Errorf("rejected = %v", err)
	}
	d.answer = func(int, string, string, any) (string, error) {
		return `{"errors":true,"items":[{"delete":{"status":404,"error":{"type":"not_found","reason":"gone"}}}]}`, nil
	}
	if err := o.Delete(ctx, []string{"gone"}); err != nil {
		t.Errorf("delete of one gone = %v", err)
	}
	d.answer = nil
	d.calls = nil
	ids := make([]string, bulkSize+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("i%d", i)
	}
	if err := o.Delete(ctx, ids); err != nil || len(d.calls) != 2 {
		t.Errorf("delete = %v %v", err, d.calls)
	}
}

func TestOpenSearchReadsPages(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{}
	d.answer = func(n int, _, _ string, body any) (string, error) {
		after := body.(map[string]any)["search_after"]
		switch {
		case n == 0 && after == nil:
			return hitsPage(0, 10000), nil
		case n == 1 && fmt.Sprint(after) == "[i9999]":
			return hitsPage(10000, 3), nil
		}
		return "", fmt.Errorf("unexpected request %d after %v", n, after)
	}
	o := NewOpenSearch(d, "sig")
	all, err := o.All(ctx)
	if err != nil || len(all) != 10003 || all[10002].ID != "i10002" {
		t.Fatalf("all = %d %v", len(all), err)
	}
	d.calls = nil
	ids, err := o.SourceIDs(ctx, "feed-a")
	if err != nil || len(ids) != 10003 || ids[0] != "i0" {
		t.Fatalf("ids = %d %v", len(ids), err)
	}
	q, _ := json.Marshal(d.bodies[len(d.bodies)-1])
	if !strings.Contains(string(q), `"term":{"source":"feed-a"}`) {
		t.Errorf("query = %s", q)
	}

	d.answer = func(int, string, string, any) (string, error) {
		return `{"hits":{"total":{"value":12}},"aggregations":{"updated":{"value":1700000000000}}}`, nil
	}
	if v, err := o.Version(ctx); err != nil || v != "12/1.7e+12" {
		t.Errorf("version = %q %v", v, err)
	}
}
