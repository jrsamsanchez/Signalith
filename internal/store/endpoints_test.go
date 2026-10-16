package store

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// twoFronts is a client for two addresses of one fake OpenSearch. Its
// first request goes to a, the next to b, and so on in turn.
func twoFronts(t *testing.T, timeout time.Duration) (*Client, *ostest.Server, *ostest.Front, *ostest.Front) {
	t.Helper()
	os := ostest.New(t)
	a, b := os.Front(t), os.Front(t)
	return New(Config{URL: a.URL, URLs: b.URL, Timeout: timeout}), os, a, b
}

func shortDown(t *testing.T, d time.Duration) {
	old := endpointDownFor
	endpointDownFor = d
	t.Cleanup(func() { endpointDownFor = old })
}

func count(reqs []string, part string) int {
	n := 0
	for _, r := range reqs {
		if strings.Contains(r, part) {
			n++
		}
	}
	return n
}

func TestEndpointList(t *testing.T) {
	got, err := endpointList(Config{URL: "http://a:9200/", URLs: " http://b:9200/ ,http://a:9200,, http://c:9200"})
	if err != nil || strings.Join(got, " ") != "http://a:9200 http://b:9200 http://c:9200" {
		t.Fatalf("got %q %v", got, err)
	}
	_, err = endpointList(Config{URL: "http://a:9200", URLs: "http://admin:SECRET@b:9200"})
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "user name or password") {
		t.Fatalf("credentials in urls: %v", err)
	}
	c := New(Config{URL: "http://a:9200", URLs: "http://admin:SECRET@b:9200"})
	if _, err := c.Health(context.Background()); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("a client with credentials in urls was usable: %v", err)
	}
}

func TestResendable(t *testing.T) {
	ids := []byte(`{"create":{"_index":"e","_id":"1"}}` + "\n" + `{"a":1}` + "\n" + `{"index":{"_index":"e","_id":"2"}}` + "\n" + `{"a":2}` + "\n")
	noID := []byte(`{"create":{"_index":"e","_id":"1"}}` + "\n" + `{"a":1}` + "\n" + `{"create":{"_index":"e"}}` + "\n" + `{"a":2}` + "\n")
	del := []byte(`{"delete":{"_index":"e","_id":"1"}}` + "\n")
	for _, tc := range []struct {
		method, path string
		body         []byte
		want         bool
	}{
		{"GET", "/_cluster/health", nil, true},
		{"HEAD", "/events", nil, true},
		{"POST", "/events-*/_search?ignore_unavailable=true", nil, true},
		{"POST", "/_search/scroll", nil, false},
		{"POST", "/events/_count", nil, true},
		{"POST", "/_mget?realtime=true", nil, true},
		{"POST", "/_bulk", ids, true},
		{"POST", "/_bulk", noID, false},
		{"POST", "/_bulk", del, false},
		{"POST", "/_bulk", nil, false},
		{"PUT", "/_index_template/x", nil, false},
		{"PUT", "/f/_create/1", nil, false},
		{"PUT", "/f/_doc/1?if_seq_no=1&if_primary_term=1", nil, false},
		{"POST", "/f/_update/1", nil, false},
		{"POST", "/f/_delete_by_query", nil, false},
		{"POST", "/f/_update_by_query", nil, false},
		{"DELETE", "/f", nil, false},
	} {
		if got := resendable(tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s %s: resendable %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestOneEndpointIsUnchanged(t *testing.T) {
	os := ostest.New(t)
	url := os.URL
	os.Close()
	c := New(Config{URL: url, Timeout: time.Second})
	_, err := c.Health(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "opensearch unreachable at "+url+": ") || strings.Contains(err.Error(), "other OpenSearch") {
		t.Fatalf("error: %v", err)
	}
	if st := c.Endpoints(); len(st) != 1 || st[0].Down || st[0].URL != url || c.Endpoint() != url {
		t.Fatalf("endpoints: %+v", st)
	}

	// A refusal is the same error as ever, with no address added.
	os2 := ostest.New(t)
	os2.FailN(1, "GET", "/_cluster/health", http.StatusServiceUnavailable, "cluster_manager_not_discovered_exception")
	c = New(Config{URL: os2.URL})
	_, err = c.Health(context.Background())
	if err == nil || err.Error() != "opensearch returned 503: cluster_manager_not_discovered_exception: injected by the test" {
		t.Fatalf("error: %v", err)
	}
	if c.Endpoints()[0].Down {
		t.Fatal("the only address was marked down")
	}
}

func TestRequestsAreSpreadAndADownAddressSkipped(t *testing.T) {
	shortDown(t, 300*time.Millisecond)
	c, _, a, b := twoFronts(t, 5*time.Second)
	ctx := context.Background()
	for range 4 {
		if _, err := c.Health(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if na, nb := len(a.Requests()), len(b.Requests()); na != 2 || nb != 2 {
		t.Fatalf("requests not spread: a=%d b=%d", na, nb)
	}

	a.Down()
	for i := range 6 {
		if _, err := c.Health(ctx); err != nil {
			t.Fatalf("a request failed while another address was up: %v", err)
		}
		// The first finds a down (Go's transport may try a kept connection
		// twice); after that it is skipped.
		if na := len(a.Requests()); i > 0 && na != 0 {
			t.Fatalf("a down address got %d requests", na)
		}
	}
	st := c.Endpoints()
	if !st[0].Down || st[1].Down || st[0].Reason == "" || st[0].Until.IsZero() {
		t.Fatalf("status: %+v", st)
	}

	// After endpointDownFor it is tried again, and is up once it answers.
	a.Up()
	time.Sleep(350 * time.Millisecond)
	for range 4 {
		if _, err := c.Health(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if na := len(a.Requests()); na == 0 {
		t.Fatal("the address was not tried again")
	}
	if st := c.Endpoints(); st[0].Down {
		t.Fatalf("still down: %+v", st)
	}
}

func TestEveryAddressDown(t *testing.T) {
	c, _, a, b := twoFronts(t, 5*time.Second)
	a.Down()
	b.Down()
	ctx := context.Background()
	_, err := c.Health(ctx)
	if err == nil || !strings.Contains(err.Error(), "(1 other OpenSearch address also failed)") || !strings.Contains(err.Error(), b.URL) {
		t.Fatalf("error: %v", err)
	}
	// Both are down now, and both are still tried.
	_, _ = a.Requests(), b.Requests()
	if _, err := c.Health(ctx); err == nil {
		t.Fatal("no error")
	}
	if len(a.Requests()) != 1 || len(b.Requests()) != 1 {
		t.Fatal("not every address was tried")
	}
	b.Up()
	if _, err := c.Health(ctx); err != nil {
		t.Fatalf("an address that came back was not used: %v", err)
	}

	// 503 from every address keeps its type.
	a.Up()
	for _, f := range []*ostest.Front{a, b} {
		f.SetFault(func(m, p string) *ostest.Fault { return &ostest.NotInitialized })
	}
	_, err = c.Health(ctx)
	if RefusalOf(err) != RefusedNotInitialized || !strings.Contains(err.Error(), "also failed") {
		t.Fatalf("error: %v (%s)", err, RefusalOf(err))
	}
}

func TestAutoIDBulkIsNeverSentTwice(t *testing.T) {
	c, os, a, b := twoFronts(t, 300*time.Millisecond)
	a.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "_bulk") {
			return &ostest.Fault{Stall: true}
		}
		return nil
	})
	errs, err := c.Bulk(context.Background(), []IndexedDoc{{Index: "e", Doc: map[string]any{"a": 1}}})
	if err == nil || !NoAnswer(err) || strings.Contains(err.Error(), "also failed") || len(errs) != 0 {
		t.Fatalf("bulk: %v %v", errs, err)
	}
	if n := count(b.Requests(), "_bulk"); n != 0 {
		t.Fatalf("an auto-ID bulk was sent again to another address (%d)", n)
	}
	if len(os.Indices()) != 0 && len(os.Indices()) != 1 {
		t.Fatal("unexpected indices")
	}
}

func TestBulkWithIDsMovesOn(t *testing.T) {
	shortDown(t, 0)
	c, os, a, b := twoFronts(t, 300*time.Millisecond)
	ctx := context.Background()
	docs := []IndexedDoc{{Index: "e", ID: "1", Doc: map[string]any{"a": 1}}, {Index: "e", ID: "2", Doc: map[string]any{"a": 2}}}

	// a takes the bulk and answers nothing: b gets it.
	a.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "_bulk") {
			return &ostest.Fault{Stall: true}
		}
		return nil
	})
	errs, err := c.Bulk(ctx, docs)
	if err != nil || len(errs) != 0 || count(b.Requests(), "_bulk") != 1 || os.Source("e", "1") == nil {
		t.Fatalf("bulk: %v %v", errs, err)
	}

	// a stores the documents, then drops the connection: b refuses them as
	// already stored, which WithoutConflicts drops.
	a.SetFault(nil)
	_, _ = c.Health(ctx) // so the next request goes to a
	docs = []IndexedDoc{{Index: "e", ID: "3", Doc: map[string]any{"a": 3}}}
	a.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "_bulk") {
			return &ostest.Fault{Drop: true}
		}
		return nil
	})
	_, _ = a.Requests(), b.Requests()
	errs, err = c.Bulk(ctx, docs)
	if err != nil || count(a.Requests(), "_bulk") != 1 || count(b.Requests(), "_bulk") != 1 {
		t.Fatalf("bulk: %v %v", errs, err)
	}
	if left, dup := WithoutConflicts(errs, docs); len(left) != 0 || dup != 1 {
		t.Fatalf("errors %v, duplicates %d", left, dup)
	}
}

func TestLostWriteIsSettledOnAnotherAddress(t *testing.T) {
	c, os, a, b := twoFronts(t, 5*time.Second)
	ctx := context.Background()
	os.Put("f", "1", map[string]any{"n": 1})
	_, v, _, err := c.Get(ctx, "f", "1")
	if err != nil {
		t.Fatal(err)
	}
	dropWrites := func(f *ostest.Front, fault ostest.Fault) {
		f.SetFault(func(m, p string) *ostest.Fault {
			if m == http.MethodPut {
				return &fault
			}
			return nil
		})
	}
	// Whichever address gets the write applies it and drops the answer;
	// the read that settles it goes to the other.
	dropWrites(a, ostest.Fault{Drop: true})
	dropWrites(b, ostest.Fault{Drop: true})
	nv, err := c.PutIf(ctx, "f", "1", map[string]any{"n": 2}, v, false)
	if err != nil || nv.SeqNo <= v.SeqNo {
		t.Fatalf("PutIf: %v %v", nv, err)
	}
	puts := count(a.Requests(), "PUT") + count(b.Requests(), "PUT")
	if puts != 1 {
		t.Fatalf("the write was sent %d times", puts)
	}

	// A write that never got in: the original error stands.
	dropWrites(a, ostest.Fault{Status: http.StatusBadGateway, Type: "bad_gateway"})
	dropWrites(b, ostest.Fault{Status: http.StatusBadGateway, Type: "bad_gateway"})
	_, err = c.PutIf(ctx, "f", "1", map[string]any{"n": 3}, nv, false)
	var se *Error
	if !errors.As(err, &se) || se.Status != http.StatusBadGateway || IsConflict(err) {
		t.Fatalf("PutIf: %v", err)
	}

	// A create whose answer was lost is the creator's, not ErrExists.
	dropWrites(a, ostest.Fault{Drop: true})
	dropWrites(b, ostest.Fault{Drop: true})
	if _, err := c.Create(ctx, "f", "2", map[string]any{"n": 1}, false); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestNotSentIsTriedElsewhere(t *testing.T) {
	c, os, a, b := twoFronts(t, 5*time.Second)
	a.Close()
	ctx := context.Background()
	for i, do := range []func() error{
		func() error { return c.PutIndexTemplate(ctx, "t", map[string]any{"index_patterns": []string{"x-*"}}) },
		func() error {
			_, err := c.Bulk(ctx, []IndexedDoc{{Index: "e", Doc: map[string]any{"a": 1}}})
			return err
		},
		func() error {
			return c.Do(ctx, http.MethodPost, "/e/_delete_by_query", map[string]any{"query": map[string]any{"match_all": map[string]any{}}}, nil)
		},
		func() error { _, err := c.Update(ctx, "e2", "1", map[string]any{"a": 1}, false); return err },
	} {
		if err := do(); err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if len(os.Templates()) != 1 || count(b.Requests(), "_bulk") != 1 {
		t.Fatal("requests did not reach the other address")
	}
}

func TestBlocksAndTooManyRequestsStay(t *testing.T) {
	c, os, a, b := twoFronts(t, 5*time.Second)
	os.Block(true)
	_, err := c.Bulk(context.Background(), []IndexedDoc{{Index: "e", ID: "1", Doc: map[string]any{"a": 1}}})
	_ = err
	n := count(a.Requests(), "_bulk") + count(b.Requests(), "_bulk")
	if n != 1 {
		t.Fatalf("a blocked bulk was sent %d times", n)
	}
	for _, f := range []*ostest.Front{a, b} {
		f.SetFault(func(m, p string) *ostest.Fault {
			return &ostest.Fault{Status: http.StatusTooManyRequests, Type: "es_rejected_execution_exception"}
		})
	}
	if _, err := c.Health(context.Background()); err == nil || strings.Contains(err.Error(), "also failed") {
		t.Fatalf("429: %v", err)
	}
	for _, st := range c.Endpoints() {
		if st.Down {
			t.Fatalf("marked down for a cluster-wide refusal: %+v", st)
		}
	}
}
