package playbooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeDocs answers the OpenSearch calls a playbook store makes from what a
// test put in it, and records them.
type fakeDocs struct {
	calls     []string
	bodies    []any
	doErr     error
	doAnswer  string
	docs      map[string]json.RawMessage
	getErr    error
	created   []string
	put       []string
	putErr    error
	mgets     int
	mgetErr   error
	search    []store.Doc
	searchErr error
	searchQ   map[string]any
}

func newFakeDocs() *fakeDocs { return &fakeDocs{docs: map[string]json.RawMessage{}} }

func (f *fakeDocs) Do(_ context.Context, method, path string, body, out any) error {
	f.calls = append(f.calls, method+" "+path)
	f.bodies = append(f.bodies, body)
	if f.doErr != nil {
		return f.doErr
	}
	if out != nil && f.doAnswer != "" {
		return json.Unmarshal([]byte(f.doAnswer), out)
	}
	return nil
}

func (f *fakeDocs) Get(_ context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if f.getErr != nil {
		return nil, store.Version{}, false, f.getErr
	}
	raw, ok := f.docs[id]
	return raw, store.Version{SeqNo: 4, PrimaryTerm: 1}, ok, nil
}

func (f *fakeDocs) Create(_ context.Context, index, id string, body any, _ bool) (store.Version, error) {
	if _, ok := f.docs[id]; ok {
		return store.Version{}, store.ErrExists
	}
	b, _ := json.Marshal(body)
	f.docs[id] = b
	f.created = append(f.created, index+"/"+id)
	return store.Version{SeqNo: 1, PrimaryTerm: 1}, nil
}

func (f *fakeDocs) PutIf(_ context.Context, index, id string, body any, v store.Version, _ bool) (store.Version, error) {
	if f.putErr != nil {
		return store.Version{}, f.putErr
	}
	f.put = append(f.put, fmt.Sprintf("%s/%s@%d", index, id, v.SeqNo))
	return store.Version{SeqNo: v.SeqNo + 1, PrimaryTerm: 1}, nil
}

func (f *fakeDocs) MGetVersions(_ context.Context, refs []store.Ref) (map[store.Ref]store.Version, error) {
	f.mgets++
	if f.mgetErr != nil {
		return nil, f.mgetErr
	}
	if len(refs) > 500 {
		return nil, errors.New("too many refs in one request")
	}
	out := map[store.Ref]store.Version{}
	for _, r := range refs {
		if _, ok := f.docs[r.ID]; ok {
			out[r] = store.Version{SeqNo: 1}
		}
	}
	return out, nil
}

func (f *fakeDocs) SearchDocs(_ context.Context, index string, q map[string]any) ([]store.Doc, error) {
	f.searchQ = q
	return f.search, f.searchErr
}

func TestOpenSearchIndex(t *testing.T) {
	ctx := context.Background()
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	if o.Index != "sig_playbook_runs" {
		t.Errorf("index = %q", o.Index)
	}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	body := f.bodies[0].(map[string]any)
	props := body["mappings"].(map[string]any)["properties"].(map[string]any)
	if f.calls[0] != "PUT /sig_playbook_runs" || props["status"].(map[string]any)["type"] != "keyword" || props["steps"].(map[string]any)["enabled"] != false {
		t.Errorf("create = %v %v", f.calls, props)
	}
	f.doErr = &store.Error{Status: 400, Body: "resource_already_exists_exception"}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Errorf("existing index = %v", err)
	}
	f.doErr = &store.Error{Status: 403, Body: "forbidden"}
	if err := o.EnsureIndex(ctx); err == nil {
		t.Error("forbidden not returned")
	}
	f.doErr, f.calls = nil, nil
	f.doAnswer = `{"sig_playbook_runs":{"settings":{"index":{"number_of_replicas":"0"}}}}`
	if err := o.Replicate(ctx); err != nil || len(f.calls) != 2 || f.calls[1] != "PUT /sig_playbook_runs/_settings" {
		t.Errorf("replicate = %v %v", err, f.calls)
	}
}

func TestOpenSearchRuns(t *testing.T) {
	ctx := context.Background()
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	now := time.Now().UTC().Truncate(time.Millisecond)
	r := &Run{ID: "r1", PlaybookID: "pb", FindingID: "f1", Status: StatusRunning, Created: now}
	if _, err := o.Claim(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Claim(ctx, r); !errors.Is(err, store.ErrExists) {
		t.Errorf("claim twice = %v", err)
	}
	got, err := o.Get(ctx, "r1")
	if err != nil || got.FindingID != "f1" || got.Version.SeqNo != 4 || !got.Created.Equal(now) {
		t.Errorf("get = %+v %v", got, err)
	}
	if _, err := o.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing = %v", err)
	}
	f.docs["bad"] = json.RawMessage(`{"id":5}`)
	if _, err := o.Get(ctx, "bad"); err == nil {
		t.Error("bad document read")
	}
	f.getErr = errors.New("down")
	if _, err := o.Get(ctx, "r1"); err == nil || err.Error() != "down" {
		t.Errorf("get error = %v", err)
	}
	if v, err := o.Update(ctx, r, store.Version{SeqNo: 4}); err != nil || v.SeqNo != 5 || f.put[0] != "sig_playbook_runs/r1@4" {
		t.Errorf("update = %v %v %v", v, err, f.put)
	}

	// Existing asks in batches of 500.
	ids := make([]string, 1203)
	for i := range ids {
		ids[i] = fmt.Sprint("x", i)
	}
	ids[1202] = "r1"
	ex, err := o.Existing(ctx, ids)
	if err != nil || len(ex) != 1 || !ex["r1"] || f.mgets != 3 {
		t.Errorf("existing = %v %v (%d requests)", ex, err, f.mgets)
	}
	if ex, err := o.Existing(ctx, nil); err != nil || len(ex) != 0 {
		t.Errorf("existing of none = %v %v", ex, err)
	}
	f.mgetErr = errors.New("down")
	if _, err := o.Existing(ctx, ids); err == nil {
		t.Error("mget error not returned")
	}
}

func TestOpenSearchDue(t *testing.T) {
	ctx := context.Background()
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	now := time.Now()
	doc := func(id, status string, created time.Time) store.Doc {
		b, _ := json.Marshal(Run{ID: id, Status: status, Created: created})
		return store.Doc{Ref: store.Ref{ID: id}, Version: store.Version{SeqNo: 9}, Source: b}
	}
	f.search = []store.Doc{
		doc("q2", StatusQueued, now.Add(-time.Minute)),
		doc("a1", StatusApproved, now.Add(-time.Hour)),
		doc("q1", StatusQueued, now.Add(-time.Minute)),
		doc("w1", StatusWaiting, now),
		doc("s1", StatusRunning, now),
		doc("d1", StatusSucceeded, now),
		{Source: json.RawMessage(`not json`)},
	}
	resume, expired, stuck, err := o.Due(ctx, now, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, s := range resume {
		order = append(order, s.ID)
	}
	if strings.Join(order, ",") != "a1,q1,q2" || len(expired) != 1 || expired[0].ID != "w1" || len(stuck) != 1 || stuck[0].Version.SeqNo != 9 {
		t.Errorf("due = %v %v %v", order, expired, stuck)
	}
	should := f.searchQ["bool"].(map[string]any)["should"].([]any)
	if len(should) != 3 {
		t.Errorf("due query = %v", f.searchQ)
	}
	f.searchErr = errors.New("down")
	if _, _, _, err := o.Due(ctx, now, now); err == nil {
		t.Error("search error not returned")
	}
}

func TestOpenSearchListAndPurge(t *testing.T) {
	ctx := context.Background()
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	f.doAnswer = `{"hits":{"total":{"value":7},"hits":[{"_source":{"id":"r2"}},{"_source":{"id":"r1"}}]}}`
	list, total, err := o.List(ctx, Filter{Status: []string{StatusSucceeded}, FindingID: "f1", PlaybookID: "pb", Limit: 9999})
	if err != nil || total != 7 || len(list) != 2 || list[0].ID != "r2" {
		t.Fatalf("list = %v %d %v", list, total, err)
	}
	body := f.bodies[0].(map[string]any)
	if !strings.HasPrefix(f.calls[0], "POST /sig_playbook_runs/_search?") || body["size"] != 500 ||
		len(body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)) != 3 {
		t.Errorf("list request = %v %v", f.calls, body)
	}
	if _, _, err := o.List(ctx, Filter{}); err != nil {
		t.Fatal(err)
	}
	body = f.bodies[1].(map[string]any)
	if _, ok := body["query"].(map[string]any)["match_all"]; !ok || body["size"] != 50 {
		t.Errorf("unfiltered list = %v", body)
	}
	before := time.Now()
	f.doAnswer = ""
	if err := o.Purge(ctx, before); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.calls[2], "POST /sig_playbook_runs/_delete_by_query?") {
		t.Errorf("purge = %v", f.calls)
	}
	q := f.bodies[2].(map[string]any)["query"].(map[string]any)["bool"].(map[string]any)
	keep := q["must_not"].([]any)[0].(map[string]any)["terms"].(map[string]any)["status"].([]string)
	if len(keep) != 4 || !strings.Contains(fmt.Sprint(q["filter"]), ts(before)) {
		t.Errorf("purge query = %v", q)
	}
	f.doErr = errors.New("down")
	if _, _, err := o.List(ctx, Filter{}); err == nil {
		t.Error("list error not returned")
	}
}
