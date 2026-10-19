package risk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeClient answers bulks and counts as told.
type fakeClient struct {
	bulkErr  error
	rejected []store.BulkItemError
	count    int
	doErr    error
	path     string
	body     any
}

func (f *fakeClient) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	return f.rejected, f.bulkErr
}

func (f *fakeClient) Do(_ context.Context, _, path string, body, out any) error {
	f.path, f.body = path, body
	if f.doErr != nil {
		return f.doErr
	}
	b, _ := json.Marshal(map[string]int{"count": f.count})
	return json.Unmarshal(b, out)
}

func TestWriteAndExists(t *testing.T) {
	ctx := context.Background()
	f := &fakeClient{}
	s := &Store{Client: f, Prefix: "sig"}
	if err := s.Write(ctx, nil); err != nil {
		t.Errorf("nothing = %v", err)
	}
	ev := detect.RiskEvent{ID: "e1", Time: time.Now().Add(-time.Hour), Object: "bob", ObjectType: "user", Score: 5, DetectionID: "r1", GroupKey: "k"}
	boom := errors.New("opensearch down")
	f.bulkErr = boom
	if err := s.Write(ctx, []detect.RiskEvent{ev}); !errors.Is(err, boom) {
		t.Errorf("bulk = %v", err)
	}
	f.bulkErr = nil
	f.rejected = []store.BulkItemError{{Index: "sig-risk-x", Pos: 0, Status: 400, Reason: "mapper_parsing_exception"}}
	if err := s.Write(ctx, []detect.RiskEvent{ev}); err == nil || err.Error() != "1 risk events were rejected: mapper_parsing_exception" {
		t.Errorf("rejected = %v", err)
	}

	since := time.Now().Add(-2 * time.Hour)
	f.count = 2
	if ok, err := s.Exists(ctx, "r1", "k", since); err != nil || !ok {
		t.Errorf("exists = %v %v", ok, err)
	}
	if f.path != "/sig-risk-%2A/_count?ignore_unavailable=true&allow_no_indices=true" && f.path != "/sig-risk-*/_count?ignore_unavailable=true&allow_no_indices=true" {
		t.Errorf("path = %s", f.path)
	}
	q, _ := json.Marshal(f.body)
	for _, want := range []string{`"detection_id":"r1"`, `"group_key":"k"`, since.UTC().Format(time.RFC3339Nano)} {
		if !strings.Contains(string(q), want) {
			t.Errorf("query lacks %s: %s", want, q)
		}
	}
	f.count = 0
	if ok, err := s.Exists(ctx, "r1", "k", since); err != nil || ok {
		t.Errorf("none = %v %v", ok, err)
	}
	f.doErr = boom
	if _, err := s.Exists(ctx, "r1", "k", since); !errors.Is(err, boom) {
		t.Errorf("count error = %v", err)
	}
}
