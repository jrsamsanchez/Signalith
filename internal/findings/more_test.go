package findings

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

// scriptDoer answers requests in turn with the answers given, recording
// each request.
type scriptDoer struct {
	answers []answer
	calls   []string
	bodies  []string
}

type answer struct {
	resp string
	err  error
}

func (d *scriptDoer) Do(_ context.Context, method, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	d.calls = append(d.calls, method+" "+path)
	d.bodies = append(d.bodies, string(b))
	if len(d.answers) == 0 {
		return nil
	}
	a := d.answers[0]
	d.answers = d.answers[1:]
	if a.err != nil {
		return a.err
	}
	if out != nil && a.resp != "" {
		return json.Unmarshal([]byte(a.resp), out)
	}
	return nil
}

func TestOpenSearchIndexUpkeep(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{answers: []answer{{err: &store.Error{Status: 400, Body: `{"error":{"type":"resource_already_exists_exception"}}`}}}}
	s := NewOpenSearch(d, "sig")
	if err := s.EnsureIndex(ctx); err != nil {
		t.Errorf("index exists = %v", err)
	}
	if err := s.Upgrade(ctx); err != nil || len(d.calls) != 3 || d.calls[1] != "PUT /sig_findings/_mapping" ||
		!strings.HasPrefix(d.calls[2], "POST /sig_findings/_update_by_query") || !strings.Contains(d.bodies[2], "ctx._source.urgency = ctx._source.severity") {
		t.Errorf("upgrade = %v %v", err, d.calls)
	}
	boom := errors.New("mapping refused")
	d.answers = []answer{{err: boom}}
	if err := s.Upgrade(ctx); !errors.Is(err, boom) {
		t.Errorf("upgrade failure = %v", err)
	}
	if err := s.EnsureSampleField(ctx); err != nil || !strings.Contains(d.bodies[len(d.bodies)-1], `"sample":{"type":"keyword"}`) {
		t.Errorf("sample field = %v %s", err, d.bodies[len(d.bodies)-1])
	}
}

func TestOpenSearchDocs(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{}
	s := NewOpenSearch(d, "sig")
	if err := s.Save(ctx, &Finding{ID: "f1"}); err != nil || d.calls[0] != "PUT /sig_findings/_doc/f1?refresh=wait_for" {
		t.Errorf("save = %v %v", err, d.calls)
	}

	missing := &store.Error{Status: 404}
	boom := errors.New("down")
	d.answers = []answer{{err: missing}, {err: boom}}
	if err := s.Delete(ctx, "f1"); err != nil {
		t.Errorf("delete missing = %v", err)
	}
	if err := s.Delete(ctx, "f1"); !errors.Is(err, boom) {
		t.Errorf("delete failure = %v", err)
	}

	d.answers = []answer{{err: missing}, {err: boom}, {resp: `{"found":false}`}, {resp: `{"found":true,"_source":{"id":"f1","status":"new"}}`}}
	for i, want := range []error{ErrNotFound, boom, ErrNotFound, nil} {
		f, err := s.Get(ctx, "f1")
		if !errors.Is(err, want) || (want == nil && f.ID != "f1") {
			t.Errorf("get %d = %+v %v", i, f, err)
		}
	}

	// A plain client: read, change, write.
	found := answer{resp: `{"found":true,"_source":{"id":"f1","status":"new"}}`}
	d.answers = []answer{found, {}}
	d.calls = nil
	f, err := s.Modify(ctx, "f1", func(f *Finding) (bool, error) { f.Status = StatusClosed; return true, nil })
	if err != nil || f.Status != StatusClosed || len(d.calls) != 2 || !strings.HasPrefix(d.calls[1], "PUT /sig_findings/_doc/f1") {
		t.Errorf("modify = %+v %v %v", f, err, d.calls)
	}
	d.answers = []answer{found}
	d.calls = nil
	if _, err := s.Modify(ctx, "f1", func(*Finding) (bool, error) { return false, nil }); err != nil || len(d.calls) != 1 {
		t.Errorf("unchanged modify = %v %v", err, d.calls)
	}
	d.answers = []answer{found}
	nope := errors.New("not allowed")
	if _, err := s.Modify(ctx, "f1", func(*Finding) (bool, error) { return false, nope }); !errors.Is(err, nope) {
		t.Errorf("change failure = %v", err)
	}
	d.answers = []answer{{err: missing}}
	if _, err := s.Modify(ctx, "f1", func(*Finding) (bool, error) { return true, nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("modify missing = %v", err)
	}
	d.answers = []answer{found, {err: boom}}
	if _, err := s.Modify(ctx, "f1", func(*Finding) (bool, error) { return true, nil }); !errors.Is(err, boom) {
		t.Errorf("write failure = %v", err)
	}
}

func TestOpenSearchQueries(t *testing.T) {
	ctx := context.Background()
	since := time.Now().Add(-time.Hour)
	d := &scriptDoer{answers: []answer{{resp: `{"hits":{"total":{"value":0},"hits":[]}}`}}}
	s := NewOpenSearch(d, "sig")
	_, _, err := s.Search(ctx, Filter{Severity: []string{"high"}, Urgency: []string{"critical"}, Owner: "sam", DetectionID: "d1",
		EntityValues: []string{"bob"}, Since: since, UpdatedSince: since})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"terms":{"severity":["high"]}`, `"terms":{"urgency":["critical"]}`, `"term":{"owner":"sam"}`,
		`"term":{"detection_id":"d1"}`, `"terms":{"entity_values":["bob"]}`, `"created":{"gte":`, `"updated":{"gte":`} {
		if !strings.Contains(d.bodies[0], want) {
			t.Errorf("search body lacks %s: %s", want, d.bodies[0])
		}
	}
	boom := errors.New("down")
	d.answers = []answer{{err: boom}}
	if _, _, err := s.Search(ctx, Filter{}); !errors.Is(err, boom) {
		t.Errorf("search failure = %v", err)
	}

	d.answers = []answer{{resp: `{"count":2}`}, {resp: `{"count":0}`}, {err: boom}}
	for i, want := range []bool{true, false} {
		if ok, err := s.Exists(ctx, "d1", "k", since); err != nil || ok != want {
			t.Errorf("exists %d = %v %v", i, ok, err)
		}
	}
	if !strings.Contains(d.calls[len(d.calls)-1], "/sig_findings/_count") || !strings.Contains(d.bodies[len(d.bodies)-1], `"group_key":"k"`) {
		t.Errorf("exists request = %s %s", d.calls[len(d.calls)-1], d.bodies[len(d.bodies)-1])
	}
	if _, err := s.Exists(ctx, "d1", "k", since); !errors.Is(err, boom) {
		t.Errorf("exists failure = %v", err)
	}

	d.answers = []answer{{resp: `{"aggregations":{"open":{"doc_count":1,"urgency":{"buckets":[{"key":"high","doc_count":1}]}}}}`}, {err: boom}}
	if sm, err := s.Summary(ctx); err != nil || sm.ByUrgency["high"] != 1 {
		t.Errorf("summary = %+v %v", sm, err)
	}
	if _, err := s.Summary(ctx); !errors.Is(err, boom) {
		t.Errorf("summary failure = %v", err)
	}
}

func TestMatchesFilters(t *testing.T) {
	now := time.Now()
	f := &Finding{ID: "a", Status: StatusNew, Severity: "low", Urgency: "high", Owner: "sam", DetectionID: "d1",
		Entities: map[string]any{"user": "bob"}, Created: now.Add(-time.Hour), Updated: now.Add(-time.Hour)}
	for name, c := range map[string]struct {
		flt  Filter
		want bool
	}{
		"status":        {Filter{Status: []string{StatusClosed}}, false},
		"urgency":       {Filter{Urgency: []string{"high"}}, true},
		"urgency miss":  {Filter{Urgency: []string{"low"}}, false},
		"owner":         {Filter{Owner: "kim"}, false},
		"detection":     {Filter{DetectionID: "d2"}, false},
		"entity":        {Filter{EntityValues: []string{"alice", "bob"}}, true},
		"entity miss":   {Filter{EntityValues: []string{"alice"}}, false},
		"since":         {Filter{Since: now}, false},
		"updated since": {Filter{UpdatedSince: now}, false},
		"all":           {Filter{Owner: "sam", DetectionID: "d1", Since: now.Add(-2 * time.Hour)}, true},
	} {
		if got := Matches(f, c.flt); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestMemoryEdges(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.Save(ctx, &Finding{ID: "nope"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("save missing = %v", err)
	}
	for i := range 5 {
		m.Create(ctx, &Finding{ID: fmt.Sprint(i), Status: StatusNew, Created: time.Now().Add(-time.Duration(i) * time.Minute)})
	}
	got, total, _ := m.Search(ctx, Filter{Limit: 2})
	if len(got) != 2 || total != 5 || got[0].ID != "0" {
		t.Errorf("limit = %d of %d", len(got), total)
	}
	f, err := m.Modify(ctx, "1", func(*Finding) (bool, error) { return false, nil })
	if err != nil || f.ID != "1" {
		t.Errorf("unchanged modify = %+v %v", f, err)
	}
}

func TestUpdateEdges(t *testing.T) {
	if err := (Update{Disposition: ptr("maybe")}).Validate(); err == nil || !strings.Contains(err.Error(), "disposition") {
		t.Errorf("disposition = %v", err)
	}
	if err := (Update{Comment: strings.Repeat("x", 10001)}).Validate(); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("comment = %v", err)
	}
	// An analyst's severity replaces the computed urgency.
	f := &Finding{Severity: "low", Urgency: "medium"}
	if !f.Apply(Update{Severity: ptr("critical")}, "sam", time.Now()) || f.Urgency != "critical" || f.EffectiveUrgency() != "critical" {
		t.Errorf("finding = %+v", f)
	}
	if got := modifyResult(store.ErrNotFound); !errors.Is(got, ErrNotFound) {
		t.Errorf("modifyResult = %v", got)
	}
	if (changeError{errors.New("x")}).Error() != "x" {
		t.Error("changeError")
	}
}
