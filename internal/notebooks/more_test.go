package notebooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestOpenSearchStore(t *testing.T) {
	ctx := context.Background()
	fake := ostest.New(t)
	s := NewOpenSearch(store.New(store.Config{URL: fake.URL}), "t")
	for range 2 { // the second finds it there
		if err := s.EnsureIndex(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Upgrade(ctx); err != nil {
		t.Errorf("upgrade = %v", err)
	}
	if err := s.Replicate(ctx); err != nil {
		t.Errorf("replicate = %v", err)
	}

	ran := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	n := valid()
	n.ID, n.Owner, n.Updated = "NB-1", "Andy", time.Now().UTC()
	n.Cells[1].Result = &Result{RanAt: ran, Matched: 2}
	if err := s.Create(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, n); !errors.Is(err, ErrExists) {
		t.Errorf("twice = %v", err)
	}
	other := valid()
	other.ID, other.Owner, other.Sharing = "NB-2", "bob", Read
	if err := s.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "NB-1")
	if err != nil || got.Title != "Hunt" || got.Cells[1].Result.Matched != 2 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := s.Get(ctx, "NB-9"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}

	list, total, err := s.Search(ctx, Filter{Admin: true})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("search = %v %d %v", list, total, err)
	}
	for _, sum := range list {
		if sum.ID == "NB-1" && (sum.Cells != 2 || sum.Searches != 1 || !sum.LastRun.Equal(ran)) {
			t.Errorf("summary = %+v", sum)
		}
	}
	if list, _, err := s.Search(ctx, Filter{User: "bob", Limit: 5}); err != nil || len(list) != 1 || list[0].ID != "NB-2" {
		t.Errorf("bob sees %v %v", list, err)
	}

	// Modify: a change, none, a refusal, a missing notebook.
	if m, err := s.Modify(ctx, "NB-1", func(n *Notebook) (bool, error) { n.Title = "Renamed"; return true, nil }); err != nil || m.Title != "Renamed" {
		t.Errorf("modify = %+v %v", m, err)
	}
	if m, err := s.Modify(ctx, "NB-1", func(n *Notebook) (bool, error) { return false, nil }); err != nil || m.Title != "Renamed" {
		t.Errorf("no change = %+v %v", m, err)
	}
	refuse := errors.New("not yours")
	if _, err := s.Modify(ctx, "NB-1", func(*Notebook) (bool, error) { return false, refuse }); !errors.Is(err, refuse) {
		t.Errorf("refused = %v", err)
	}
	if _, err := s.Modify(ctx, "NB-9", func(*Notebook) (bool, error) { return true, nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("modify missing = %v", err)
	}
	fake.Put("t_notebooks", "NB-bad", map[string]any{"title": 7})
	if _, err := s.Modify(ctx, "NB-bad", func(*Notebook) (bool, error) { return true, nil }); err == nil {
		t.Error("a broken notebook was modified")
	}

	if err := s.Delete(ctx, "NB-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "NB-1"); err != nil {
		t.Errorf("delete twice = %v", err)
	}
	if _, err := s.Get(ctx, "NB-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete = %v", err)
	}
}

// failDoer answers every request with err.
type failDoer struct{ err error }

func (f failDoer) Do(context.Context, string, string, any, any) error { return f.err }

func TestOpenSearchFailures(t *testing.T) {
	ctx := context.Background()
	down := errors.New("connection refused")
	s := NewOpenSearch(failDoer{down}, "t")
	if err := s.EnsureIndex(ctx); !errors.Is(err, down) {
		t.Errorf("ensure = %v", err)
	}
	if _, err := s.Get(ctx, "x"); !errors.Is(err, down) {
		t.Errorf("get = %v", err)
	}
	if err := s.Delete(ctx, "x"); !errors.Is(err, down) {
		t.Errorf("delete = %v", err)
	}
	if _, _, err := s.Search(ctx, Filter{}); !errors.Is(err, down) {
		t.Errorf("search = %v", err)
	}
	if err := s.Create(ctx, valid()); !errors.Is(err, down) {
		t.Errorf("create = %v", err)
	}
	if _, err := s.Modify(ctx, "x", nil); err == nil || !strings.Contains(err.Error(), "cannot write with versions") {
		t.Errorf("modify = %v", err)
	}
	// A 404 from the index is a missing notebook.
	gone := NewOpenSearch(failDoer{&store.Error{Status: 404, Body: "{}"}}, "t")
	if _, err := gone.Get(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get 404 = %v", err)
	}
	if err := gone.Delete(ctx, "x"); err != nil {
		t.Errorf("delete 404 = %v", err)
	}
}

func TestFilterQuery(t *testing.T) {
	if q := filterQuery(Filter{Admin: true}); q["match_all"] == nil {
		t.Errorf("admin = %v", q)
	}
	q := filterQuery(Filter{User: "Andy", Owner: "Bob", Case: "CASE-1", Technique: " t1059 ", Text: "powershell"})
	fs := q["bool"].(map[string]any)["filter"].([]any)
	if len(fs) != 5 {
		t.Fatalf("filters = %v", fs)
	}
	s := fmt.Sprint(fs)
	for _, want := range []string{"owner_key:andy", "owner_key:bob", "cases:CASE-1", "techniques:T1059.", "title:powershell"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in %s", want, s)
		}
	}
}

func TestMemoryMore(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	n := valid()
	n.ID = "a"
	if err := m.Create(ctx, n); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Get(ctx, "a"); err != nil || got.Title != "Hunt" {
		t.Errorf("get = %v %v", got, err)
	}
	if _, err := m.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing = %v", err)
	}
	if got, err := m.Modify(ctx, "a", func(*Notebook) (bool, error) { return false, nil }); err != nil || got.ID != "a" {
		t.Errorf("no change = %v %v", got, err)
	}
	boom := errors.New("boom")
	if _, err := m.Modify(ctx, "a", func(*Notebook) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Errorf("refused = %v", err)
	}
	// Someone writes every time change runs: busy.
	if _, err := m.Modify(ctx, "a", func(x *Notebook) (bool, error) {
		m.mu.Lock()
		m.ver["a"]++
		m.mu.Unlock()
		return true, nil
	}); !errors.Is(err, ErrBusy) {
		t.Errorf("busy = %v", err)
	}
	for i := range 3 {
		c := valid()
		c.ID = fmt.Sprintf("x%d", i)
		m.Create(ctx, c)
	}
	if list, _, _ := m.Search(ctx, Filter{Admin: true, Limit: 2}); len(list) != 2 {
		t.Errorf("limit = %d", len(list))
	}
	if err := m.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete = %v", err)
	}
	if modifyResult(store.ErrNotFound) != ErrNotFound || modifyResult(boom) != boom {
		t.Error("modifyResult")
	}
	if (changeError{boom}).Error() != "boom" {
		t.Error("changeError")
	}
}

func TestFilterMatches(t *testing.T) {
	n := valid()
	n.ID, n.Owner, n.Cases, n.Description = "NB-7", "andy", []string{"CASE-1"}, "Encoded commands"
	for f, want := range map[*Filter]bool{
		{User: "andy", Case: "CASE-1"}:   true,
		{User: "andy", Case: "CASE-2"}:   false,
		{User: "andy", Owner: "ANDY"}:    true,
		{User: "andy", Owner: "bob"}:     false,
		{User: "andy", Text: "encoded"}:  true,
		{User: "andy", Text: "nb-7"}:     true,
		{User: "andy", Text: "registry"}: false,
	} {
		if got := f.Matches(n); got != want {
			t.Errorf("%+v = %v", *f, got)
		}
	}
}

func TestValidateLimits(t *testing.T) {
	n := valid()
	n.Title = strings.Repeat("t", MaxTitleLen+1)
	n.Description = strings.Repeat("d", MaxTextLen+1)
	n.TimeRange = "10s"
	for i := range MaxTechniques + 1 {
		n.Techniques = append(n.Techniques, fmt.Sprintf("T1%03d", i))
	}
	for i := range MaxCases + 1 {
		n.Cases = append(n.Cases, fmt.Sprintf("CASE-%d", i))
	}
	n.Cells = append(n.Cells,
		Cell{ID: "bad id!", Kind: KindMarkdown, Text: "x"},
		Cell{ID: "s1", Kind: KindSearch, Title: strings.Repeat("t", MaxTitleLen+1), Text: strings.Repeat("x", MaxTextLen+1)},
		Cell{ID: "s2", Kind: KindSearch, Query: strings.Repeat("a", MaxQueryLen+1)})
	for len(n.Cells) <= MaxCells {
		n.Cells = append(n.Cells, Cell{ID: fmt.Sprintf("m%d", len(n.Cells)), Kind: KindMarkdown, Text: "x"})
	}
	err := n.Validate()
	for _, want := range []string{"title must be 200", "description is too long", "time range must be", "at most 30 techniques",
		"at most 50 cases", "at most 60 cells", "bad id", "the note is too long", "query is required", "query is too long"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("no %q in %v", want, err)
		}
	}
	empty := &Notebook{Title: "x\x01y"}
	empty.Normalize()
	if empty.Cells == nil || empty.Title != "x y" {
		t.Errorf("normalized = %+v", empty)
	}
	if NewID(time.Now())[:3] != "NB-" {
		t.Error("NewID")
	}
}

func TestExportStates(t *testing.T) {
	ran := time.Now().UTC().Add(-time.Hour)
	n := &Notebook{Title: "Hunt", TimeRange: "7d", Cells: []Cell{
		{Kind: KindSearch, Query: "a=1", Text: "Why this search"},
		{Kind: KindSearch, Title: "Failed", Query: "b=1", Result: &Result{RanAt: ran, Error: "index missing"}},
		{Kind: KindSearch, Title: "Empty", Query: "c=1", Result: &Result{RanAt: ran}},
		{Kind: KindSearch, Title: "Events", Query: "d=1", Result: &Result{RanAt: ran, Kind: "events", Truncated: true, Matched: 3,
			Rows: []map[string]any{
				{"_raw": "raw", "user": "a", "n": 1.5, "ok": true, "l": []any{"x", "y"}, "m": map[string]any{"k": 1}, "nil": nil, "long": strings.Repeat("é", 400)},
				{"_raw": "raw2", "user": "b"},
			}}},
	}}
	md := string(Markdown(n, 1))
	for _, want := range []string{"### Search\n\nWhy this search", "_Not run yet._", "_Failed when it ran at", "index missing",
		"_No results when it ran at", ", more not kept", "; the first 1 shown", "1\\.5", "true", "x, y", `\{"k"\:1\}`, "…"} {
		if !strings.Contains(md, want) {
			t.Errorf("no %q in\n%s", want, md)
		}
	}
	if strings.Contains(md, "| _raw") || strings.Contains(md, "\\_raw") {
		t.Errorf("_raw shown:\n%s", md)
	}
	if cutUTF8("ab", 5) != "ab" {
		t.Error("cutUTF8")
	}
}

func TestSnapshotLimits(t *testing.T) {
	big := map[string]any{}
	for i := range 50 {
		big[fmt.Sprint(i)] = strings.Repeat("v", 100)
	}
	var list []any
	for i := range 150 {
		list = append(list, float64(i))
	}
	var rows []map[string]any
	for range 90 {
		rows = append(rows, map[string]any{"m": big, "l": list, "small": map[string]any{"a": 1}, "s": strings.Repeat("x", MaxValueLen)})
	}
	r := Snapshot("table", nil, rows, 90, false)
	if !r.Truncated || len(r.Rows) == 0 || len(r.Rows) == 90 {
		t.Errorf("rows %d truncated %v", len(r.Rows), r.Truncated)
	}
	row := r.Rows[0]
	if s, ok := row["m"].(string); !ok || !strings.HasSuffix(s, "…") {
		t.Errorf("big map = %T", row["m"])
	}
	if l := row["l"].([]any); len(l) != 100 {
		t.Errorf("list = %d", len(l))
	}
	if _, ok := row["small"].(map[string]any); !ok {
		t.Errorf("small map = %T", row["small"])
	}

	n := valid()
	n.Cells = append(n.Cells, Cell{Kind: KindSearch, Query: "a=1", Result: &Result{RanAt: time.Now()}})
	if sum := Summarize(n); sum.LastRun.IsZero() || sum.Searches != 2 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestDecodeStarterErrors(t *testing.T) {
	if _, err := decodeStarter([]byte("id: x\nunknown: 1\n")); err == nil {
		t.Error("an unknown key was taken")
	}
	if _, err := decodeStarter([]byte("id: starter-x\ntitle: \"\"\n")); err == nil {
		t.Error("an invalid starter was taken")
	}
}
