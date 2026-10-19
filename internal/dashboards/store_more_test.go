package dashboards

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// memBackend keeps dashboards in memory, recording who changed them.
type memBackend struct {
	mu      sync.Mutex
	items   map[string]Stored
	listErr error
}

func (m *memBackend) List() ([]Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []Stored
	for _, it := range m.items {
		out = append(out, it)
	}
	return out, nil
}

func (m *memBackend) Get(id string) (Stored, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[id]
	return it, ok
}

func (m *memBackend) Change(_ context.Context, by, id string, fn func(cur *Stored) (*Dashboard, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cur *Stored
	if it, ok := m.items[id]; ok {
		cur = &it
	}
	next, err := fn(cur)
	if err != nil {
		return err
	}
	if next == nil {
		delete(m.items, id)
		return nil
	}
	m.items[id] = Stored{Dashboard: next, By: by, Node: "n1", At: "2026-01-01T00:00:00Z"}
	return nil
}

func panel(title, q string) Panel { return Panel{Title: title, Query: q} }

func TestStoreWithBackend(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.Shared() {
		t.Error("shared before a backend")
	}
	b := &memBackend{items: map[string]Stored{}}
	s.UseBackend(b)
	if !s.Shared() {
		t.Error("not shared with a backend")
	}

	d := &Dashboard{ID: "auth", Title: "Auth", Panels: []Panel{panel("Failures", "datamodel=Authentication action=failure | stats count")}}
	if err := s.Create(ctx, "sam", d); err != nil {
		t.Fatal(err)
	}
	if d.TimeRange != "24h" || d.Panels[0].Viz != VizSingle {
		t.Errorf("defaults = %+v", d)
	}
	if err := s.Create(ctx, "sam", &Dashboard{ID: "auth", Title: "Again"}); !errors.Is(err, ErrExists) {
		t.Errorf("create twice = %v", err)
	}
	if err := s.Create(ctx, "sam", &Dashboard{ID: "x"}); err == nil {
		t.Error("an invalid dashboard was created")
	}
	if err := s.Create(ctx, "sam", &Dashboard{ID: "zeta", Title: "auth"}); err != nil {
		t.Fatal(err)
	}
	list, problems, err := s.List()
	// Same title in another case: by ID.
	if err != nil || len(problems) != 0 || len(list) != 2 || list[0].ID != "auth" || list[1].ID != "zeta" {
		t.Errorf("list = %v %v %v", list, problems, err)
	}
	got, etag, err := s.GetETag("auth")
	if err != nil || got.Title != "Auth" || etag != ETag(got) || etag == "" {
		t.Errorf("get = %+v %q %v", got, etag, err)
	}
	if _, _, err := s.GetETag("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get unknown = %v", err)
	}
	if !s.Exists("auth") || s.Exists("nope") {
		t.Error("Exists")
	}

	// Update with the version read; a stale one names who changed it.
	saved, err := s.Update(ctx, "kim", "auth", etag, func(d *Dashboard) error {
		d.Title = "Authentication"
		d.Panels = append(d.Panels, panel("Top", "datamodel=Authentication | top user"))
		return nil
	})
	if err != nil || saved.Title != "Authentication" || len(saved.Panels) != 2 || saved.Panels[1].Viz != VizBar {
		t.Fatalf("update = %+v %v", saved, err)
	}
	if len(got.Panels) != 1 {
		t.Error("the update changed the copy read before")
	}
	_, err = s.Update(ctx, "kim", "auth", etag, func(*Dashboard) error { return nil })
	var stale *detect.StaleError
	if !errors.As(err, &stale) || stale.By != "kim" || stale.Node != "n1" {
		t.Errorf("stale update = %#v", err)
	}
	if _, err := s.Update(ctx, "kim", "nope", "", func(*Dashboard) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("update unknown = %v", err)
	}
	boom := errors.New("boom")
	if _, err := s.Update(ctx, "kim", "auth", "", func(*Dashboard) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("update refused = %v", err)
	}
	if _, err := s.Update(ctx, "kim", "auth", "", func(d *Dashboard) error { d.Title = ""; return nil }); err == nil {
		t.Error("an update made it invalid")
	}

	// PutIf of a version that is not there, or another.
	if err := s.PutIf(ctx, "kim", &Dashboard{ID: "new-one", Title: "New"}, "abc"); !errors.As(err, &stale) || stale.By != "" {
		t.Errorf("putif missing = %#v", err)
	}
	if err := s.PutIf(ctx, "kim", &Dashboard{ID: "auth", Title: "Over"}, "abc"); !errors.As(err, &stale) || stale.By != "kim" {
		t.Errorf("putif other = %#v", err)
	}

	// DeleteIf likewise.
	if err := s.DeleteIf(ctx, "kim", "auth", "abc"); !errors.As(err, &stale) {
		t.Errorf("deleteif stale = %v", err)
	}
	if err := s.DeleteIf(ctx, "kim", "Bad/ID", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleteif bad id = %v", err)
	}
	if err := s.DeleteIf(ctx, "kim", "auth", ETag(saved)); err != nil {
		t.Errorf("deleteif = %v", err)
	}
	if s.Exists("auth") {
		t.Error("still there")
	}

	b.listErr = errors.New("settings unreadable")
	if _, _, err := s.List(); err == nil {
		t.Error("a backend error was dropped")
	}
}

func TestStoreFolderEdges(t *testing.T) {
	ctx := context.Background()
	if _, err := NewStore(""); err == nil {
		t.Error("a store with no folder")
	}
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "dash"))

	// A hold that refuses stops the change; one that is given is released.
	s.Hold = func() (func(), error) { return nil, errors.New("moving to shared settings") }
	if err := s.Put(&Dashboard{ID: "one", Title: "One"}); err == nil || !strings.Contains(err.Error(), "moving") {
		t.Errorf("held = %v", err)
	}
	released := 0
	s.Hold = func() (func(), error) { return func() { released++ }, nil }
	if err := s.Create(ctx, "sam", &Dashboard{ID: "one", Title: "One"}); err != nil || released != 1 {
		t.Errorf("create = %v, released %d", err, released)
	}
	s.Hold = nil

	// A file that does not load counts as one with no version: Create
	// refuses, PutIf with a version is stale, and a plain save is fine.
	broken := filepath.Join(s.Dir, "broken.yaml")
	os.WriteFile(broken, []byte("id: broken\ntitle: [\n"), 0o600)
	if !s.Exists("broken") || s.Exists("Bad/ID") {
		t.Error("Exists")
	}
	if err := s.Create(ctx, "sam", &Dashboard{ID: "broken", Title: "B"}); !errors.Is(err, ErrExists) {
		t.Errorf("create over broken = %v", err)
	}
	if err := s.PutIf(ctx, "sam", &Dashboard{ID: "broken", Title: "B"}, "abc"); err == nil {
		t.Error("putif over broken with a version")
	}
	if err := s.Put(&Dashboard{ID: "broken", Title: "B"}); err != nil {
		t.Errorf("put over broken = %v", err)
	}
	if _, err := s.Update(ctx, "sam", "Bad/ID", "", func(*Dashboard) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("update bad id = %v", err)
	}

	// A folder where a dashboard file belongs.
	if err := os.Mkdir(filepath.Join(s.Dir, "dir-one.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.Dir, "dir-one.yaml", "inside"), []byte("x"), 0o600)
	if _, err := s.Get("dir-one"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("get a folder = %v", err)
	}
	if err := s.Delete("dir-one"); err == nil {
		t.Error("deleted a folder")
	}

	// The dashboards folder is a file.
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("x"), 0o600)
	fs, _ := NewStore(file)
	if err := fs.Put(&Dashboard{ID: "one", Title: "One"}); err == nil {
		t.Error("saved under a file")
	}
	if runtime.GOOS != "windows" {
		if _, _, err := (&Store{Dir: "["}).List(); err == nil {
			t.Error("a bad pattern was listed")
		}
	}

	// IDs from titles.
	for title, want := range map[string]string{
		"a":                        "dashboard",
		"Posture":                  "my-posture",
		strings.Repeat("abc-", 20): strings.Repeat("abc-", 12) + "ab",
		"One":                      "one-2",
	} {
		if got := s.NewID(title); got != want {
			t.Errorf("NewID(%q) = %q, want %q", title, got, want)
		}
	}
	if IsBuiltin(s.NewID("malware")) {
		t.Error("a built-in ID was given")
	}
	if ETag(nil) != "" {
		t.Error("ETag(nil)")
	}
}

func TestValidateMore(t *testing.T) {
	var panels []Panel
	for range MaxPanels + 1 {
		panels = append(panels, panel("p", "* | stats count"))
	}
	d := &Dashboard{ID: "many", Title: strings.Repeat("t", 201), TimeRange: "1s", Refresh: "soon", Panels: panels}
	d.Defaults()
	d.Panels[0].Query = ""
	err := d.Validate()
	for _, want := range []string{"200 characters", "between 1m and 366d", "refresh:", "at most 40 panels", "panel 1 (p): query is required"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestRunEdges(t *testing.T) {
	ctx := context.Background()
	ex := &fakeExec{respond: func(q *query.Query) (*search.Result, error) {
		if q.Latest != "" {
			return nil, context.DeadlineExceeded
		}
		return &search.Result{Kind: "table", Columns: []string{"user"}, Rows: []search.Row{{"user": "alice"}}}, nil
	}}
	r := &Runner{Engine: ex}
	out := r.Run(ctx, []Panel{{Title: "a", Query: "* | stats count by user", Viz: VizSingle, Compare: true}}, "-1h")
	if len(out) != 1 || out[0].Value != "alice" || out[0].Field != "user" || !strings.Contains(out[0].CompareNote, "timed out") || out[0].Earliest != "-1h" {
		t.Errorf("run = %+v", out)
	}

	if f, v := SingleValue(nil, "x"); f != "x" || v != nil {
		t.Errorf("nil = %s %v", f, v)
	}
	if f, v := SingleValue(&search.Result{Columns: []string{"a"}, Rows: []search.Row{{"a": "x"}, {"a": "y"}}}, ""); f != "rows" || v != int64(2) {
		t.Errorf("rows = %s %v", f, v)
	}
	if f, v := SingleValue(&search.Result{Columns: []string{"a", "n"}, Rows: []search.Row{{"a": "x", "n": 3}}}, ""); f != "n" || v != 3 {
		t.Errorf("int = %s %v", f, v)
	}
	if _, _, ok := PreviousPeriod("-0h"); ok {
		t.Error("a zero range has a previous period")
	}
	if _, _, ok := PreviousPeriod("-99999999999999999999h"); ok {
		t.Error("an overflowing range has a previous period")
	}
}
