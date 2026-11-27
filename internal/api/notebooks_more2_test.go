// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// flakyNotebooks is a notebook store that fails while down is set.
type flakyNotebooks struct {
	notebooks.Store
	down atomic.Bool
}

var errNotebooksDown = errors.New("notebooks down")

func (f *flakyNotebooks) Create(ctx context.Context, n *notebooks.Notebook) error {
	if f.down.Load() {
		return errNotebooksDown
	}
	return f.Store.Create(ctx, n)
}

func (f *flakyNotebooks) Modify(ctx context.Context, id string, change func(n *notebooks.Notebook) (bool, error)) (*notebooks.Notebook, error) {
	if f.down.Load() {
		return nil, errNotebooksDown
	}
	return f.Store.Modify(ctx, id, change)
}

func (f *flakyNotebooks) Delete(ctx context.Context, id string) error {
	if f.down.Load() {
		return errNotebooksDown
	}
	return f.Store.Delete(ctx, id)
}

func (f *flakyNotebooks) Search(ctx context.Context, flt notebooks.Filter) ([]*notebooks.Summary, int, error) {
	if f.down.Load() {
		return nil, 0, errNotebooksDown
	}
	return f.Store.Search(ctx, flt)
}

// A search cell whose search fails keeps the reason as its result; the
// run itself succeeds. A cell whose query does not parse is never added.
func TestNotebookRunKeepsCellErrors(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Engine = &search.Engine{Store: searchFails{&fakeOS{}}, Assets: s.Assets}
	})
	_, out := do(t, ts, "POST", "/api/notebooks", `{"title":"  Hunt  "}`, true)
	n := notebookOf(t, out)
	if n.Title != "Hunt" {
		t.Errorf("title %q", n.Title)
	}
	if code, out := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/cells", `{"kind":"search","query":"user=bob | stats"}`, true); code != http.StatusBadRequest {
		t.Errorf("add a query that does not parse: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/cells", `{"kind":"search","query":"user=bob"}`, true); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	code, out := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/run", `{"range":"1h"}`, true)
	if code != http.StatusOK || out["saved"] != true {
		t.Fatalf("run: %d %v", code, out)
	}
	ran := notebookOf(t, out)
	var errs []string
	for _, c := range ran.Cells {
		if c.Result != nil {
			errs = append(errs, c.Result.Error)
		}
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "The search failed") {
		t.Errorf("cell errors %q", errs)
	}
	if code, _ := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/run", `{"range":"2s"}`, true); code != http.StatusBadRequest {
		t.Errorf("bad range: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/run", `{"cell":"nope"}`, true); code != http.StatusNotFound {
		t.Errorf("unknown cell: %d", code)
	}
}

// A notebook store that fails answers 502 for every change and the list,
// never a list that looks empty.
func TestNotebookStoreDown(t *testing.T) {
	nbs := &flakyNotebooks{Store: notebooks.NewMemory()}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Notebooks = nbs })
	_, out := do(t, ts, "POST", "/api/notebooks", `{"title":"Hunt"}`, true)
	n := notebookOf(t, out)
	if code, out := do(t, ts, "POST", "/api/notebooks/"+n.ID+"/cells", `{"kind":"search","query":"user=bob"}`, true); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	_, out = do(t, ts, "POST", "/api/cases", `{"title":"Linked"}`, true)
	caseID := out["case"].(map[string]any)["id"].(string)
	// Unlinking a case that was never linked changes nothing.
	if code, out := do(t, ts, "DELETE", "/api/notebooks/"+n.ID+"/cases/"+caseID, "", true); code != http.StatusOK {
		t.Errorf("unlink a case never linked: %d %v", code, out)
	}
	nbs.down.Store(true)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/notebooks", ""},
		{"POST", "/api/notebooks", `{"title":"Another"}`},
		{"POST", "/api/notebooks/" + n.ID + "/run", ``},
		{"DELETE", "/api/notebooks/" + n.ID, ""},
	} {
		if code, out := do(t, ts, c.method, c.path, c.body, true); code != http.StatusBadGateway {
			t.Errorf("%s %s while down: %d %v", c.method, c.path, code, out)
		}
	}
	nbs.down.Store(false)
	if code, _ := do(t, ts, "GET", "/api/notebooks/"+n.ID, "", true); code != http.StatusOK {
		t.Errorf("the notebook is gone: %d", code)
	}
}

// Without a notebook store the list still offers the starter hunts and
// says why there are no notebooks; a notebook cannot be opened.
func TestNotebookListWithoutStore(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Notebooks = nil })
	code, out := do(t, ts, "GET", "/api/notebooks", "", true)
	if code != http.StatusOK || out["error"] != errNotebooksOff.Error() || len(out["starters"].([]any)) == 0 {
		t.Errorf("list: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/notebooks/NB-20260101-0123456789abcdef", "", true); code < 400 {
		t.Errorf("open: %d", code)
	}
}
