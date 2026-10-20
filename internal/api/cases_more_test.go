// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// failCases is a case store whose reads and writes fail with err while it
// is set.
type failCases struct {
	cases.Store
	mu  sync.Mutex
	err error
}

func (f *failCases) failing(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *failCases) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *failCases) Create(ctx context.Context, c *cases.Case) error {
	if err := f.get(); err != nil {
		return err
	}
	return f.Store.Create(ctx, c)
}

func (f *failCases) Get(ctx context.Context, id string) (*cases.Case, error) {
	if err := f.get(); err != nil {
		return nil, err
	}
	return f.Store.Get(ctx, id)
}

func (f *failCases) Modify(ctx context.Context, id string, change func(c *cases.Case) (bool, error)) (*cases.Case, error) {
	if err := f.get(); err != nil {
		return nil, err
	}
	return f.Store.Modify(ctx, id, change)
}

func (f *failCases) Search(ctx context.Context, flt cases.Filter) ([]*cases.Case, int, error) {
	if err := f.get(); err != nil {
		return nil, 0, err
	}
	return f.Store.Search(ctx, flt)
}

// Without the cases store every case route says so; each check of the
// request is answered 400; a store that fails is 502, and one that keeps
// losing races is 409.
func TestCasesErrors(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Cases = nil })
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/cases"}, {"GET", "/api/cases/summary"}, {"GET", "/api/cases/x"}, {"POST", "/api/cases"},
		{"PATCH", "/api/cases/x"}, {"POST", "/api/cases/x/findings"}, {"DELETE", "/api/cases/x/findings/f"},
		{"POST", "/api/cases/x/entries"}, {"DELETE", "/api/cases/x/entries/e"}, {"POST", "/api/cases/x/entities"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "{}", true); code != http.StatusServiceUnavailable || out["error"] != errCasesOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}

	store := &failCases{Store: cases.NewMemory()}
	var srv *Server
	ts, _ = newTestServerWith(t, func(s *Server) { s.Cases, srv = store, s })
	code, out := do(t, ts, "POST", "/api/cases", `{"title":"Brute force","severity":"high","owner":"admin"}`, true)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	c := out["case"].(map[string]any)
	id := c["id"].(string)
	if c["status"] != findings.StatusInProgress {
		t.Errorf("a case with an owner starts in progress: %v", c["status"])
	}
	for _, c := range []struct {
		method, path, body string
		want               string
	}{
		{"GET", "/api/cases?limit=0", "", "limit must be 1-1000"},
		{"GET", "/api/cases?limit=x", "", "limit must be 1-1000"},
		{"POST", "/api/cases", `{`, ""},
		{"POST", "/api/cases", `{"title":"  "}`, "title is required"},
		{"POST", "/api/cases", `{"title":"x","severity":"apocalyptic"}`, ""},
		{"POST", "/api/cases", `{"title":"x","findings":[` + strings.Repeat(`"f",`, cases.MaxFindings) + `"f"]}`, "too many findings"},
		{"PATCH", "/api/cases/" + id, `{`, ""},
		{"PATCH", "/api/cases/" + id, `{"severity":"apocalyptic"}`, ""},
		{"PATCH", "/api/cases/" + id, `{"status":"resolved","disposition":"maybe"}`, ""},
		{"PATCH", "/api/cases/" + id, `{"close_findings":true}`, "set the case to resolved or closed"},
		{"POST", "/api/cases/" + id + "/findings", `{`, ""},
		{"POST", "/api/cases/" + id + "/findings", `{"ids":[]}`, "ids must list 1-500 findings"},
		{"POST", "/api/cases/" + id + "/entries", `{`, ""},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"note","text":"` + strings.Repeat("x", cases.MaxTextLen+1) + `"}`, "text is too long"},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"note"}`, "a note needs text"},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"search"}`, "query is required"},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"search","query":"| bogus"}`, ""},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"event"}`, "event is required"},
		{"POST", "/api/cases/" + id + "/entries", `{"kind":"drawing"}`, "kind must be note, search or event"},
		{"POST", "/api/cases/" + id + "/entities", `{`, ""},
		{"POST", "/api/cases/" + id + "/entities", `{"field":"user","value":" "}`, "field and value are required"},
	} {
		code, out := do(t, ts, c.method, c.path, c.body, true)
		if msg, _ := out["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %.60s: %d %v", c.method, c.path, c.body, code, out)
		}
	}

	// A search kept on the timeline, and an entity added once.
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"search","query":"* | stats count by src","earliest":"-1h"}`, true)
	if e, _ := out["entry"].(map[string]any); code != http.StatusCreated || e["query"] != "* | stats count by src" || e["earliest"] != "-1h" || e["rows"] == nil {
		t.Errorf("search entry: %d %v", code, out)
	}
	for i := 0; i < 2; i++ {
		code, out = do(t, ts, "POST", "/api/cases/"+id+"/entities", `{"field":"user","value":"bob"}`, true)
		if code != http.StatusOK || len(out["entities"].([]any)) != 1 {
			t.Errorf("entity %d: %d %v", i, code, out)
		}
	}
	if code, _ := do(t, ts, "POST", "/api/cases/nope/entities", `{"field":"user","value":"bob"}`, true); code != http.StatusNotFound {
		t.Errorf("entity on a missing case: %d", code)
	}

	// Closing a case closes its open findings, with the disposition, and
	// says which could not be read.
	now := time.Now().UTC()
	for _, f := range []*findings.Finding{
		{ID: "f-open", Title: "Brute force", Status: findings.StatusNew, Severity: "high", Created: now},
		{ID: "f-done", Title: "Old", Status: findings.StatusClosed, Severity: "low", Created: now},
	} {
		if err := srv.Findings.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/findings", `{"ids":["f-open","f-done","f-missing"]}`, true)
	if failed, _ := out["failed"].(map[string]any); code != http.StatusOK || failed["f-missing"] == nil {
		t.Fatalf("link: %d %v", code, out)
	}
	if err := srv.Findings.Delete(context.Background(), "f-done"); err != nil {
		t.Fatal(err)
	}
	code, out = do(t, ts, "PATCH", "/api/cases/"+id, `{"status":"resolved","close_findings":true,"disposition":"true_positive"}`, true)
	if code != http.StatusOK || out["findings_closed"] != float64(1) || out["failed"].(map[string]any)["f-done"] == nil {
		t.Fatalf("close: %d %v", code, out)
	}
	if f, err := srv.Findings.Get(context.Background(), "f-open"); err != nil || f.Status != findings.StatusResolved || f.Disposition != "true_positive" {
		t.Errorf("finding after close: %+v %v", f, err)
	}
	code, out = do(t, ts, "GET", "/api/cases/"+id, "", true)
	if code != http.StatusOK || len(out["missing_findings"].([]any)) != 1 {
		t.Errorf("get with a missing finding: %d %v", code, out["missing_findings"])
	}

	// A case without a title is named after its first finding.
	code, out = do(t, ts, "POST", "/api/cases", `{"findings":["f-open"]}`, true)
	if code != http.StatusCreated || out["case"].(map[string]any)["title"] != "Brute force" {
		t.Errorf("titled after its finding: %d %v", code, out)
	}

	store.failing(errDown)
	for _, rt := range []struct{ method, path, body string }{
		{"GET", "/api/cases", ""}, {"GET", "/api/cases/summary", ""}, {"POST", "/api/cases", `{"title":"x"}`},
		{"GET", "/api/cases/" + id, ""}, {"POST", "/api/cases/" + id + "/entities", `{"field":"user","value":"eve"}`},
	} {
		if code, out := do(t, ts, rt.method, rt.path, rt.body, true); code != http.StatusBadGateway {
			t.Errorf("%s %s with a failing store: %d %v", rt.method, rt.path, code, out)
		}
	}
	store.failing(cases.ErrBusy)
	if code, out := do(t, ts, "PATCH", "/api/cases/"+id, `{"severity":"low"}`, true); code != http.StatusConflict || out["error"] != errCaseBusy.Error() {
		t.Errorf("busy: %d %v", code, out)
	}
	store.failing(nil)
}

// Linking findings needs the findings store.
func TestAddCaseFindingsWithoutFindings(t *testing.T) {
	s := &Server{Cases: cases.NewMemory()}
	if _, _, err := s.addCaseFindings(context.Background(), "x", []string{"f"}, "admin"); !errors.Is(err, errDetectionsOff) {
		t.Errorf("no findings store: %v", err)
	}
}
