// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Every way a notebook request can be wrong is answered with its own
// status: bad bodies 400, starter hunts 403 to change, missing notebooks
// and cases 404, a stale version 412.
func TestNotebookErrors(t *testing.T) {
	ts, _ := newNotebookServer(t)
	starter := notebooks.Starters()[0].ID
	code, out, _, _ := nb(t, ts, "andy", "POST", "/api/notebooks", `{"title":"Hunt","sharing":"edit","cells":[{"kind":"search","query":"* | stats count by user"}]}`, "")
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	n := notebookOf(t, out)
	id, version := n.ID, out["version"].(string)

	for _, c := range []struct {
		user, method, path, body, ifMatch string
		code                              int
		want                              string
	}{
		{"andy", "POST", "/api/notebooks", `{`, "", 400, ""},
		{"andy", "POST", "/api/notebooks", `{"from":"nope"}`, "", 404, ""},
		{"andy", "POST", "/api/notebooks", `{"title":"x","cells":[{"kind":"search","query":"| bogus"}]}`, "", 400, "unknown command"},
		{"andy", "PUT", "/api/notebooks/" + id, `{`, "", 400, ""},
		{"andy", "PUT", "/api/notebooks/" + starter, `{"title":"x"}`, "", 403, "starter hunts can’t be changed"},
		{"andy", "PUT", "/api/notebooks/" + id, putBody(n, nil), "2001-01-01T00:00:00Z", 412, "changed this notebook since you opened it"},
		{"bea", "PUT", "/api/notebooks/" + id, putBody(n, func(m map[string]any) { m["sharing"] = "private" }), "", 403, "can change who this notebook is shared with"},
		{"andy", "POST", "/api/notebooks/" + id + "/cells", `{`, "", 400, ""},
		{"andy", "POST", "/api/notebooks/" + starter + "/cells", `{"kind":"note","text":"x"}`, "", 403, ""},
		{"andy", "POST", "/api/notebooks/" + id + "/run", `{`, "", 400, ""},
		{"andy", "POST", "/api/notebooks/" + id + "/run", `{"range":"forever"}`, "", 400, ""},
		{"andy", "POST", "/api/notebooks/" + id + "/run", `{"cell":"nope"}`, "", 404, "that search is not in the notebook"},
		{"andy", "POST", "/api/notebooks/nope/run", `{}`, "", 404, ""},
		{"andy", "POST", "/api/notebooks/" + id + "/cases", `{`, "", 400, ""},
		{"andy", "POST", "/api/notebooks/" + id + "/cases", `{"case_id":" "}`, "", 400, "case_id is required"},
		{"andy", "POST", "/api/notebooks/" + id + "/cases", `{"case_id":"CASE-nope"}`, "", 404, ""},
		{"andy", "DELETE", "/api/notebooks/" + starter, "", "", 403, "starter hunts are built in"},
		{"andy", "DELETE", "/api/notebooks/nope", "", "", 404, ""},
		{"bea", "DELETE", "/api/notebooks/" + id, "", "", 403, "or an admin can delete this notebook"},
	} {
		code, out, _, raw := nb(t, ts, c.user, c.method, c.path, c.body, c.ifMatch)
		if msg, _ := out["error"].(string); code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %s %.50s: %d %s", c.user, c.method, c.path, c.body, code, raw)
		}
	}

	// A cell added from the Search page, then a run over another range:
	// each search's result is kept.
	code, out, _, _ = nb(t, ts, "bea", "POST", "/api/notebooks/"+id+"/cells", `{"kind":"search","query":"* | head 1"}`, "")
	if code != http.StatusCreated || out["cell"] == "" {
		t.Fatalf("add cell: %d %v", code, out)
	}
	code, out, _, _ = nb(t, ts, "andy", "POST", "/api/notebooks/"+id+"/run", `{"range":"4h"}`, "")
	if code != http.StatusOK || out["saved"] != true || out["range"] != "4h" {
		t.Fatalf("run: %d %v", code, out)
	}
	ran := notebookOf(t, out)
	if r := ran.Cells[1].Result; r == nil || r.Error != "" {
		t.Errorf("added cell's result %+v", r)
	}
	if r := ran.Cells[0].Result; r == nil || r.Error != "" || r.Earliest != "-4h" || r.RanBy != "andy" {
		t.Errorf("good query result %+v", r)
	}
	// A viewer runs a starter: the results are only in the answer.
	code, out, _, _ = nb(t, ts, "vera", "POST", "/api/notebooks/"+starter+"/run", "", "")
	if code != http.StatusOK || out["saved"] != false {
		t.Errorf("viewer run: %d %v", code, out["saved"])
	}
	// The version the page read still saves; bea edits a notebook shared
	// for editing, which is recorded.
	_, out, _, _ = nb(t, ts, "andy", "GET", "/api/notebooks/"+id, "", "")
	version = out["version"].(string)
	cur := notebookOf(t, out)
	if code, out, _, _ := nb(t, ts, "bea", "PUT", "/api/notebooks/"+id, putBody(cur, func(m map[string]any) { m["title"] = "Hunt 2" }), version); code != http.StatusOK {
		t.Errorf("bea's save: %d %v", code, out)
	}
	// A copy of a saved notebook is named as a copy.
	code, out, _, _ = nb(t, ts, "bea", "POST", "/api/notebooks", `{"from":"`+id+`"}`, "")
	if code != http.StatusCreated || notebookOf(t, out).Title != "Hunt 2 (copy)" {
		t.Errorf("copy: %d %v", code, out)
	}
}

func TestNotebooksOff(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Notebooks = nil })
	for _, rt := range []struct{ method, path, body string }{
		{"POST", "/api/notebooks", `{"title":"x"}`}, {"DELETE", "/api/notebooks/x", ""},
	} {
		if code, out := do(t, ts, rt.method, rt.path, rt.body, true); code != http.StatusServiceUnavailable || out["error"] != errNotebooksOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
	if code, out := do(t, ts, "PUT", "/api/notebooks/x", `{"title":"x"}`, true); code == http.StatusOK {
		t.Errorf("put without notebooks: %d %v", code, out)
	}
	// The starter hunts need no store.
	if code, _ := do(t, ts, "GET", "/api/notebooks/"+notebooks.Starters()[0].ID, "", true); code != http.StatusOK {
		t.Errorf("a starter without notebooks: %d", code)
	}
}

func TestSearchErrText(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{search.ErrBusy, "Too many searches are running."},
		{search.ErrUserBusy, "Too many searches are running."},
		{context.DeadlineExceeded, "The search took too long."},
		{errors.New("boom"), "The search failed: boom"},
		{&search.QueryError{Msg: "unknown field"}, "unknown field"},
	} {
		if got := searchErrText(c.err); !strings.Contains(got, c.want) {
			t.Errorf("searchErrText(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	if got := queryErrText(errors.New("plain")); got != "plain" {
		t.Errorf("queryErrText = %q", got)
	}
}
