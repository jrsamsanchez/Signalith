// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newNotebookServer has a viewer (vera), two analysts (andy, bea) and the
// admin.
func newNotebookServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst, "bea": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
	})
	return ts, srv
}

// nb calls the notebook API as user ("admin" is the built-in admin), with
// an If-Match header when ifMatch is set.
func nb(t *testing.T, ts *httptest.Server, user, method, path, body, ifMatch string) (int, map[string]any, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	pass := "role-password"
	if user == "admin" {
		pass = "s3cret-pass"
	}
	req.SetBasicAuth(user, pass)
	if ifMatch != "" {
		req.Header.Set("If-Match", `"`+ifMatch+`"`)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out, resp.Header, string(raw)
}

func notebookOf(t *testing.T, body map[string]any) *notebooks.Notebook {
	t.Helper()
	b, _ := json.Marshal(body["notebook"])
	var n notebooks.Notebook
	if err := json.Unmarshal(b, &n); err != nil || n.ID == "" {
		t.Fatalf("no notebook in %v (%v)", body, err)
	}
	return &n
}

// putBody is the page's save of n with changes.
func putBody(n *notebooks.Notebook, change func(m map[string]any)) string {
	m := map[string]any{"title": n.Title, "description": n.Description, "techniques": n.Techniques, "time_range": n.TimeRange, "cells": n.Cells}
	if change != nil {
		change(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestNotebookStartersForEveryone(t *testing.T) {
	ts, _ := newNotebookServer(t)
	code, body, _, _ := nb(t, ts, "vera", "GET", "/api/notebooks", "", "")
	if code != 200 || len(body["starters"].([]any)) != 7 || len(body["notebooks"].([]any)) != 0 {
		t.Fatalf("list = %d %v", code, body)
	}
	code, body, _, _ = nb(t, ts, "vera", "GET", "/api/notebooks?technique=T1110", "", "")
	if st := body["starters"].([]any); code != 200 || len(st) != 1 || st[0].(map[string]any)["id"] != "starter-password-spraying" {
		t.Errorf("by technique = %v", body["starters"])
	}
	code, body, _, _ = nb(t, ts, "vera", "GET", "/api/notebooks/starter-powershell", "", "")
	if can := body["can"].(map[string]any); code != 200 || can["edit"] != false || can["copy"] != false || body["version"] != nil {
		t.Errorf("viewer starter = %d %v", code, body)
	}
	// A viewer runs a starter hunt: the results come back, nothing is saved.
	code, body, _, _ = nb(t, ts, "vera", "POST", "/api/notebooks/starter-password-spraying/run", "", "")
	if code != 200 || body["saved"] != false {
		t.Fatalf("viewer run = %d %v", code, body)
	}
	ran := 0
	for _, c := range notebookOf(t, body).Cells {
		if c.Kind == notebooks.KindSearch {
			if c.Result == nil || c.Result.Error != "" || c.Result.RanBy != "vera" || c.Result.Earliest != "-7d" {
				t.Errorf("cell %s result %+v", c.ID, c.Result)
			}
			ran++
		}
	}
	if ran != 3 {
		t.Errorf("%d searches ran", ran)
	}
	if code, _, _, _ := nb(t, ts, "admin", "PUT", "/api/notebooks/starter-powershell", `{"title":"x"}`, ""); code != 403 {
		t.Errorf("admin changed a starter: %d", code)
	}
	if code, _, _, _ := nb(t, ts, "admin", "DELETE", "/api/notebooks/starter-powershell", "", ""); code != 403 {
		t.Errorf("admin deleted a starter: %d", code)
	}
}

func TestNotebookSharing(t *testing.T) {
	ts, _ := newNotebookServer(t)
	code, body, _, _ := nb(t, ts, "andy", "POST", "/api/notebooks", `{"from":"starter-powershell"}`, "")
	if code != 201 {
		t.Fatalf("copy starter = %d %v", code, body)
	}
	n := notebookOf(t, body)
	if n.Owner != "andy" || n.Sharing != notebooks.Private || n.From != "starter-powershell" || n.Starter || n.Title != "Suspicious PowerShell" || len(n.Cells) < 3 {
		t.Fatalf("copy = %+v", n)
	}
	path := "/api/notebooks/" + n.ID
	// Private: bea and vera cannot see it at all; the admin can.
	for _, u := range []string{"bea", "vera"} {
		if code, _, _, _ := nb(t, ts, u, "GET", path, "", ""); code != 404 {
			t.Errorf("%s sees a private notebook: %d", u, code)
		}
		if _, body, _, _ := nb(t, ts, u, "GET", "/api/notebooks", "", ""); len(body["notebooks"].([]any)) != 0 {
			t.Errorf("%s lists a private notebook", u)
		}
	}
	if code, _, _, _ := nb(t, ts, "bea", "POST", "/api/notebooks", `{"from":"`+n.ID+`"}`, ""); code != 404 {
		t.Errorf("bea copied a private notebook: %d", code)
	}
	if code, _, _, _ := nb(t, ts, "admin", "GET", path, "", ""); code != 200 {
		t.Errorf("admin = %d", code)
	}

	// Shared for reading: everyone sees it; bea may not change it, nor
	// keep run results in it, but may copy it.
	code, body, _, _ = nb(t, ts, "andy", "PUT", path, putBody(n, func(m map[string]any) { m["sharing"] = "read" }), n.Updated.Format("2006-01-02T15:04:05.999999999Z07:00"))
	if code != 200 {
		t.Fatalf("share = %d %v", code, body)
	}
	n = notebookOf(t, body)
	if code, body, _, _ := nb(t, ts, "vera", "GET", path, "", ""); code != 200 || body["can"].(map[string]any)["edit"] != false {
		t.Errorf("vera on shared = %d %v", code, body)
	}
	if code, _, _, _ := nb(t, ts, "bea", "PUT", path, putBody(n, nil), ""); code != 403 {
		t.Errorf("bea changed a read-shared notebook: %d", code)
	}
	if code, body, _, _ := nb(t, ts, "bea", "POST", path+"/run", "", ""); code != 200 || body["saved"] != false {
		t.Errorf("bea run = %d %v", code, body)
	}
	code, body, _, _ = nb(t, ts, "bea", "POST", "/api/notebooks", `{"from":"`+n.ID+`"}`, "")
	if c := notebookOf(t, body); code != 201 || c.Owner != "bea" || c.Sharing != notebooks.Private || c.Title != "Suspicious PowerShell (copy)" {
		t.Errorf("bea copy = %d %+v", code, c)
	}

	// Shared for editing: bea changes the cells, but not the sharing, and
	// cannot delete it.
	_, body, _, _ = nb(t, ts, "andy", "PUT", path, putBody(n, func(m map[string]any) { m["sharing"] = "edit" }), "")
	n = notebookOf(t, body)
	code, body, _, _ = nb(t, ts, "bea", "PUT", path, putBody(n, func(m map[string]any) { m["title"] = "Bea's hunt" }), "")
	if code != 200 || notebookOf(t, body).Title != "Bea's hunt" || notebookOf(t, body).UpdatedBy != "bea" || notebookOf(t, body).Owner != "andy" {
		t.Errorf("bea edit = %d %v", code, body)
	}
	if code, _, _, _ := nb(t, ts, "bea", "PUT", path, putBody(n, func(m map[string]any) { m["sharing"] = "private" }), ""); code != 403 {
		t.Errorf("bea changed the sharing: %d", code)
	}
	if code, _, _, _ := nb(t, ts, "bea", "DELETE", path, "", ""); code != 403 {
		t.Errorf("bea deleted: %d", code)
	}
	if code, _, _, _ := nb(t, ts, "vera", "PUT", path, putBody(n, nil), ""); code != 403 {
		t.Errorf("viewer saved: %d", code)
	}
	// A save over a version bea changed since is refused, naming her.
	code, body, _, _ = nb(t, ts, "andy", "PUT", path, putBody(n, nil), n.Updated.Format("2006-01-02T15:04:05.999999999Z07:00"))
	if code != 412 || body["by"] != "bea" {
		t.Errorf("stale save = %d %v", code, body)
	}
	if code, _, _, _ := nb(t, ts, "andy", "DELETE", path, "", ""); code != 204 {
		t.Errorf("owner delete = %d", code)
	}
	if code, _, _, _ := nb(t, ts, "andy", "GET", path, "", ""); code != 404 {
		t.Errorf("deleted notebook = %d", code)
	}
}

func TestNotebookRunKeepsResults(t *testing.T) {
	ts, _ := newNotebookServer(t)
	_, body, _, _ := nb(t, ts, "andy", "POST", "/api/notebooks", `{"title":"Spray","techniques":["T1110.003"],"time_range":"24h","cells":[
		{"kind":"markdown","text":"<img src=x onerror=alert(1)> **why**"},
		{"kind":"search","title":"Sources","query":"datamodel=Authentication action=failure | stats count by src"}]}`, "")
	n := notebookOf(t, body)
	path := "/api/notebooks/" + n.ID
	code, body, _, _ := nb(t, ts, "andy", "POST", path+"/run", `{"cell":"`+n.Cells[1].ID+`"}`, "")
	if code != 200 || body["saved"] != true {
		t.Fatalf("run = %d %v", code, body)
	}
	_, body, _, _ = nb(t, ts, "andy", "GET", path, "", "")
	n = notebookOf(t, body)
	r := n.Cells[1].Result
	if r == nil || r.RanBy != "andy" || r.Earliest != "-24h" || len(r.Rows) != 2 || r.Kind != "table" {
		t.Fatalf("saved result %+v", r)
	}
	// The markdown is kept as text; the page renders it without HTML.
	if n.Cells[0].Text != "<img src=x onerror=alert(1)> **why**" {
		t.Errorf("note = %q", n.Cells[0].Text)
	}
	// A save that leaves the query alone keeps the result; one that
	// changes it drops it.
	_, body, _, _ = nb(t, ts, "andy", "PUT", path, putBody(n, func(m map[string]any) { m["title"] = "Spray 2" }), "")
	if notebookOf(t, body).Cells[1].Result == nil {
		t.Error("result dropped by a title change")
	}
	n.Cells[1].Query += " | head 1"
	_, body, _, _ = nb(t, ts, "andy", "PUT", path, putBody(n, nil), "")
	if notebookOf(t, body).Cells[1].Result != nil {
		t.Error("result kept for a changed query")
	}
	if code, body, _, _ := nb(t, ts, "andy", "POST", path+"/run", `{"cell":"nope"}`, ""); code != 404 {
		t.Errorf("unknown cell = %d %v", code, body)
	}
	// Add a search from the Search page.
	code, body, _, _ = nb(t, ts, "andy", "POST", path+"/cells", `{"kind":"search","title":"More","query":"datamodel=Endpoint | stats count by dest"}`, "")
	if code != 201 || len(notebookOf(t, body).Cells) != 3 || body["cell"] == "" {
		t.Errorf("add cell = %d %v", code, body)
	}
	if code, body, _, _ := nb(t, ts, "andy", "POST", path+"/cells", `{"kind":"search","query":"a=1 |"}`, ""); code != 400 || body["problems"] == nil {
		t.Errorf("bad cell = %d %v", code, body)
	}
	if code, body, _, _ := nb(t, ts, "andy", "PUT", path, putBody(n, func(m map[string]any) { m["techniques"] = []string{"T0000"} }), ""); code != 400 {
		t.Errorf("bad technique = %d %v", code, body)
	}
	// The Markdown download.
	code, _, h, md := nb(t, ts, "andy", "GET", path+"/markdown", "", "")
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.Contains(h.Get("Content-Disposition"), "attachment") || !strings.Contains(md, "# Spray") {
		t.Errorf("markdown = %d %v %q", code, h, md)
	}
}

func TestNotebookLinksToCase(t *testing.T) {
	ts, s := newNotebookServer(t)
	_, body, _, _ := nb(t, ts, "andy", "POST", "/api/notebooks", `{"from":"starter-password-spraying"}`, "")
	n := notebookOf(t, body)
	path := "/api/notebooks/" + n.ID
	nb(t, ts, "andy", "POST", path+"/run", "", "")
	_, body, _, _ = nb(t, ts, "andy", "POST", "/api/cases", `{"title":"Spray from 203.0.113.9","severity":"high"}`, "")
	caseID := body["case"].(map[string]any)["id"].(string)

	if code, _, _, _ := nb(t, ts, "andy", "POST", path+"/cases", `{"case_id":"CASE-nope"}`, ""); code != 404 {
		t.Errorf("unknown case = %d", code)
	}
	if code, _, _, _ := nb(t, ts, "bea", "POST", path+"/cases", `{"case_id":"`+caseID+`"}`, ""); code != 404 {
		t.Errorf("bea linked a private notebook: %d", code)
	}
	code, body, _, _ := nb(t, ts, "andy", "POST", path+"/cases", `{"case_id":"`+caseID+`","with_results":true}`, "")
	if code != 200 || len(notebookOf(t, body).Cases) != 1 {
		t.Fatalf("link = %d %v", code, body)
	}
	c, _ := s.Cases.Get(context.Background(), caseID)
	kinds := map[string]int{}
	var entry string
	for _, e := range c.Entries {
		kinds[e.Kind]++
		if e.Kind == cases.KindNotebook {
			entry = e.ID
			if e.NotebookID != n.ID || e.Text != n.Title || e.Author != "andy" {
				t.Errorf("entry %+v", e)
			}
		}
	}
	if kinds[cases.KindNotebook] != 1 || kinds[cases.KindSearch] != 3 {
		t.Errorf("case entries %v", kinds)
	}
	// Linking again adds nothing, even with results, until a result
	// changes; the notebook entry comes off the case only by unlinking.
	nb(t, ts, "andy", "POST", path+"/cases", `{"case_id":"`+caseID+`"}`, "")
	for range 3 {
		nb(t, ts, "andy", "POST", path+"/cases", `{"case_id":"`+caseID+`","with_results":true}`, "")
	}
	if c, _ := s.Cases.Get(context.Background(), caseID); len(c.Entries) != 4 {
		t.Errorf("relink added entries: %d", len(c.Entries))
	}
	if code, _, _, _ := nb(t, ts, "admin", "DELETE", "/api/cases/"+caseID+"/entries/"+entry, "", ""); code != 400 {
		t.Errorf("removed the notebook entry from the case: %d", code)
	}
	if code, body, _, _ := nb(t, ts, "andy", "GET", "/api/notebooks?case="+caseID, "", ""); code != 200 || len(body["notebooks"].([]any)) != 1 || len(body["starters"].([]any)) != 0 {
		t.Errorf("by case = %v", body)
	}
	code, body, _, _ = nb(t, ts, "andy", "DELETE", path+"/cases/"+caseID, "", "")
	if code != 200 || len(notebookOf(t, body).Cases) != 0 {
		t.Errorf("unlink = %d %v", code, body)
	}
	c, _ = s.Cases.Get(context.Background(), caseID)
	if len(c.Entries) != 3 {
		t.Errorf("after unlink the case has %d entries; the copied searches stay", len(c.Entries))
	}
}

// A deleted user's notebooks lose their owner, so a new account with the
// same name does not inherit them; admins still see them.
func TestNotebookOwnerDeleted(t *testing.T) {
	ts, s := newNotebookServer(t)
	_, body, _, _ := nb(t, ts, "bea", "POST", "/api/notebooks", `{"title":"Bea's private hunt"}`, "")
	id := notebookOf(t, body).ID
	if code, _, _, _ := nb(t, ts, "admin", "DELETE", "/api/users/bea", "", ""); code != 200 {
		t.Fatalf("delete user = %d", code)
	}
	if n, _ := s.Notebooks.Get(context.Background(), id); n.Owner != "" {
		t.Errorf("owner = %q", n.Owner)
	}
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "Bea", Role: users.Analyst, Password: "role-password"}); err != nil {
		t.Fatal(err)
	}
	if code, _, _, _ := nb(t, ts, "bea", "GET", "/api/notebooks/"+id, "", ""); code != 404 {
		t.Errorf("new bea opened the old notebook: %d", code)
	}
	if code, _, _, _ := nb(t, ts, "admin", "GET", "/api/notebooks/"+id, "", ""); code != 200 {
		t.Errorf("admin = %d", code)
	}
}

// failingNotebooks fails every change while fail is set.
type failingNotebooks struct {
	notebooks.Store
	fail atomic.Bool
}

func (f *failingNotebooks) Modify(ctx context.Context, id string, fn func(*notebooks.Notebook) (bool, error)) (*notebooks.Notebook, error) {
	if f.fail.Load() {
		return nil, errors.New("opensearch is down")
	}
	return f.Store.Modify(ctx, id, fn)
}

// A release that failed when the user was deleted is done before an
// account of that name is made again, and the account waits for it.
func TestNotebookOwnerReleasedBeforeReuse(t *testing.T) {
	ts, s := newNotebookServer(t)
	_, body, _, _ := nb(t, ts, "bea", "POST", "/api/notebooks", `{"title":"Bea's private hunt"}`, "")
	id := notebookOf(t, body).ID
	flaky := &failingNotebooks{Store: s.Notebooks}
	s.Notebooks = flaky
	flaky.fail.Store(true)
	if code, _, _, _ := nb(t, ts, "admin", "DELETE", "/api/users/bea", "", ""); code != 200 {
		t.Fatalf("delete user = %d", code)
	}
	if n, _ := s.Notebooks.Get(context.Background(), id); n.Owner != "bea" {
		t.Fatalf("owner after a failed release = %q", n.Owner)
	}
	newBea := `{"username":"Bea","role":"analyst","password":"Quiet-river-stone-77","must_change_password":false}`
	if code, out, _, _ := nb(t, ts, "admin", "POST", "/api/users", newBea, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("new bea made while her old notebooks could not be released: %d %v", code, out)
	}
	flaky.fail.Store(false)
	if code, out, _, _ := nb(t, ts, "admin", "POST", "/api/users", newBea, ""); code != http.StatusCreated {
		t.Fatalf("new bea: %d %v", code, out)
	}
	if n, _ := s.Notebooks.Get(context.Background(), id); n.Owner != "" {
		t.Errorf("owner = %q", n.Owner)
	}
	// Making an account whose name is taken leaves its notebooks alone.
	_, body, _, _ = nb(t, ts, "andy", "POST", "/api/notebooks", `{"title":"Andy's hunt"}`, "")
	andys := notebookOf(t, body).ID
	if code, _, _, _ := nb(t, ts, "admin", "POST", "/api/users", `{"username":"andy","role":"analyst","password":"Quiet-river-stone-77"}`, ""); code == http.StatusCreated {
		t.Fatal("a second andy was made")
	}
	if n, _ := s.Notebooks.Get(context.Background(), andys); n.Owner != "andy" {
		t.Errorf("andy's notebook owner = %q", n.Owner)
	}
}
