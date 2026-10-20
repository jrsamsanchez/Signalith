// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestCasesAPI(t *testing.T) {
	var fs *findings.Memory
	ts, _ := newTestServerWith(t, func(s *Server) { fs = s.Findings.(*findings.Memory) })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, f := range []*findings.Finding{
		{ID: "f1", Title: "Brute force from 10.0.0.9", Severity: "high", Status: findings.StatusNew, Entities: map[string]any{"src": "10.0.0.9"}, Created: now, Updated: now},
		{ID: "f2", Title: "New admin account", Severity: "medium", Status: findings.StatusNew, Entities: map[string]any{"user": "eve"}, Created: now, Updated: now},
	} {
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	code, out := do(t, ts, "POST", "/api/cases", `{"findings":["f1","nope"]}`, true)
	if code != 201 {
		t.Fatalf("create = %d %v", code, out)
	}
	c := out["case"].(map[string]any)
	id := c["id"].(string)
	if c["title"] != "Brute force from 10.0.0.9" || c["severity"] != "high" || len(out["failed"].(map[string]any)) != 1 {
		t.Errorf("case = %v failed = %v", c, out["failed"])
	}
	if f, _ := fs.Get(ctx, "f1"); f.CaseID != id || f.Status != findings.StatusInProgress {
		t.Errorf("finding after link = %s %s", f.CaseID, f.Status)
	}

	if code, out := do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"note","text":"Blocked 10.0.0.9 at the firewall"}`, true); code != 201 {
		t.Fatalf("note = %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"search","query":"datamodel=Authentication | stats count by src","earliest":"-24h"}`, true)
	if code != 201 {
		t.Fatalf("search entry = %d %v", code, out)
	}
	e := out["entry"].(map[string]any)
	if e["result_kind"] != "table" || len(e["rows"].([]any)) != 2 || e["author"] != "admin" {
		t.Errorf("search entry = %v", e)
	}
	if code, _ := do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"search","query":"a=1 | stats avg"}`, true); code != 400 {
		t.Errorf("bad query = %d", code)
	}
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"event","event":{"_time":"2026-10-12T09:00:00Z","user":"eve","dest":"dc01"}}`, true)
	if code != 201 {
		t.Fatalf("event = %d %v", code, out)
	}
	if ents := out["case"].(map[string]any)["entities"].([]any); len(ents) != 3 {
		t.Errorf("entities = %v", ents)
	}

	// Adding a finding that belongs to another case moves it.
	_, out = do(t, ts, "POST", "/api/cases", `{"title":"Account abuse","findings":["f2"]}`, true)
	other := out["case"].(map[string]any)["id"].(string)
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/findings", `{"ids":["f2"]}`, true)
	if code != 200 || len(out["case"].(map[string]any)["findings"].([]any)) != 2 {
		t.Fatalf("add finding = %d %v", code, out)
	}
	if _, out := do(t, ts, "GET", "/api/cases/"+other, "", true); out["case"].(map[string]any)["findings"] != nil {
		t.Errorf("old case still lists f2: %v", out["case"])
	}

	code, out = do(t, ts, "GET", "/api/cases?q=dc01", "", true)
	if code != 200 || out["total"] != float64(1) {
		t.Errorf("search by entity = %d %v", code, out)
	}
	if code, _ := put(t, ts.URL+"/api/lookups/identities", "identity,name,priority\neve,Eve,high\n"); code != 200 {
		t.Fatalf("identities = %d", code)
	}
	code, out = do(t, ts, "GET", "/api/cases/"+id, "", true)
	if code != 200 || len(out["findings"].([]any)) != 2 || len(out["case"].(map[string]any)["entries"].([]any)) != 5 {
		t.Errorf("get = %d %v", code, out)
	}
	// Entity context lines up with the entities; unlisted values are null.
	ents, ectx := out["case"].(map[string]any)["entities"].([]any), out["entity_context"].([]any)
	if len(ectx) != len(ents) {
		t.Fatalf("entity_context = %v for %v", ectx, ents)
	}
	for i, e := range ents {
		e := e.(map[string]any)
		c, _ := ectx[i].(map[string]any)
		if listed := e["field"] == "user" && e["value"] == "eve"; listed != (c != nil) || (listed && c["name"] != "Eve") {
			t.Errorf("context for %v = %v", e, ectx[i])
		}
	}
	if code, out := do(t, ts, "GET", "/api/cases/summary", "", true); code != 200 || out["open"] != float64(2) {
		t.Errorf("summary = %d %v", code, out)
	}

	if code, _ := do(t, ts, "PATCH", "/api/cases/"+id, `{"close_findings":true}`, true); code != 400 {
		t.Errorf("closing findings of an open case = %d", code)
	}
	code, out = do(t, ts, "PATCH", "/api/cases/"+id, `{"status":"resolved","resolution":"Password spray; source blocked","close_findings":true,"disposition":"true_positive"}`, true)
	if code != 200 || out["findings_closed"] != float64(2) {
		t.Fatalf("close = %d %v", code, out)
	}
	for _, fid := range []string{"f1", "f2"} {
		if f, _ := fs.Get(ctx, fid); f.Status != findings.StatusResolved || f.Disposition != "true_positive" {
			t.Errorf("%s = %s %s", fid, f.Status, f.Disposition)
		}
	}

	if code, _ := do(t, ts, "DELETE", "/api/cases/"+id+"/findings/f1", "", true); code != 200 {
		t.Errorf("remove finding = %d", code)
	}
	if f, _ := fs.Get(ctx, "f1"); f.CaseID != "" {
		t.Errorf("f1 still linked to %s", f.CaseID)
	}
	if code, _ := do(t, ts, "GET", "/api/cases/CASE-nope", "", true); code != 404 {
		t.Errorf("unknown case = %d", code)
	}
}

// takenOnce answers the first create as if its ID were taken.
type takenOnce struct {
	*cases.Memory
	tried []string
}

func (s *takenOnce) Create(ctx context.Context, c *cases.Case) error {
	s.tried = append(s.tried, c.ID)
	if len(s.tried) == 1 {
		return cases.ErrExists
	}
	return s.Memory.Create(ctx, c)
}

func TestCaseIDCollisionGetsANewID(t *testing.T) {
	st := &takenOnce{Memory: cases.NewMemory()}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Cases = st })
	code, out := do(t, ts, "POST", "/api/cases", `{"title":"Phishing wave"}`, true)
	if code != 201 || len(st.tried) != 2 || st.tried[0] == st.tried[1] || out["case"].(map[string]any)["id"] != st.tried[1] {
		t.Fatalf("create = %d %v, tried %v", code, out, st.tried)
	}
}

// TestCaseFromFindingShowsHiddenCharacters: a new case is named after its
// first finding; a finding stored before titles were made safe may still
// hold U+202E, which must not reach the case title (xss-bidi-spoof).
func TestCaseFromFindingShowsHiddenCharacters(t *testing.T) {
	var fs *findings.Memory
	ts, _ := newTestServerWith(t, func(s *Server) { fs = s.Findings.(*findings.Memory) })
	now := time.Now().UTC()
	rlo := string(rune(0x202e))
	f := &findings.Finding{ID: "f1", Title: "Failed logons for bob" + rlo + "gnp.exe", Severity: "high", Status: findings.StatusNew, Created: now, Updated: now}
	if err := fs.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	code, out := do(t, ts, "POST", "/api/cases", `{"findings":["f1"]}`, true)
	c, _ := out["case"].(map[string]any)
	if code != 201 || c["title"] != "Failed logons for bob⟨U+202E⟩gnp.exe" {
		t.Errorf("%d %v", code, out)
	}
}
