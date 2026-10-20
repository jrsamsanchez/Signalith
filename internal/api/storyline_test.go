// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/url"
	"strings"
	"testing"
)

func TestStoryline(t *testing.T) {
	ts, _ := newTestServer(t)
	code, f := do(t, ts, "POST", "/api/findings", `{"title":"Encoded PowerShell","severity":"high","result":{"dest":"ws-fin-07","user":"alice"}}`, true)
	if code != 201 {
		t.Fatalf("finding = %d %v", code, f)
	}
	id := f["id"].(string)
	do(t, ts, "POST", "/api/findings", `{"title":"Elsewhere","severity":"low","result":{"dest":"web-01"}}`, true)

	check := func(path string) map[string]any {
		t.Helper()
		code, out := do(t, ts, "GET", path, "", true)
		if code != 200 {
			t.Fatalf("%s = %d %v", path, code, out)
		}
		st := out["storyline"].(map[string]any)
		items := st["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["title"] != "Encoded PowerShell" {
			t.Fatalf("%s items = %v", path, items)
		}
		if q, _ := st["searches"].(map[string]any)["risk"].(string); !strings.Contains(q, "datamodel=Risk") {
			t.Errorf("%s risk search = %v", path, st["searches"])
		}
		return out
	}
	out := check("/api/storyline?type=system&object=ws-fin-07&since=30d")
	if a := out["anchor"].(map[string]any); a["kind"] != "entity" || a["value"] != "ws-fin-07" {
		t.Errorf("anchor = %v", a)
	}
	out = check("/api/storyline?finding=" + url.QueryEscape(id))
	if a := out["anchor"].(map[string]any); a["kind"] != "finding" || a["title"] != "Encoded PowerShell" {
		t.Errorf("anchor = %v", a)
	}
	seeds := out["storyline"].(map[string]any)["seeds"].([]any)
	if len(seeds) != 2 {
		t.Errorf("seeds = %v", seeds)
	}

	code, c := do(t, ts, "POST", "/api/cases", `{"findings":["`+id+`"]}`, true)
	if code != 201 {
		t.Fatalf("case = %d %v", code, c)
	}
	caseID := c["case"].(map[string]any)["id"].(string)
	out = check("/api/storyline?case=" + url.QueryEscape(caseID))
	if a := out["anchor"].(map[string]any); a["kind"] != "case" {
		t.Errorf("anchor = %v", a)
	}

	for path, want := range map[string]int{
		"/api/storyline": 400,
		"/api/storyline?type=process&object=cmd.exe":      400,
		"/api/storyline?type=user&object=*":               400,
		"/api/storyline?type=user&object=bob&since=90d":   400,
		"/api/storyline?type=user&object=bob&since=never": 400,
		"/api/storyline?finding=nope":                     404,
		"/api/storyline?case=nope":                        404,
	} {
		if code, out := do(t, ts, "GET", path, "", true); code != want {
			t.Errorf("%s = %d %v, want %d", path, code, out, want)
		}
	}
	// A finding with no user, system or address has no story to tell.
	_, f = do(t, ts, "POST", "/api/findings", `{"title":"No entities","severity":"low","result":{"count":3}}`, true)
	if code, _ := do(t, ts, "GET", "/api/storyline?finding="+url.QueryEscape(f["id"].(string)), "", true); code != 422 {
		t.Errorf("no seeds = %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/storyline?type=user&object=bob", "", false); code != 401 {
		t.Errorf("signed out = %d", code)
	}
}
