// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"testing"
)

// TestFindingsQueuePagesGroupsAndCounts: the queue pages in urgency
// order with a cursor, filters unowned findings and one entity, counts
// each urgency without the urgency filter, and groups by detection or
// entity.
func TestFindingsQueuePagesGroupsAndCounts(t *testing.T) {
	ts, _ := newTestServer(t)
	sev := []string{"low", "critical", "high", "medium", "critical"}
	for i, s := range sev {
		body := fmt.Sprintf(`{"title":"F%d","severity":%q,"query":"* | head 1","result":{"user":"u%d","host":"web-1"}}`, i, s, i%2)
		if code, out := do(t, ts, "POST", "/api/findings", body, true); code != http.StatusCreated {
			t.Fatalf("create: %d %v", code, out)
		}
	}
	var seen []string
	after := ""
	for range sev {
		code, out := do(t, ts, "GET", "/api/findings?sort=urgency&limit=2&counts=urgency&urgency=critical,high,medium,low"+after, "", true)
		if code != http.StatusOK {
			t.Fatalf("page: %d %v", code, out)
		}
		for _, f := range out["findings"].([]any) {
			seen = append(seen, f.(map[string]any)["severity"].(string))
		}
		if c := out["by_urgency"].(map[string]any); c["critical"] != float64(2) || c["low"] != float64(1) {
			t.Errorf("counts %v", c)
		}
		next, _ := out["next"].(string)
		if next == "" {
			break
		}
		after = "&after=" + next
	}
	if fmt.Sprint(seen) != "[critical critical high medium low]" {
		t.Errorf("by urgency: %v", seen)
	}
	if code, out := do(t, ts, "GET", "/api/findings?due=overdue", "", true); code != http.StatusOK || out["total"] != float64(0) || len(out["due"].(map[string]any)) != 0 {
		t.Errorf("overdue: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/findings?due=15m", "", true); code != http.StatusOK || out["total"] != float64(2) || len(out["due"].(map[string]any)) != 2 {
		t.Errorf("due within 15m: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/findings?due=soon", "", true); code != http.StatusBadRequest {
		t.Errorf("due=soon: %d", code)
	}
	if code, out := do(t, ts, "GET", "/api/findings?entity=u1&unowned=true", "", true); code != http.StatusOK || out["total"] != float64(2) {
		t.Errorf("entity u1: %d %v", code, out)
	}
	code, out := do(t, ts, "GET", "/api/findings?group=entity", "", true)
	if code != http.StatusOK {
		t.Fatalf("group: %d %v", code, out)
	}
	top := out["groups"].([]any)[0].(map[string]any)
	if top["key"] != "web-1" || top["count"] != float64(5) || top["urgency"] != "critical" {
		t.Errorf("groups %v", out["groups"])
	}
	if code, out := do(t, ts, "GET", "/api/findings?group=detection", "", true); code != http.StatusOK || len(out["groups"].([]any)) != 1 {
		t.Errorf("by detection: %d %v", code, out)
	}
}

// TestFindingViews: each user keeps their own saved views; bad ones are
// refused whole.
func TestFindingViews(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/me/finding-views", "", true); code != http.StatusOK || len(out["views"].([]any)) != 0 {
		t.Fatalf("empty: %d %v", code, out)
	}
	code, out := do(t, ts, "PUT", "/api/me/finding-views", `{"views":[{"id":"crit","name":"Unowned critical","query":"urgency=critical&owner=__none"}]}`, true)
	if code != http.StatusOK || out["views"].([]any)[0].(map[string]any)["query"] != "owner=__none&urgency=critical" {
		t.Fatalf("put: %d %v", code, out)
	}
	if code, out := do(t, ts, "PUT", "/api/me/finding-views", `{"views":[{"id":"x","name":"x","query":"token=1"}]}`, true); code != http.StatusBadRequest {
		t.Errorf("bad view: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/me/finding-views", "", true); code != http.StatusOK || len(out["views"].([]any)) != 1 {
		t.Errorf("after a refused put: %d %v", code, out)
	}
}
