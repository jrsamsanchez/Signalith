// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// doIf is do with an If-Match header.
func doIf(t *testing.T, ts *httptest.Server, method, path, body, etag string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret-pass")
	if etag != "" {
		req.Header.Set("If-Match", `"`+etag+`"`)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func TestDetectionChangesHonourIfMatch(t *testing.T) {
	ts, _ := newTestServer(t)
	rule := `{"id":"etag-rule","title":"One","query":"event.action=failure","schedule":"5m","lookback":"5m","severity":"low","enabled":true}`
	code, out := do(t, ts, "POST", "/api/detections", rule, true)
	if code != 201 || out["etag"] == "" {
		t.Fatalf("create = %d %v", code, out)
	}
	first := out["etag"].(string)
	_, got := do(t, ts, "GET", "/api/detections/etag-rule", "", true)
	if got["etag"] != first {
		t.Fatalf("get etag %v, created %v", got["etag"], first)
	}
	code, out = doIf(t, ts, "PUT", "/api/detections/etag-rule", strings.Replace(rule, "One", "Two", 1), first)
	if code != 200 || out["etag"] == first {
		t.Fatalf("put with the current version = %d %v", code, out)
	}
	// A page that read the first version is told it changed.
	code, out = doIf(t, ts, "PUT", "/api/detections/etag-rule", strings.Replace(rule, "One", "Three", 1), first)
	if code != 412 || out["code"] != "stale" {
		t.Fatalf("put over a changed version = %d %v", code, out)
	}
	if code, _ := doIf(t, ts, "DELETE", "/api/detections/etag-rule", "", first); code != 412 {
		t.Fatalf("delete over a changed version = %d", code)
	}
	// Without If-Match (a script), changes apply as before.
	if code, _ := do(t, ts, "PUT", "/api/detections/etag-rule", strings.Replace(rule, "One", "Four", 1), true); code != 200 {
		t.Fatalf("put without If-Match = %d", code)
	}
	code, out = do(t, ts, "GET", "/api/detections", "", true)
	found := false
	for _, d := range out["detections"].([]any) {
		m := d.(map[string]any)
		if m["id"] == "etag-rule" {
			found = m["etag"] != "" && m["etag"] != first
		}
	}
	if code != 200 || !found {
		t.Fatal("the list does not give the rule's version")
	}
}

func TestDashboardChangesHonourIfMatch(t *testing.T) {
	ts, _ := newTestServer(t)
	board := `{"id":"etag-board","title":"One","panels":[{"title":"Events","query":"* | stats count"}]}`
	code, out := do(t, ts, "POST", "/api/dashboards", board, true)
	if code != 201 || out["etag"] == "" {
		t.Fatalf("create = %d %v", code, out)
	}
	first := out["etag"].(string)
	if code, out := doIf(t, ts, "PUT", "/api/dashboards/etag-board", strings.Replace(board, "One", "Two", 1), first); code != 200 {
		t.Fatalf("put = %d %v", code, out)
	}
	code, out = doIf(t, ts, "PUT", "/api/dashboards/etag-board", strings.Replace(board, "One", "Three", 1), first)
	if code != 412 || out["code"] != "stale" {
		t.Fatalf("put over a changed version = %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/dashboards/etag-board", "", true)
	if code, _ := doIf(t, ts, "DELETE", "/api/dashboards/etag-board", "", out["etag"].(string)); code != 204 {
		t.Fatalf("delete with the current version = %d", code)
	}
}

// fakeLists is a shared copy of the lists for the API tests: one version
// per list, a change over an older one refused.
type fakeLists struct{ etags map[string]string }

func (f *fakeLists) ETag(kind string) string { return f.etags[kind] }

func (f *fakeLists) Put(_ context.Context, by, kind string, _ []byte, etag string) error {
	if etag != "" && etag != f.etags[kind] {
		return &shared.StaleError{By: "alice", Node: "siem-a", At: "2026-10-14T10:00:00Z"}
	}
	f.etags[kind] += "x"
	return nil
}

func TestLookupUploadsHonourIfMatch(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Assets.UseBackend(&fakeLists{etags: map[string]string{"assets": "v1"}}) })
	_, got := do(t, ts, "GET", "/api/lookups/assets", "", true)
	if got["shared"] != true || got["etag"] != "v1" {
		t.Fatalf("get = %v", got)
	}
	code, out := doIf(t, ts, "PUT", "/api/lookups/assets", "host\nweb1\n", "v1")
	if code != 200 || out["etag"] != "v1x" {
		t.Fatalf("upload over the version shown = %d %v", code, out)
	}
	code, out = doIf(t, ts, "PUT", "/api/lookups/assets", "host\nweb2\n", "v1")
	if code != 412 || out["changed_by"] != "alice" || out["changed_on"] != "siem-a" {
		t.Fatalf("upload over a changed version = %d %v", code, out)
	}
	if _, got := do(t, ts, "GET", "/api/lookups/assets", "", true); got["count"] != float64(1) {
		t.Fatalf("the refused list is in use: %v", got)
	}
	// Without If-Match (a script), the upload applies to the latest.
	if code, _ := doIf(t, ts, "PUT", "/api/lookups/assets", "host\nweb3\n", ""); code != 200 {
		t.Fatalf("upload without If-Match = %d", code)
	}
}
