// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

func post(t *testing.T, url, contentType, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestIntelAPI(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# test feed\n203.0.113.9\n198.51.100.0/24\n"))
	}))
	defer feed.Close()
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Engine.Intel = store
		s.Feeds = &intel.Feeds{Store: store, Log: s.Log, AllowLoopback: true, List: []intel.Feed{
			{Name: "test-feed", URL: feed.URL, Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 2, Enabled: true,
				Headers: map[string]string{"Authorization": "secret"}},
		}}
	})

	code, out := do(t, ts, "GET", "/api/intel", "", true)
	feeds := out["feeds"].([]any)
	if code != 200 || len(feeds) != 1 || out["summary"].(map[string]any)["total"] != float64(0) {
		t.Fatalf("overview = %d %v", code, out)
	}
	f0 := feeds[0].(map[string]any)
	hdrs, _ := f0["headers"].([]any)
	if f0["interval"] != "1h" || f0["has_headers"] != true || f0["source"] != "config" || len(hdrs) != 1 ||
		hdrs[0].(map[string]any)["name"] != "Authorization" || hdrs[0].(map[string]any)["set"] != true {
		t.Errorf("feed view = %v", f0)
	}
	if raw := getRaw(t, ts, "/api/intel"); strings.Contains(raw, "secret") {
		t.Errorf("a header value was shown: %s", raw)
	}

	code, out = do(t, ts, "POST", "/api/intel/feeds/test-feed/refresh", "", true)
	if code != 200 || out["status"].(map[string]any)["count"] != float64(2) {
		t.Fatalf("refresh = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/intel/feeds/nope/refresh", "", true); code != 404 {
		t.Errorf("unknown feed = %d", code)
	}

	// Manual add, with validation.
	code, out = do(t, ts, "POST", "/api/intel/indicators", `{"value":"evil[.]example","description":"Phishing","weight":"1.5","tags":["phish"]}`, true)
	if code != 200 || out["type"] != "domain" || out["value"] != "evil.example" || out["source"] != "manual" || out["weight"] != 1.5 {
		t.Fatalf("add = %d %v", code, out)
	}
	manualID := out["id"].(string)
	code, out = do(t, ts, "POST", "/api/intel/indicators", `{"value":"nope nope","weight":"99"}`, true)
	if code != 400 || !strings.Contains(out["error"].(string), "weight") {
		t.Errorf("bad add = %d %v", code, out)
	}

	// Upload reports every bad line and saves nothing.
	code, body := post(t, ts.URL+"/api/intel/upload", "text/csv", "value,type,weight\n192.0.2.1,,\nbad value,,\n192.0.2.2,domain,\n")
	if code != 400 || !strings.Contains(body, `"line":3`) || !strings.Contains(body, `"line":4`) || !strings.Contains(body, "nothing was saved") {
		t.Fatalf("bad upload = %d %s", code, body)
	}
	code, body = post(t, ts.URL+"/api/intel/upload", "text/csv", "value,description,expires\n192.0.2.1,Scanner,30d\n"+strings.Repeat("e", 64)+",Dropper,\n")
	if code != 200 || !strings.Contains(body, `"count":2`) {
		t.Fatalf("upload = %d %s", code, body)
	}
	// A file over the upload limit is refused, not cut short.
	code, body = post(t, ts.URL+"/api/intel/upload", "text/csv", strings.Repeat(" ", maxUploadBytes+1))
	if code != 413 || !strings.Contains(body, "larger than 16 MB") {
		t.Fatalf("oversized upload = %d %s", code, body)
	}

	code, out = do(t, ts, "GET", "/api/intel/indicators?source=manual", "", true)
	if code != 200 || out["total"] != float64(3) {
		t.Errorf("list manual = %d %v", code, out)
	}
	code, out = do(t, ts, "GET", "/api/intel/indicators?q=198.51&type=ip", "", true)
	if code != 200 || out["total"] != float64(1) {
		t.Errorf("list network = %d %v", code, out)
	}
	code, out = do(t, ts, "GET", "/api/intel/lookup?value=198.51.100.200", "", true)
	if m := out["matches"].([]any); code != 200 || len(m) != 1 || m[0].(map[string]any)["source"] != "test-feed" {
		t.Errorf("lookup = %d %v", code, out)
	}

	// Feed indicators cannot be deleted one by one; manual ones can.
	feedInd, _ := store.List(intel.Filter{Source: "test-feed", Limit: 1})
	if code, out := do(t, ts, "DELETE", "/api/intel/indicators/"+feedInd[0].ID, "", true); code != 409 || !strings.Contains(out["error"].(string), "disable the feed") {
		t.Errorf("delete feed indicator = %d %v", code, out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/intel/indicators/"+manualID, "", true); code != 200 {
		t.Errorf("delete manual = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/intel/indicators/"+manualID, "", true); code != 404 {
		t.Errorf("delete again = %d", code)
	}

	// The search commands use the same indicators, and explain describes them.
	code, out = do(t, ts, "POST", "/api/explain", `{"query":"* | threatmatch src | intel dest"}`, true)
	steps, _ := out["steps"].([]any)
	if code != 200 || len(steps) != 3 || !strings.Contains(steps[1].(string), "threat intel indicator") || !strings.Contains(steps[2].(string), "dest_intel_source") {
		t.Errorf("explain = %d %v", code, out)
	}
}

func TestIntelOff(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/intel", "", true); code != 503 {
		t.Errorf("intel off = %d", code)
	}
}
