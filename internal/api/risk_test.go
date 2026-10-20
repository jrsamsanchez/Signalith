// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

func put(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("PUT", url, strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Content-Type", "text/csv")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLookupLists(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := put(t, ts.URL+"/api/lookups/assets", "host,owner,priority\nDC01,it-ops,critical\nweb1,web,urgent\n")
	if code != 400 || !strings.Contains(body, `"line":3`) || !strings.Contains(body, "nothing was saved") {
		t.Fatalf("bad csv = %d %s", code, body)
	}
	code, body = put(t, ts.URL+"/api/lookups/assets", "host,owner,priority\nDC01,it-ops,critical\n")
	if code != 200 || !strings.Contains(body, `"count":1`) {
		t.Fatalf("put = %d %s", code, body)
	}
	if code, _ := put(t, ts.URL+"/api/lookups/identities", "identity,name,priority\nbob,Bob,high\n"); code != 200 {
		t.Fatalf("identities = %d", code)
	}
	if code, body := put(t, ts.URL+"/api/lookups/assets", "host\n"+strings.Repeat("web1\n", maxUploadBytes/5)); code != 413 || !strings.Contains(body, "larger than 16 MB") {
		t.Fatalf("oversized list = %d %s", code, body)
	}
	if code, _ := put(t, ts.URL+"/api/lookups/printers", "x\n"); code != 404 {
		t.Errorf("unknown list = %d", code)
	}
	code, out := do(t, ts, "GET", "/api/lookups/assets", "", true)
	if code != 200 || out["count"] != float64(1) {
		t.Errorf("get = %d %v", code, out)
	}
	code, out = do(t, ts, "GET", "/api/lookups/context?field=dest&value=dc01.corp.local", "", true)
	if code != 200 || out["owner"] != "it-ops" || out["kind"] != "asset" {
		t.Errorf("context = %d %v", code, out)
	}
	code, out = do(t, ts, "GET", "/api/lookups/context?field=user&value=CORP%5Cbob", "", true)
	if code != 200 || out["name"] != "Bob" {
		t.Errorf("user context = %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/lookups/identities.csv", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "identity,name") || !strings.Contains(string(b), "bob,Bob") {
		t.Errorf("csv = %s", b)
	}

	// Manual findings pick up context and urgency.
	code, out = do(t, ts, "POST", "/api/findings", `{"title":"x","severity":"medium","result":{"dest":"DC01"}}`, true)
	if code != 201 || out["urgency"] != "high" || out["context"] == nil {
		t.Errorf("manual finding = %d %v", code, out)
	}
	code, out = do(t, ts, "GET", "/api/findings?urgency=high", "", true)
	if code != 200 || len(out["findings"].([]any)) != 1 {
		t.Errorf("urgency filter = %d %v", code, out)
	}
}

func TestRiskEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := do(t, ts, "GET", "/api/risk?since=7d", "", true)
	if code != 200 || out["objects"] == nil || !strings.Contains(out["query"].(string), "datamodel=Risk") {
		t.Errorf("risk = %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/risk?since=forever", "", true); code != 400 {
		t.Errorf("bad since = %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/risk/object?object=bob", "", true); code != 400 {
		t.Errorf("missing type = %d", code)
	}
	code, out = do(t, ts, "GET", "/api/risk/object?object=bob&type=user", "", true)
	if code != 200 || !strings.Contains(out["query"].(string), "risk_object=bob") {
		t.Errorf("object = %d %v", code, out)
	}
}

// max(_time) is epoch seconds; the Risk page needs a date it can read.
func TestRiskLastSeenIsADate(t *testing.T) {
	seen := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	rows := []search.Row{{"last_seen": float64(seen.UnixMilli()) / 1000}, {"last_seen": seen.Unix()}, {"risk_object": "bob"}}
	lastSeenAsTime(rows)
	for i, r := range rows[:2] {
		got, err := time.Parse(time.RFC3339Nano, r["last_seen"].(string))
		if err != nil || time.Since(got) > 24*time.Hour || time.Since(got) < time.Hour-time.Second {
			t.Errorf("row %d: last_seen = %v", i, r["last_seen"])
		}
	}
	if _, ok := rows[2]["last_seen"]; ok {
		t.Errorf("row without last_seen = %v", rows[2])
	}
}
