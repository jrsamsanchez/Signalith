package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDraftDetectionOffline(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/detections/draft",
		`{"description":"Alert me when more than 10 failed logins come from the same source in 5 minutes"}`, true)
	if code != 200 {
		t.Fatalf("draft = %d %v", code, body)
	}
	dr := body["draft"].(map[string]any)
	d := dr["detection"].(map[string]any)
	if dr["source"] != "rules" || d["enabled"] != false || d["lookback"] != "5m" || d["severity"] != "medium" {
		t.Errorf("draft: %v", dr)
	}
	if q := d["query"].(string); !strings.Contains(q, "action=failure") || !strings.Contains(q, "by src") || !strings.Contains(q, "count>10") {
		t.Errorf("query: %q", q)
	}
	if m := d["mitre"].([]any); len(m) == 0 || m[0] != "T1110" {
		t.Errorf("mitre: %v", m)
	}
	risk := d["risk"].(map[string]any)
	if risk["score"].(float64) <= 0 {
		t.Errorf("risk: %v", risk)
	}
	if len(dr["steps"].([]any)) == 0 {
		t.Error("no steps explain the draft")
	}

	// The draft saves as it is, turned off.
	raw, _ := json.Marshal(d)
	code, saved := do(t, ts, "POST", "/api/detections", string(raw), true)
	if code != 201 || saved["enabled"] != false {
		t.Fatalf("save = %d %v", code, saved)
	}
	// A second draft of the same gets an ID of its own.
	_, body = do(t, ts, "POST", "/api/detections/draft",
		`{"description":"Alert me when more than 10 failed logins come from the same source in 5 minutes"}`, true)
	if id := body["draft"].(map[string]any)["detection"].(map[string]any)["id"]; id == d["id"] {
		t.Errorf("second draft reused id %v", id)
	}

	for _, bad := range []string{`{"description":""}`, `{"description":"` + strings.Repeat("x", 1001) + `"}`, `{"description":"x","mode":"magic"}`, `{"description":"x","mode":"ai"}`} {
		if code, out := do(t, ts, "POST", "/api/detections/draft", bad, true); code != 400 {
			t.Errorf("%.40s: %d %v", bad, code, out)
		}
	}
}

func TestBacktestDetection(t *testing.T) {
	ts, _ := newTestServer(t)
	det := `{"id":"bt-test","title":"Failures from $src$","query":"datamodel=Authentication action=failure | stats count by src | where count >= 10","schedule":"5m","lookback":"1h","severity":"low","throttle":{"fields":["src"],"window":"1h"}}`
	code, body := do(t, ts, "POST", "/api/detections/backtest", `{"detection":`+det+`,"window":"1d"}`, true)
	if code != 200 {
		t.Fatalf("backtest = %d %v", code, body)
	}
	bt := body["backtest"].(map[string]any)
	if bt["searches"].(float64) < 1 || bt["searches"].(float64) > 60 || len(bt["buckets"].([]any)) == 0 {
		t.Errorf("backtest: %v", bt)
	}
	if bt["findings"].(float64) < 1 {
		t.Errorf("no findings over a day of failures: %v", bt)
	}
	// Nothing was raised.
	_, list := do(t, ts, "GET", "/api/findings?detection=bt-test", "", true)
	if fs, _ := list["findings"].([]any); len(fs) != 0 {
		t.Errorf("a backtest raised %d findings", len(fs))
	}
	for _, bad := range []string{
		`{"detection":` + det + `,"window":"91d"}`,
		`{"detection":` + det + `,"window":"5m"}`,
		`{"detection":` + det + `,"window":"soon"}`,
		`{"detection":{"title":"x","query":"user=x earliest=-1h"}}`,
		`{"detection":{"title":"x","query":"index=.opendistro_security | stats count"}}`,
	} {
		if code, out := do(t, ts, "POST", "/api/detections/backtest", bad, true); code != 400 {
			t.Errorf("%.60s: %d %v", bad, code, out)
		}
	}
}

func TestBacktestSlots(t *testing.T) {
	var b backtestSlots
	done, _ := b.start("alice")
	if done == nil {
		t.Fatal("first backtest refused")
	}
	if again, why := b.start("alice"); again != nil || why == "" {
		t.Error("a second backtest for the same person ran")
	}
	bob, _ := b.start("bob")
	if bob == nil {
		t.Fatal("another person's backtest refused")
	}
	if c, _ := b.start("carol"); c != nil {
		t.Errorf("more than %d backtests ran at once", maxBacktests)
	}
	done()
	if c, _ := b.start("carol"); c == nil {
		t.Error("a freed slot was not reused")
	}
	bob()
}
