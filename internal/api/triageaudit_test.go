// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
)

// wantAudit checks that the log has an audit line with msg, by admin,
// holding each of want.
func wantAudit(t *testing.T, logs *logBuffer, msg string, want ...string) {
	t.Helper()
	line := auditLine(t, logs.String(), `msg="`+msg)
	for _, w := range append([]string{"audit=true", "by=admin"}, want...) {
		if !strings.Contains(line, w) {
			t.Errorf("audit line %q lacks %s: %s", msg, w, line)
		}
	}
}

// Triage, exceptions and case changes are audit records, with what they
// changed from and to.
func TestTriageAndCaseChangesAreAudited(t *testing.T) {
	var logs logBuffer
	var store findings.Store
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
		store = s.Findings
	})
	now := time.Now().Add(-time.Hour)
	for _, id := range []string{"f-1", "f-2", "f-3"} {
		f := &findings.Finding{ID: id, DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium",
			Status: findings.StatusNew, Result: map[string]any{"dest": "web1"}, Created: now, Updated: now}
		if err := store.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}

	if code, out := do(t, ts, "POST", "/api/findings", `{"title":"Odd logon","severity":"low","query":"user=bob"}`, true); code != 201 {
		t.Fatalf("manual finding = %d %v", code, out)
	}
	wantAudit(t, &logs, "finding.create:", `title="Odd logon"`, "severity=low", `query="user=bob"`)

	if code, out := do(t, ts, "PATCH", "/api/findings/f-1", `{"status":"closed","disposition":"false_positive","comment":"lab"}`, true); code != 200 {
		t.Fatalf("patch = %d %v", code, out)
	}
	wantAudit(t, &logs, "finding.update:", "target=f-1", "status: new -> closed", "disposition: (none) -> false_positive", "commented=true")

	if code, out := do(t, ts, "POST", "/api/findings/bulk", `{"ids":["f-2","f-3","nope"],"update":{"owner":"bob"}}`, true); code != 200 {
		t.Fatalf("bulk = %d %v", code, out)
	}
	wantAudit(t, &logs, "finding.bulk_update:", `update="owner=bob"`, "updated=2", "failed=1", "findings=f-2,f-3")

	code, out := do(t, ts, "POST", "/api/detections/auth-brute-force/exceptions", `{"match":{"src":"203.0.113.*"},"for":"7d","comment":"our scanner"}`, true)
	if code != 200 {
		t.Fatalf("exception = %d %v", code, out)
	}
	exID := out["exception"].(map[string]any)["id"].(string)
	wantAudit(t, &logs, "detection.exception_add:", "target=auth-brute-force", "exception="+exID, "203.0.113.*", `comment="our scanner"`, "until=")
	if code, _ := do(t, ts, "DELETE", "/api/detections/auth-brute-force/exceptions/"+exID, "", true); code != 200 {
		t.Fatalf("remove exception = %d", code)
	}
	wantAudit(t, &logs, "detection.exception_remove:", "exception="+exID, "203.0.113.*", "added_by=admin")

	if code, out := do(t, ts, "POST", "/api/findings/f-2/suppress", `{"fields":["dest"],"update":{"status":"closed"}}`, true); code != 200 {
		t.Fatalf("suppress = %d %v", code, out)
	}
	wantAudit(t, &logs, "finding.suppress:", "finding=f-2", "dest=web1")
	if !strings.Contains(auditLine(t, logs.String(), "target=f-2 "), "status: new -> closed") {
		t.Errorf("the suppressed finding's change is not audited:\n%s", logs.String())
	}

	code, out = do(t, ts, "POST", "/api/cases", `{"title":"Brute force","findings":["f-1"]}`, true)
	if code != 201 {
		t.Fatalf("case = %d %v", code, out)
	}
	caseID := out["case"].(map[string]any)["id"].(string)
	wantAudit(t, &logs, "case.create:", "target="+caseID, "findings=f-1")
	if code, out := do(t, ts, "PATCH", "/api/cases/"+caseID, `{"status":"in_progress","owner":"carol"}`, true); code != 200 {
		t.Fatalf("case patch = %d %v", code, out)
	}
	wantAudit(t, &logs, "case.update:", "target="+caseID, "owner: (none) -> carol")
	code, out = do(t, ts, "POST", "/api/cases/"+caseID+"/entries", `{"kind":"note","text":"Blocked 10.0.0.9"}`, true)
	if code != 201 {
		t.Fatalf("note = %d %v", code, out)
	}
	entry := out["entry"].(map[string]any)["id"].(string)
	wantAudit(t, &logs, "case.entry_add:", "entry="+entry, "kind=note")
	if code, out := do(t, ts, "DELETE", "/api/cases/"+caseID+"/entries/"+entry, "", true); code != 200 {
		t.Fatalf("remove entry = %d %v", code, out)
	}
	wantAudit(t, &logs, "case.entry_remove:", "entry="+entry, "kind=note", "added_by=admin", `text="Blocked 10.0.0.9"`)
	if code, out := do(t, ts, "DELETE", "/api/cases/"+caseID+"/findings/f-1", "", true); code != 200 {
		t.Fatalf("remove finding = %d %v", code, out)
	}
	wantAudit(t, &logs, "case.finding_remove:", "finding=f-1")
}

// Threat intel changes are audit records; a feed's address is logged
// without the key it holds.
func TestIntelChangesAreAudited(t *testing.T) {
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# list\n203.0.113.9\n"))
	}))
	defer feedSrv.Close()
	var logs logBuffer
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
		s.Intel = store
		s.Engine.Intel = store
		s.Feeds = &intel.Feeds{Store: store, Log: s.Log, AllowLoopback: true, File: filepath.Join(dir, "intel_feeds.yaml")}
	})

	code, out := do(t, ts, "POST", "/api/intel/indicators", `{"value":"evil[.]example","weight":"2","expires":"30d","tags":["phish"]}`, true)
	if code != 200 {
		t.Fatalf("add = %d %v", code, out)
	}
	wantAudit(t, &logs, "intel.indicator_add:", "target=evil.example", "type=domain", "source=manual", "weight=2", "expires=20", "tags=phish")
	if code, out := do(t, ts, "POST", "/api/intel/indicators", `{"value":"0.0.0.0/0"}`, true); code != 400 || !strings.Contains(out["error"].(string), "too broad") {
		t.Errorf("a catch-all network = %d %v", code, out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/intel/indicators/"+out["id"].(string), "", true); code != 200 {
		t.Fatalf("delete = %d", code)
	}
	wantAudit(t, &logs, "intel.indicator_delete:", "target=evil.example")
	if code, body := post(t, ts.URL+"/api/intel/upload", "text/plain", "192.0.2.1\n192.0.2.2\nbad.example\n"); code != 200 {
		t.Fatalf("upload = %d %s", code, body)
	}
	wantAudit(t, &logs, "intel.indicator_upload:", "indicators=3", `types="domain=1,ip=2"`, "192.0.2.1")

	keyed := feedSrv.URL + "/list.txt?api_key=K3Y-SECRET"
	if code, out := do(t, ts, "POST", "/api/intel/feeds", `{"name":"keyed","url":"`+keyed+`","interval":"1h","weight":3}`, true); code != 200 {
		t.Fatalf("feed add = %d %v", code, out)
	}
	wantAudit(t, &logs, "intel.feed_add:", "feed=keyed", "url=", "interval=1h0m0s", "weight=3", "enabled=true")
	if code, out := do(t, ts, "PUT", "/api/intel/feeds/keyed", `{"enabled":false,"weight":5}`, true); code != 200 {
		t.Fatalf("feed change = %d %v", code, out)
	}
	wantAudit(t, &logs, "intel.feed_change:", "feed=keyed", "weight: 3 -> 5", "enabled: true -> false")
	if code, out := do(t, ts, "POST", "/api/intel/feeds/test", `{"url":"`+keyed+`"}`, true); code != 200 {
		t.Fatalf("feed test = %d %v", code, out)
	}
	wantAudit(t, &logs, "intel.feed_test:", "ok=true")
	if code, out := do(t, ts, "DELETE", "/api/intel/feeds/keyed", "", true); code != 200 {
		t.Fatalf("feed delete = %d %v", code, out)
	}
	wantAudit(t, &logs, "intel.feed_delete:", "feed=keyed", "indicators_removed=")
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "audit=true") && strings.Contains(l, "K3Y-SECRET") {
			t.Errorf("an audit line holds the feed's key: %s", l)
		}
	}
}
