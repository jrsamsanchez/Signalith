// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestSearchesAreAudited: every search someone runs leaves an audit line
// with who ran it, how they signed in, from where, the query, its time
// range and indices, and how it ended, refused ones too.
func TestSearchesAreAudited(t *testing.T) {
	var logs logBuffer
	ts, _ := newTestServerWith(t, func(s *Server) { s.Log = slog.New(slog.NewTextHandler(&logs, nil)) })

	if code, body := do(t, ts, "POST", "/api/search", `{"query":"| makeresults count=2","earliest":"-24h"}`, true); code != http.StatusOK {
		t.Fatalf("search = %d %v", code, body)
	}
	line := auditLine(t, logs.String(), `msg="search.run: ran a search"`)
	for _, want := range []string{"audit=true", "by=admin", "method=basic", "client=127.0.0.1", `query="| makeresults count=2"`, "earliest=-24h", "outcome=ok"} {
		if !strings.Contains(line, want) {
			t.Errorf("search audit line lacks %s: %s", want, line)
		}
	}

	if code, _ := do(t, ts, "POST", "/api/search", `{"query":"index=other-app"}`, true); code == http.StatusOK {
		t.Fatal("a search outside Signalith's events was run")
	}
	if line := auditLine(t, logs.String(), `query="index=other-app"`); !strings.Contains(line, "outcome=failed") || !strings.Contains(line, "err=") {
		t.Errorf("refused search audit line = %s", line)
	}

	if code, body := do(t, ts, "POST", "/api/panels/run", `{"range":"1h","panel":{"title":"x","viz":"table","query":"| makeresults count=1"}}`, true); code != http.StatusOK {
		t.Fatalf("panel run = %d %v", code, body)
	}
	if line := auditLine(t, logs.String(), `msg="search.panel: ran a panel's search"`); !strings.Contains(line, `query="| makeresults count=1"`) || !strings.Contains(line, "by=admin") {
		t.Errorf("panel audit line = %s", line)
	}
}

func auditLine(t *testing.T, logs, has string) string {
	t.Helper()
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, has) {
			return l
		}
	}
	t.Fatalf("no log line with %s in:\n%s", has, logs)
	return ""
}

// A demo visitor's searches are logged, but not as audit records.
func TestDemoVisitorSearchesAreNotAuditRecords(t *testing.T) {
	var logs logBuffer
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Demo.Enabled = true
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	})
	c := demoVisit(t, ts)
	if code, body, _ := call(t, ts, "POST", "/api/search", `{"query":"| makeresults count=2"}`, "", "", c); code != http.StatusOK {
		t.Fatalf("visitor search = %d %v", code, body)
	}
	line := auditLine(t, logs.String(), `msg="search.run: ran a search"`)
	if strings.Contains(line, "audit=true") || !strings.Contains(line, "demo=true") || !strings.Contains(line, "by=demo") {
		t.Errorf("visitor search line = %s", line)
	}
}
