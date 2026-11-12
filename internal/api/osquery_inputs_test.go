// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

// Without endpoint management every osquery route says so with 503, so
// osquery tries again later instead of dropping its data.
func TestOsqueryRoutesWithoutEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, path := range []string{"/api/osquery/config", "/api/osquery/log", "/api/osquery/distributed/read", "/api/osquery/distributed/write"} {
		if code, out := do(t, ts, "POST", path, `{"node_key":"x"}`, false); code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
}

// A live query answer that is not JSON is refused, one from an unknown
// node is told to enroll again, and answers to ids that cannot be
// queries are skipped.
func TestOsqueryWriteChecks(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Endpoints = endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
	})
	code, body := do(t, ts, "POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false)
	key, _ := body["node_key"].(string)
	if code != http.StatusOK || key == "" {
		t.Fatalf("enroll: %d %v", code, body)
	}
	write := "/api/osquery/distributed/write"
	if code, out := do(t, ts, "POST", write, `{`, false); code != http.StatusBadRequest || out["error"] != "not valid JSON" {
		t.Errorf("bad JSON: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", write, `{"node_key":"nope","queries":{}}`, false); code != http.StatusUnauthorized || out["node_invalid"] != true {
		t.Errorf("unknown node: %d %v", code, out)
	}
	long := strings.Repeat("q", 65)
	if code, out := do(t, ts, "POST", write, `{"node_key":"`+key+`","queries":{"`+long+`":[{"a":"b"}],"unknown-query":[]},"statuses":{"unknown-query":0}}`, false); code != http.StatusOK {
		t.Errorf("answers: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/osquery/distributed/read", `{"node_key":"`+key+`"}`, false); code != http.StatusOK || out["queries"] == nil {
		t.Errorf("read: %d %v", code, out)
	}
}

func TestOsqueryTextHelpers(t *testing.T) {
	if got := cut("  Xeon\x00\x00 ", 10); got != "Xeon" {
		t.Errorf("cut %q", got)
	}
	if got := cut("abcdefgh", 3); got != "abc" {
		t.Errorf("cut long %q", got)
	}
	if got := firstNonEmpty("", "  ", " web1 ", "x"); got != "web1" {
		t.Errorf("firstNonEmpty %q", got)
	}
	if got := firstNonEmpty("", " "); got != "" {
		t.Errorf("firstNonEmpty none %q", got)
	}
	for s, want := range map[string]int64{"0": 0, "8589934592": 8589934592} {
		if n, ok := parseInt(s); !ok || n != want {
			t.Errorf("parseInt(%q) = %d %v", s, n, ok)
		}
	}
	for _, s := range []string{"", "-1", "12a", "99999999999999999999"} {
		if _, ok := parseInt(s); ok {
			t.Errorf("parseInt(%q) parsed", s)
		}
	}
	s := &Server{}
	if s.isHostKeyID("") {
		t.Error("empty id is a host key")
	}
}
