// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// osquery's status log keeps only its latest error (severity 2 or more),
// sent as objects or as JSON strings; logs Signalith does not keep are
// answered and dropped, and results that cannot be stored are asked for
// again with 503.
func TestOsqueryLogStatusAndFailures(t *testing.T) {
	var bulker *modeBulker
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Endpoints = endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
		bulker = &modeBulker{fakeOS: &fakeOS{}}
		s.Pipeline = &ingest.Pipeline{Store: bulker}
	})
	call := func(path, body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, "POST", path, body, false)
	}
	code, body := call("/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"))
	key, _ := body["node_key"].(string)
	if code != http.StatusOK || key == "" {
		t.Fatalf("enroll: %d %v", code, body)
	}

	if code, _ := call("/api/osquery/log", `{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, body := call("/api/osquery/log", `{"node_key":"nope","log_type":"status","data":[]}`); code != http.StatusUnauthorized || body["node_invalid"] != true {
		t.Errorf("unknown node: %d %v", code, body)
	}
	status := `{"node_key":"` + key + `","log_type":"status","data":[` +
		`{"severity":"2","message":"first error"},` +
		`"{\"severity\":\"2\",\"message\":\"disk read failed\"}",` +
		`{"severity":"1","message":"a path to watch is missing"},` +
		`"not json",{"severity":"x"}]}`
	if code, body := call("/api/osquery/log", status); code != http.StatusOK {
		t.Fatalf("status: %d %v", code, body)
	}
	if code, body := call("/api/osquery/log", `{"node_key":"`+key+`","log_type":"snapshot","data":[{}]}`); code != http.StatusOK {
		t.Errorf("a log type that is not kept: %d %v", code, body)
	}
	_, list := do(t, ts, "GET", "/api/endpoints", "", true)
	eps, _ := list["endpoints"].([]any)
	if len(eps) != 1 || eps[0].(map[string]any)["last_error"] != "disk read failed" {
		t.Errorf("endpoint after the status log: %v", list)
	}

	result := `{"node_key":"` + key + `","log_type":"result","data":[{"name":"signalith_software","unixTime":` +
		fmt.Sprint(nowUnix()) + `,"diffResults":{"added":[{"name":"openssl","version":"3.0.2"}],"removed":[]}}]}`
	bulker.set("down")
	code, body = call("/api/osquery/log", result)
	if code != http.StatusServiceUnavailable || body["error"] != "results could not be stored right now; try again later" {
		t.Errorf("store down: %d %v", code, body)
	}
	bulker.set("")
	if code, body := call("/api/osquery/log", result); code != http.StatusOK || len(bulker.fakeOS.bulk) == 0 {
		t.Errorf("store back: %d %v, %d stored", code, body, len(bulker.fakeOS.bulk))
	}
}
