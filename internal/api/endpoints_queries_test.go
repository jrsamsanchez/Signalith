package api

import (
	"net/http"
	"strings"
	"testing"
)

// A live query goes to the hosts picked: all of them, those of one
// platform, or only those online; one with no host to go to, or no SQL,
// is a 400, and a store that fails a 502.
func TestNewLiveQueryTargets(t *testing.T) {
	docs := newFailDocs()
	st, _ := enrolled(t, docs)
	ts, _ := newTestServerWith(t, func(s *Server) { s.Endpoints = st })
	send := func(body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, "POST", "/api/endpoints/queries", body, true)
	}
	targets := func(out map[string]any) []string {
		var ids []string
		for _, id := range out["targets"].([]any) {
			ids = append(ids, id.(string))
		}
		return ids
	}
	if code, _ := send(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	code, out := send(`{"sql":"select * from users;","all":true,"platform":"windows"}`)
	if code != http.StatusOK || strings.Join(targets(out), ",") != "n3" || out["created_by"] != "admin" {
		t.Errorf("windows: %d %v", code, out)
	}
	code, out = send(`{"sql":"select 1;","targets":["n1","n2"],"online":true}`)
	if code != http.StatusOK || strings.Join(targets(out), ",") != "n1" {
		t.Errorf("online: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if code, out := do(t, ts, "GET", "/api/endpoints/queries/"+id, "", true); code != http.StatusOK || out["expired"] != false {
		t.Errorf("read: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/endpoints/queries/nope", "", true); code != http.StatusNotFound {
		t.Errorf("unknown query: %d", code)
	}
	if code, out := send(`{"sql":"select 1;","targets":["nope"]}`); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "none of the chosen hosts") {
		t.Errorf("no host: %d %v", code, out)
	}
	if code, out := send(`{"sql":"  ","all":true}`); code != http.StatusBadRequest || out["error"] != "write a query first" {
		t.Errorf("no SQL: %d %v", code, out)
	}
	docs.failing(failOn("create", "lq:"))
	if code, _ := send(`{"sql":"select 1;","all":true}`); code != http.StatusBadGateway {
		t.Errorf("store fails: %d", code)
	}
}

// Endpoint settings are saved over the version the page read; a stale
// one is a 409, and a store that cannot be read a 502.
func TestSaveEndpointSettingsErrors(t *testing.T) {
	docs := newFailDocs()
	st, _ := enrolled(t, docs)
	ts, _ := newTestServerWith(t, func(s *Server) { s.Endpoints = st })
	if code, _ := do(t, ts, "PUT", "/api/endpoints/settings", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	_, cur := do(t, ts, "GET", "/api/endpoints/settings", "", true)
	if code, out := do(t, ts, "PUT", "/api/endpoints/settings", `{"settings":{},"version":"stale"}`, true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "someone else saved") {
		t.Errorf("stale: %d %v", code, out)
	}
	docs.failing(failOn("get", ""))
	if code, _ := do(t, ts, "PUT", "/api/endpoints/settings", `{"settings":{},"version":"`+cur["version"].(string)+`"}`, true); code != http.StatusBadGateway {
		t.Errorf("store fails: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/endpoints/settings", "", true); code != http.StatusBadGateway {
		t.Errorf("read fails: %d", code)
	}
}
