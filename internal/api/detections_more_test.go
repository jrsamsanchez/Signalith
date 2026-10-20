// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// failFindings is a findings store whose reads and writes fail with err
// while it is set.
type failFindings struct {
	findings.Store
	mu  sync.Mutex
	err error
}

func (f *failFindings) failing(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *failFindings) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *failFindings) Create(ctx context.Context, x *findings.Finding) error {
	if err := f.get(); err != nil {
		return err
	}
	return f.Store.Create(ctx, x)
}

func (f *failFindings) Get(ctx context.Context, id string) (*findings.Finding, error) {
	if err := f.get(); err != nil {
		return nil, err
	}
	return f.Store.Get(ctx, id)
}

func (f *failFindings) Modify(ctx context.Context, id string, change func(*findings.Finding) (bool, error)) (*findings.Finding, error) {
	if err := f.get(); err != nil {
		return nil, err
	}
	return f.Store.Modify(ctx, id, change)
}

func (f *failFindings) Search(ctx context.Context, flt findings.Filter) ([]*findings.Finding, int, error) {
	if err := f.get(); err != nil {
		return nil, 0, err
	}
	return f.Store.Search(ctx, flt)
}

func (f *failFindings) Summary(ctx context.Context) (*findings.Summary, error) {
	if err := f.get(); err != nil {
		return nil, err
	}
	return f.Store.Summary(ctx)
}

// Without detections every detection and finding route says so.
func TestDetectionsOff(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Detections = nil })
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/detections"}, {"GET", "/api/detections/x"}, {"GET", "/api/detections/x/yaml"}, {"GET", "/api/coverage"},
		{"GET", "/api/detections/packs"}, {"POST", "/api/detections"}, {"POST", "/api/detections/test"},
		{"POST", "/api/detections/enable"}, {"PUT", "/api/detections/x"}, {"DELETE", "/api/detections/x"},
		{"POST", "/api/detections/x/run"}, {"GET", "/api/findings"}, {"GET", "/api/findings/summary"},
		{"GET", "/api/findings/x"}, {"POST", "/api/findings"}, {"POST", "/api/findings/bulk"}, {"PATCH", "/api/findings/x"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "{}", true); code != http.StatusServiceUnavailable || out["error"] != errDetectionsOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
}

// Each check of a request is a 400, a missing detection a 404, and a
// findings store that fails a 502.
func TestDetectionsAndFindingsErrors(t *testing.T) {
	store := &failFindings{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		store.Store = s.Findings
		s.Findings = store
		s.Scheduler.Findings = store
	})
	for _, c := range []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"POST", "/api/detections", `{`, 400, ""},
		{"PUT", "/api/detections/x", `{`, 400, ""},
		{"PUT", "/api/detections/x", `{"id":"y"}`, 400, "does not match the URL"},
		{"POST", "/api/detections/test", `{`, 400, ""},
		{"POST", "/api/detections/test", `{"query":"*","severity":"apocalyptic"}`, 400, ""},
		{"POST", "/api/detections/enable", `{`, 400, ""},
		{"POST", "/api/detections/enable", `{"ids":[]}`, 400, "send between 1 and 5000 detection ids"},
		{"GET", "/api/detections/nope", "", 404, ""},
		{"GET", "/api/detections/nope/yaml", "", 404, ""},
		{"POST", "/api/detections/nope/run", "", 404, ""},
		{"GET", "/api/findings?since=forever", "", 400, "since: "},
		{"GET", "/api/findings?limit=5000", "", 400, "limit must be 1-1000"},
		{"GET", "/api/findings?sort=owner", "", 400, "sort must be one of"},
		{"GET", "/api/findings?after=%7B%7D", "", 400, "page cursor is not valid"},
		{"GET", "/api/findings/nope", "", 404, ""},
		{"POST", "/api/findings", `{`, 400, ""},
		{"POST", "/api/findings", `{"title":" "}`, 400, "title is required"},
		{"POST", "/api/findings", `{"title":"x","severity":"apocalyptic"}`, 400, ""},
		{"POST", "/api/findings/bulk", `{`, 400, ""},
		{"POST", "/api/findings/bulk", `{"ids":[]}`, 400, "ids must list 1-500 findings"},
		{"POST", "/api/findings/bulk", `{"ids":["a"],"update":{"status":"nonsense"}}`, 400, ""},
		{"PATCH", "/api/findings/x", `{`, 400, ""},
		{"PATCH", "/api/findings/x", `{"status":"nonsense"}`, 400, ""},
		{"PATCH", "/api/findings/nope", `{"status":"closed"}`, 404, ""},
	} {
		code, out := do(t, ts, c.method, c.path, c.body, true)
		if msg, _ := out["error"].(string); code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %s: %d %v", c.method, c.path, c.body, code, out)
		}
	}

	// A finding raised by hand keeps the entities of its result, and the
	// filters of the queue apply.
	code, out := do(t, ts, "POST", "/api/findings", `{"title":"Odd login","query":"* | head 1","result":{"user":"bob","src":"10.0.0.9","other":1}}`, true)
	if code != http.StatusCreated || out["severity"] != "medium" || out["entities"].(map[string]any)["user"] != "bob" {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	if code, out := do(t, ts, "GET", "/api/findings?since=-1h&limit=5&status=new&severity=medium", "", true); code != http.StatusOK || out["total"] != float64(1) {
		t.Errorf("list: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/findings/bulk", `{"ids":["`+id+`","nope"],"update":{"status":"closed"}}`, true); code != http.StatusOK || out["updated"] != float64(1) || out["failed"].(map[string]any)["nope"] == nil {
		t.Errorf("bulk: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/findings/"+id, "", true); code != http.StatusOK || out["finding"].(map[string]any)["status"] != "closed" {
		t.Errorf("get: %d %v", code, out)
	}

	store.failing(errDown)
	for _, rt := range []struct{ method, path, body string }{
		{"GET", "/api/findings", ""}, {"GET", "/api/findings/summary", ""}, {"GET", "/api/findings/" + id, ""},
		{"POST", "/api/findings", `{"title":"x"}`}, {"PATCH", "/api/findings/" + id, `{"status":"new"}`},
	} {
		if code, out := do(t, ts, rt.method, rt.path, rt.body, true); code != http.StatusBadGateway {
			t.Errorf("%s %s with a failing store: %d %v", rt.method, rt.path, code, out)
		}
	}
	store.failing(findings.ErrBusy)
	if code, out := do(t, ts, "PATCH", "/api/findings/"+id, `{"status":"new"}`, true); code != http.StatusConflict || out["error"] != errFindingBusy.Error() {
		t.Errorf("busy: %d %v", code, out)
	}
	store.failing(nil)
}

// A detection can be read as YAML, tested before it is saved, created
// once, changed, run and deleted.
func TestDetectionLifecycle(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Cluster = &fakeCluster{holder: "siem-a"} })
	det := `{"id":"t-odd","title":"Odd {user}","query":"* | stats count by user","severity":"low","schedule":"1h","lookback":"1h"}`
	code, out := do(t, ts, "POST", "/api/detections/test", `{"query":"* | stats count by user","schedule":"1h","lookback":"1h"}`, true)
	if code != http.StatusOK || out["titles"] == nil {
		t.Fatalf("test: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/detections", det, true); code != http.StatusCreated || out["etag"] == "" {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/detections", det, true); code != http.StatusConflict {
		t.Errorf("create twice: %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/detections/t-odd/yaml", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "t-odd") || !strings.Contains(resp.Header.Get("Content-Disposition"), "t-odd.yaml") {
		t.Errorf("yaml: %d %s", resp.StatusCode, body)
	}
	if code, out := do(t, ts, "PUT", "/api/detections/t-odd", `{"title":"Odd","query":"* | stats count by user","severity":"high","schedule":"1h","lookback":"1h"}`, true); code != http.StatusOK || out["severity"] != "high" {
		t.Errorf("put: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/detections", "", true); code != http.StatusOK || out["runs_on"] != "siem-a" || out["scheduler"] != false {
		t.Errorf("list on a standby server: %d runs_on %v scheduler %v", code, out["runs_on"], out["scheduler"])
	}
	if code, out := do(t, ts, "POST", "/api/detections/t-odd/run", "", true); code != http.StatusOK {
		t.Errorf("run: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/detections/enable", `{"ids":["t-odd"],"enabled":true}`, true); code != http.StatusOK || out["changed"] != float64(1) {
		t.Errorf("enable: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/detections/packs", "", true); code != http.StatusOK || out["packs"] == nil {
		t.Errorf("packs: %d %v", code, out)
	}
	if code, out := do(t, ts, "DELETE", "/api/detections/t-odd", "", true); code != http.StatusOK || out["deleted"] != true {
		t.Errorf("delete: %d %v", code, out)
	}
}

// A Sigma rule comes as YAML or as JSON {"rule": ...}; one that is not a
// rule is a 400.
func TestSigmaBodies(t *testing.T) {
	ts, _ := newTestServer(t)
	post := func(body, ctype string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+"/api/detections/sigma", strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := post(`{`, "application/json"); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d %s", code, body)
	}
	if code, body := post(`{"rule":"title: x"}`, "application/json; charset=utf-8"); code != http.StatusBadRequest {
		t.Errorf("not a rule: %d %s", code, body)
	}
	if code, body := post("title: [", ""); code != http.StatusBadRequest {
		t.Errorf("bad YAML: %d %s", code, body)
	}
}
