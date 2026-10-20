// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// postIngest sends a body to /api/ingest with the test token.
func postIngest(t *testing.T, ts *httptest.Server, body []byte) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("X-Signalith-Tag", "linux.auth")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp.Header
}

// TestIngestRefusesOversizedRequests reproduces dos-1 over HTTP: a body
// that would decode into far more memory than it takes on the wire is
// refused with 413 or 400 and a message saying what to change, before
// anything is written; a normal Fluent Bit chunk still goes through.
func TestIngestRefusesOversizedRequests(t *testing.T) {
	ts, fos := newTestServer(t)
	many := bytes.Repeat([]byte("{}\n"), ingest.MaxRecords+1)
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	huge := `[{"log":"` + strings.Repeat("x", ingest.MaxRecordBytes) + `"}]`
	for _, c := range []struct {
		name string
		body []byte
		code int
		msg  string
	}{
		{"body over 16 MB", bytes.Repeat([]byte(" "), ingest.MaxBodyBytes+1), 413, "larger than 16 MB"},
		{"too many records", many, 413, "more than 200000 records"},
		{"record over 1 MB", []byte(huge), 413, "the limit is 1048576 bytes"},
		{"nested too deep", []byte("[" + deep + "]"), 400, "levels deep"},
		{"not objects", []byte(`[1,2,3]`), 400, "not a JSON object"},
		{"broken JSON", []byte(`[{"a":1},{"b":`), 400, "invalid JSON in record 2"},
		{"not JSON", []byte(`hello`), 400, "JSON array of records or JSON lines"},
	} {
		code, out, _ := postIngest(t, ts, c.body)
		msg, _ := out["error"].(string)
		if code != c.code || !strings.Contains(msg, c.msg) {
			t.Errorf("%s: %d %q, want %d and %q", c.name, code, msg, c.code, c.msg)
		}
	}
	if len(fos.bulk) != 0 {
		t.Errorf("refused requests wrote %d events", len(fos.bulk))
	}

	// About what Fluent Bit sends at most per request: a 2 MB chunk.
	var chunk bytes.Buffer
	chunk.WriteByte('[')
	n := 0
	for chunk.Len() < 2<<20 {
		if n > 0 {
			chunk.WriteByte(',')
		}
		fmt.Fprintf(&chunk, `{"date":%d,"log":"Oct 11 09:15:02 web1 sshd[%d]: Failed password for bob from 192.0.2.4 port 1 ssh2"}`, time.Now().Unix(), n)
		n++
	}
	chunk.WriteByte(']')
	code, out, _ := postIngest(t, ts, chunk.Bytes())
	if code != 200 || out["indexed"] != float64(n) || len(fos.bulk) != n {
		t.Errorf("Fluent Bit chunk: %d %v, %d written of %d", code, out["error"], len(fos.bulk), n)
	}
}

// blockingBulk holds every bulk request until release is closed.
type blockingBulk struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingBulk) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	b.started <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

// TestIngestTellsSendersToRetryWhenBusy: only a few batches are decoded
// and written at once, so many agents sending at once cannot make the
// server decode many batches in memory; the rest are told to retry with
// 503.
func TestIngestTellsSendersToRetryWhenBusy(t *testing.T) {
	saved := ingestQueueWait
	ingestQueueWait = 50 * time.Millisecond
	t.Cleanup(func() { ingestQueueWait = saved })
	bb := &blockingBulk{started: make(chan struct{}, 1), release: make(chan struct{})}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Pipeline = &ingest.Pipeline{Store: bb, MaxConcurrent: 1}
	})
	done := make(chan int)
	go func() {
		code, _, _ := postIngest(t, ts, []byte(`[{"log":"first"}]`))
		done <- code
	}()
	<-bb.started
	code, out, hdr := postIngest(t, ts, []byte(`[{"log":"second"}]`))
	if code != 503 || hdr.Get("Retry-After") == "" || !strings.Contains(fmt.Sprint(out["error"]), "busy") {
		t.Errorf("second request: %d %v %v", code, out, hdr)
	}
	close(bb.release)
	if code := <-done; code != 200 {
		t.Errorf("first request: %d", code)
	}
}

// TestIndexParameterStaysInsideSignalith reproduces
// injection-index-pattern-breakout, outbound-index-any-opensearch-index and
// authz-index-param-reads-any-index over every API that runs a query or
// looks at indices: none reaches an index outside "signalith-".
func TestIndexParameterStaysInsideSignalith(t *testing.T) {
	ts, fos := newTestServer(t)
	_, c := do(t, ts, "POST", "/api/cases", `{"title":"Investigation"}`, true)
	cs, _ := c["case"].(map[string]any)
	caseID, _ := cs["id"].(string)
	if caseID == "" {
		t.Fatalf("case: %v", c)
	}
	bad := []string{
		`index=.opendistro_security`,
		`index="signalith-*,.security"`,
		`index=signalith_findings`,
		`index=signalith_cases`,
		`index=other-app-*`,
		`index=remote:signalith-*`,
		`index="<signalith-{now/d}>"`,
		`index=_all`,
		`datamodel=../../_cat`,
	}
	for _, q := range bad {
		body, _ := json.Marshal(map[string]any{"query": q + " | stats count"})
		panel, _ := json.Marshal(map[string]any{"panel": map[string]any{"title": "x", "query": q, "viz": "table"}})
		detection, _ := json.Marshal(map[string]any{"title": "x", "query": q, "schedule": "5m", "lookback": "1h"})
		entry, _ := json.Marshal(map[string]any{"kind": "search", "query": q})
		for _, r := range []struct{ method, path, body string }{
			{"POST", "/api/search", string(body)},
			{"POST", "/api/explain", string(body)},
			{"POST", "/api/detections/test", string(detection)},
			{"POST", "/api/detections/backtest", `{"detection":` + string(detection) + `}`},
			{"POST", "/api/detections", string(detection)},
			{"POST", "/api/cases/" + caseID + "/entries", string(entry)},
		} {
			code, out := do(t, ts, r.method, r.path, r.body, true)
			if code != 400 {
				t.Errorf("%s %s with %s: %d %v", r.method, r.path, q, code, out)
			}
		}
		code, out := do(t, ts, "POST", "/api/panels/run", string(panel), true)
		res, _ := out["result"].(map[string]any)
		if code != 200 || res == nil || res["error"] == nil || res["error"] == "" {
			t.Errorf("panel with %s: %d %v", q, code, out)
		}
	}
	for _, path := range []string{
		"/api/fields?datamodel=../../.security",
		"/api/fields?datamodel=Authentication,x",
		"/api/fields/values?field=user&datamodel=../../.security",
		"/api/fields/values?field=user&datamodel=*",
	} {
		if code, out := do(t, ts, "GET", path, "", true); code != 400 {
			t.Errorf("GET %s: %d %v", path, code, out)
		}
	}
	fos.mu.Lock()
	for _, ix := range fos.indices {
		t.Errorf("searched %q", ix)
	}
	fos.indices = nil
	fos.mu.Unlock()

	// Signalith's own patterns keep working.
	for _, q := range []string{`index=signalith-*`, `index=signalith-authentication-*`, `index=*`, `datamodel=Risk`, `index=signalith-risk-*`} {
		body, _ := json.Marshal(map[string]any{"query": q + " | stats count by src"})
		if code, out := do(t, ts, "POST", "/api/search", string(body), true); code != 200 {
			t.Errorf("%s: %d %v", q, code, out)
		}
	}
	if code, _ := do(t, ts, "GET", "/api/fields?datamodel=Endpoint", "", true); code != 200 {
		t.Errorf("fields for Endpoint: %d", code)
	}
	fos.mu.Lock()
	defer fos.mu.Unlock()
	for _, ix := range fos.indices {
		if !strings.HasPrefix(ix, "signalith-") {
			t.Errorf("searched %q", ix)
		}
	}
}
