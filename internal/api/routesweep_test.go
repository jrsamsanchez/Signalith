// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// TestEveryRouteRefusesBadBodiesCleanly sends malformed and mistyped JSON
// bodies to every API route, as the admin, on two servers with most parts
// set up, with real and unknown ids in the paths. No route may fail with
// an internal error or panic: each answers, and every refusal is JSON
// with an error message.
func TestEveryRouteRefusesBadBodiesCleanly(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	cts, csrv, _, _, _ := chatServer(t)
	tts, tsrv, _ := newTicketingServer(t, func(s *Server) {
		s.Endpoints = endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
		s.Vulns = &Vulns{Store: vulnscan.NewStore(endpoint.NewMemoryDocs(), "signalith")}
		s.Respond = &respond.Runner{Actions: &respond.Actions{File: filepath.Join(t.TempDir(), "response.yaml"), Log: s.Log}, Store: &respond.Memory{}, Log: s.Log}
		s.Feeds = &intel.Feeds{Store: intel.NewStore(intel.NewMemory()), File: filepath.Join(t.TempDir(), "intel_feeds.yaml"), List: []intel.Feed{
			{Name: "on", URL: "https://feeds.invalid/a.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true}}}
		s.Content = &content.Updater{Dir: filepath.Join(t.TempDir(), "content"), Library: s.Detections}
	})
	// skip are routes that act on the whole server or reach out to the
	// network whatever the body says.
	skip := regexp.MustCompile(`restart|/sample/|content/check`)
	wildcard := regexp.MustCompile(`([a-z-]+)/\{([^}]+)\}`)
	refusals := 0
	for _, sv := range []struct {
		ts *httptest.Server
		s  *Server
	}{{cts, csrv}, {tts, tsrv}} {
		ids := map[string]string{"findings": "f1", "runs": "run1", "users": "andy", "feeds": "on", "channels": "soc", "policies": "endpoint", "lookups": "assets"}
		if _, out := do(t, sv.ts, "POST", "/api/cases", `{"title":"sweep"}`, true); out["case"] != nil {
			ids["cases"], _ = out["case"].(map[string]any)["id"].(string)
		}
		if _, out := do(t, sv.ts, "POST", "/api/notebooks", `{"title":"sweep"}`, true); out["notebook"] != nil {
			ids["notebooks"], _ = out["notebook"].(map[string]any)["id"].(string)
		}
		_, out := do(t, sv.ts, "POST", "/api/dashboards", `{"title":"sweep","panels":[{"title":"x","query":"user=bob | stats count","viz":"table"}]}`, true)
		ids["dashboards"], _ = out["id"].(string)
		if _, out := do(t, sv.ts, "GET", "/api/detections", "", true); out["detections"] != nil {
			if ds := out["detections"].([]any); len(ds) > 0 {
				ids["detections"], _ = ds[0].(map[string]any)["id"].(string)
			}
		}
		if ids["cases"] == "" || ids["notebooks"] == "" || ids["dashboards"] == "" || ids["detections"] == "" {
			t.Fatalf("fixtures: %v", ids)
		}
		for _, body := range []string{"{", `{"x":1}`, `[]`} {
			for _, rt := range sv.s.routes {
				method, path, _ := strings.Cut(rt.Pattern, " ")
				if skip.MatchString(path) {
					continue
				}
				path = wildcard.ReplaceAllStringFunc(path, func(m string) string {
					sub := wildcard.FindStringSubmatch(m)
					if id := ids[sub[1]]; id != "" {
						return sub[1] + "/" + id
					}
					return sub[1] + "/nope"
				})
				path = strings.NewReplacer("{", "", "}", "").Replace(path)
				req, _ := http.NewRequest(method, sv.ts.URL+path, strings.NewReader(body))
				req.SetBasicAuth("admin", "s3cret-pass")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 500 && resp.StatusCode != http.StatusServiceUnavailable {
					t.Errorf("%s %s with %q: %d %s", method, path, body, resp.StatusCode, raw)
				}
				if resp.StatusCode < 400 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
					continue
				}
				refusals++
				var e map[string]any
				if err := json.Unmarshal(raw, &e); err != nil {
					t.Errorf("%s %s with %q: refusal is not JSON: %s", method, path, body, raw)
				} else if msg, _ := e["error"].(string); msg == "" && e["detail"] == nil {
					t.Errorf("%s %s with %q: refusal without a message: %s", method, path, body, raw)
				}
			}
		}
	}
	if refusals < 500 {
		t.Errorf("only %d refusals: the sweep did not reach the handlers", refusals)
	}
}
