// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/metrics"
)

const metricsTestToken = "sgl_metrics_test-token-0123456789abcdefghijklmnopqrstuvwxyz"

// newMetricsServer starts a server with the metrics endpoint on, or off
// when on is false.
func newMetricsServer(t *testing.T, on bool) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		if on {
			sum := sha256.Sum256([]byte(metricsTestToken))
			s.Config.Metrics.Enabled = true
			s.Config.Metrics.TokenSHA256 = hex.EncodeToString(sum[:])
		}
	})
	return ts, srv
}

func scrape(t *testing.T, ts *httptest.Server, token, accept string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

func TestMetricsOffByDefault(t *testing.T) {
	ts, s := newMetricsServer(t, false)
	if code, _, _ := scrape(t, ts, metricsTestToken, ""); code != http.StatusNotFound {
		t.Errorf("off: %d", code)
	}
	// Turned on without a token, it stays off.
	s.Config.Metrics.Enabled = true
	if code, _, _ := scrape(t, ts, "", ""); code != http.StatusNotFound {
		t.Errorf("on without a token: %d", code)
	}
	// Signing in is no way in either.
	if code, _, _ := call(t, ts, "GET", "/metrics", "", "admin", adminPass, nil); code != http.StatusNotFound {
		t.Errorf("admin password: %d", code)
	}
}

func TestMetricsNeedTheToken(t *testing.T) {
	ts, _ := newMetricsServer(t, true)
	for _, tok := range []string{"", "wrong", strings.ToUpper(metricsTestToken), metricsTestToken + "x"} {
		code, h, _ := scrape(t, ts, tok, "")
		if code != http.StatusUnauthorized || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("token %q: %d %v", tok, code, h)
		}
	}
	if code, _, _ := call(t, ts, "GET", "/metrics", "", "admin", adminPass, nil); code != http.StatusUnauthorized {
		t.Errorf("admin password: %d", code)
	}
	code, h, body := scrape(t, ts, metricsTestToken, "")
	if code != 200 || h.Get("Content-Type") != metrics.ContentTypeText || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("scrape: %d %v\n%s", code, h, body)
	}
	for _, want := range []string{
		`signalith_build_info{version="test",goversion="go`,
		"# TYPE signalith_ingest_events_total counter",
		`signalith_ingest_events_total{intake="agent",result="indexed"} `,
		`signalith_opensearch_rejected_events_total{reason="shard_limit"} `,
		`signalith_opensearch_rejected_events_total{reason="read_only"} `,
		`signalith_opensearch_rejected_events_total{reason="too_many_requests"} `,
		"# TYPE signalith_opensearch_bulk_duration_seconds histogram",
		`signalith_opensearch_bulk_duration_seconds_bucket{le="+Inf"} `,
		`signalith_ingest_slot_wait_seconds_bucket{le="0.001"} `,
		"signalith_ingest_slots 32\n",
		"signalith_syslog_enabled 0\n",
		"signalith_jobs_holder ",
		`signalith_opensearch_status{status="green"} `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "# EOF") {
		t.Error("the text format has # EOF")
	}
	// Every line is a comment or a sample of a signalith_ metric.
	line := regexp.MustCompile(`^(# (HELP|TYPE) signalith_[a-z_]+ .+|signalith_[a-z_]+(\{[a-z_]+="[^"\\\n]*"(,[a-z_]+="[^"\\\n]*")*\})? [-+0-9.eInf]+)$`)
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if !line.MatchString(l) {
			t.Errorf("line %q", l)
		}
	}

	// OpenMetrics for a scraper that asks for it.
	code, h, body = scrape(t, ts, metricsTestToken, "application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5")
	if code != 200 || h.Get("Content-Type") != metrics.ContentTypeOpenMetrics || !strings.HasSuffix(body, "# EOF\n") ||
		!strings.Contains(body, "# TYPE signalith_ingest_events counter\n") || !strings.Contains(body, "# TYPE signalith_build info\n") {
		t.Errorf("openmetrics: %d %v\n%s", code, h, body)
	}
}

// Over plain HTTP from another computer the token would cross the network
// in the clear, so the scrape is refused before it is looked at; so is
// one from an address metrics.allow leaves out.
func TestMetricsHTTPSAndAllowList(t *testing.T) {
	_, s := newMetricsServer(t, true)
	h := s.Handler()
	get := func(remote string) int {
		req := httptest.NewRequest("GET", "/metrics", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+metricsTestToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get("203.0.113.5:40000"); code != http.StatusForbidden {
		t.Errorf("plain HTTP from elsewhere: %d", code)
	}
	if code := get("127.0.0.1:40000"); code != 200 {
		t.Errorf("plain HTTP from this computer: %d", code)
	}
	s.Config.Metrics.Allow = []string{"192.0.2.0/24"}
	if code := get("127.0.0.1:40001"); code != http.StatusForbidden {
		t.Errorf("not allowed: %d", code)
	}
	s.Config.Metrics.Allow = []string{"192.0.2.0/24", "127.0.0.1"}
	if code := get("127.0.0.1:40002"); code != 200 {
		t.Errorf("allowed: %d", code)
	}
}

func TestMetricsRateLimit(t *testing.T) {
	ts, _ := newMetricsServer(t, true)
	limited := false
	for i := 0; i < metricsPerAddress+1; i++ {
		code, h, _ := scrape(t, ts, "wrong", "")
		if code == http.StatusTooManyRequests {
			limited = h.Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Error("no limit on scrapes")
	}
	if code, _, _ := scrape(t, ts, metricsTestToken, ""); code != http.StatusTooManyRequests {
		t.Errorf("after the limit: %d", code)
	}
}

func TestMetricsToken(t *testing.T) {
	ts, _ := newMetricsServer(t, false)
	if code, _ := doAs(t, ts, "admin", adminPass, "POST", "/api/metrics/token", ""); code != 200 {
		t.Fatalf("token: %d", code)
	}
	_, out := doAs(t, ts, "admin", adminPass, "POST", "/api/metrics/token", "")
	tok, _ := out["token"].(string)
	sum := sha256.Sum256([]byte(tok))
	if !strings.HasPrefix(tok, metricsTokenPrefix) || len(tok) < 50 || out["sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("token: %v", out)
	}
	code, view := doAs(t, ts, "admin", adminPass, "GET", "/api/metrics", "")
	if code != 200 || view["on"] != false || view["token_set"] != false || !strings.HasSuffix(view["scrape_url"].(string), "/metrics") {
		t.Errorf("view: %d %v", code, view)
	}
}
