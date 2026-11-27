// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// metricsBackend is a backend that also reports write blocks and shard
// room, as the OpenSearch client does.
type metricsBackend struct {
	*fakeOS
	health string
	blocks []string
}

func (b *metricsBackend) Health(context.Context) (string, error) {
	if b.healthErr != nil {
		return "", b.healthErr
	}
	return b.health, nil
}
func (b *metricsBackend) WriteBlocks(context.Context) ([]string, error) { return b.blocks, nil }
func (b *metricsBackend) Do(context.Context, string, string, any, any) error {
	return errors.New("not here")
}
func (b *metricsBackend) Endpoints() []store.EndpointStatus { return nil }
func (b *metricsBackend) ShardRoom(context.Context) (int, int, error) {
	return 120, 1000, nil
}

func newFullMetricsServer(t *testing.T, be *metricsBackend) *httptest.Server {
	t.Helper()
	ts, _ := newTestServerWith(t, func(s *Server) {
		sum := sha256.Sum256([]byte(metricsTestToken))
		s.Config.Metrics.Enabled = true
		s.Config.Metrics.TokenSHA256 = hex.EncodeToString(sum[:])
		s.Backend = be
		s.Started = time.Now().Add(-time.Hour)
		rcv := syslog.New(syslog.Config{UDP: "127.0.0.1:0", PublicPort: 514}, s.Pipeline, s.Log)
		ctx, cancel := context.WithCancel(context.Background())
		if err := rcv.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); rcv.Wait() })
		s.Syslog = rcv
		mem := retention.NewMemory()
		mem.DiskTotal, mem.DiskBase = 100*retention.GB, 30*retention.GB
		dir := t.TempDir()
		s.Retention = &retention.Manager{
			Cluster: mem, Prefix: "signalith",
			Config:      retention.Config{Default: &retention.Policy{KeepDays: 30}, Guard: &retention.Guard{MaxDiskPercent: 85}},
			Store:       retention.NewStore(filepath.Join(dir, "retention.yaml")),
			Archive:     &retention.Archive{Dir: filepath.Join(dir, "archive")},
			HistoryFile: filepath.Join(dir, "retention_history.json"),
		}
	})
	return ts
}

// A scrape reports the syslog receiver, OpenSearch's write blocks and
// shard room, and the retention disk guard when each is there.
func TestMetricsReportEveryPart(t *testing.T) {
	be := &metricsBackend{fakeOS: &fakeOS{}, health: "purple", blocks: []string{"signalith-events"}}
	ts := newFullMetricsServer(t, be)
	code, _, body := scrape(t, ts, metricsTestToken, "")
	if code != 200 {
		t.Fatalf("scrape: %d %s", code, body)
	}
	for _, want := range []string{
		"signalith_start_time_seconds ",
		"signalith_syslog_enabled 1\n",
		"signalith_syslog_messages_received_total 0\n",
		`signalith_syslog_messages_rejected_total{reason="not_allowed"} 0`,
		"signalith_syslog_queue_depth 0\n",
		// An answer that is no known status is "unknown".
		`signalith_opensearch_status{status="unknown"} 1`,
		`signalith_opensearch_status{status="green"} 0`,
		"signalith_opensearch_write_blocked 1\n",
		"signalith_opensearch_shards 120\n",
		"signalith_opensearch_shards_limit 1000\n",
		"signalith_retention_running 0\n",
		`signalith_retention_disk_guard_state{state="ok"} `,
		"signalith_retention_disk_guard_limit_percent 85\n",
		"signalith_opensearch_disk_used_percent ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
}

// OpenSearch that cannot be reached is "unreachable", and then neither
// its write blocks nor its shards are asked for.
func TestMetricsUnreachableOpenSearch(t *testing.T) {
	be := &metricsBackend{fakeOS: &fakeOS{healthErr: errors.New("connection refused")}, health: "green", blocks: []string{"x"}}
	ts := newFullMetricsServer(t, be)
	_, _, body := scrape(t, ts, metricsTestToken, "")
	if !strings.Contains(body, `signalith_opensearch_status{status="unreachable"} 1`) {
		t.Errorf("status:\n%s", body)
	}
	if strings.Contains(body, "signalith_opensearch_write_blocked") || strings.Contains(body, "signalith_opensearch_shards ") {
		t.Errorf("asked a cluster it cannot reach:\n%s", body)
	}
}

// The Metrics tab warns that a plain-http public address is not where a
// scrape is answered.
func TestMetricsViewWarnsOfPlainHTTP(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Config.Server.PublicURL = "http://siem.example.com" })
	code, out := do(t, ts, "GET", "/api/metrics", "", true)
	if code != 200 {
		t.Fatalf("view: %d %v", code, out)
	}
	if out["scrape_url"] != "http://siem.example.com/metrics" || !strings.Contains(out["warning"].(string), "only over HTTPS") {
		t.Errorf("view %v", out)
	}
	if allow, ok := out["allow"].([]any); !ok || len(allow) != 0 {
		t.Errorf("allow %v", out["allow"])
	}
}
