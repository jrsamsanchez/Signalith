package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// modeBulker stores events in fakeOS, or fails as its mode says: "down"
// fails the whole request, "busy" refuses every event for now (429),
// "bad" refuses every event for good (400).
type modeBulker struct {
	*fakeOS
	mu   sync.Mutex
	mode string
}

func (b *modeBulker) set(mode string) {
	b.mu.Lock()
	b.mode = mode
	b.mu.Unlock()
}

func (b *modeBulker) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	b.mu.Lock()
	mode := b.mode
	b.mu.Unlock()
	var errs []store.BulkItemError
	for i, d := range docs {
		switch mode {
		case "busy":
			errs = append(errs, store.BulkItemError{Index: d.Index, Reason: "too many requests", Pos: i, Status: http.StatusTooManyRequests})
		case "bad":
			errs = append(errs, store.BulkItemError{Index: d.Index, Reason: "failed to parse", Pos: i, Type: "mapper_parsing_exception", Status: http.StatusBadRequest})
		}
	}
	if mode == "down" {
		return nil, errors.New("connection refused")
	}
	if len(errs) > 0 {
		return errs, nil
	}
	return b.fakeOS.Bulk(ctx, docs)
}

// HEC senders retry what is answered 503, and only that: a store that is
// down or busy is 503 with Retry-After; events it refuses for good and
// bodies that are not what they say are 4xx.
func TestHECFailures(t *testing.T) {
	var bulker *modeBulker
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Ingest.HEC = true
		bulker = &modeBulker{fakeOS: &fakeOS{}}
		s.Pipeline = &ingest.Pipeline{Store: bulker}
	})
	auth := "Splunk tok-0123456789abcdef"
	event := `{"event":"hello","host":"app1"}`
	send := func(path, body string, header map[string]string) (int, map[string]any) {
		t.Helper()
		return hecSend(t, ts.URL, path, auth, body, header)
	}
	if code, out := send("/services/collector/event", event, map[string]string{"Content-Encoding": "br"}); code != http.StatusUnsupportedMediaType || out["code"].(float64) != ingest.HECInvalidFormat {
		t.Errorf("brotli: %d %v", code, out)
	}
	if code, out := send("/services/collector/event", "not gzip at all", map[string]string{"Content-Encoding": "gzip"}); code != http.StatusBadRequest || out["code"].(float64) != ingest.HECInvalidFormat {
		t.Errorf("bad gzip: %d %v", code, out)
	}
	if code, out := send("/services/collector/raw?host=db1", "one line\n", map[string]string{"Content-Encoding": "identity"}); code != http.StatusOK || out["text"] != "Success" {
		t.Errorf("identity: %d %v", code, out)
	}

	bulker.set("down")
	code, out := send("/services/collector/event", event, nil)
	if code != http.StatusServiceUnavailable || out["code"].(float64) != ingest.HECServerBusy {
		t.Errorf("store down: %d %v", code, out)
	}
	bulker.set("busy")
	if code, out := send("/services/collector/event", event, nil); code != http.StatusServiceUnavailable || out["code"].(float64) != ingest.HECServerBusy {
		t.Errorf("store busy: %d %v", code, out)
	}
	bulker.set("bad")
	if code, out := send("/services/collector/event", event, nil); code != http.StatusOK {
		t.Errorf("events refused for good: %d %v", code, out)
	}
	bulker.set("")
	if code, out := send("/services/collector/event", event, nil); code != http.StatusOK || len(bulker.fakeOS.bulk) != 2 {
		t.Errorf("after: %d %v, %d stored", code, out, len(bulker.fakeOS.bulk))
	}
}

// With the intake off, health and ack say so too.
func TestHECOff(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, path := range []string{"/services/collector/ack", "/services/collector/event"} {
		if code, out := hecSend(t, ts.URL, path, "Splunk tok-0123456789abcdef", `{}`, nil); code != http.StatusForbidden || out["code"].(float64) != ingest.HECTokenDisabled {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
	resp, err := http.Get(ts.URL + "/services/collector/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("health: %d", resp.StatusCode)
	}
}
