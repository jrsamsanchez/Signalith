package api

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestSampleOff(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/sample", "", true); code != http.StatusOK || out["available"] != false {
		t.Errorf("status: %d %v", code, out)
	}
	for _, path := range []string{"/api/sample/load", "/api/sample/remove"} {
		if code, out := do(t, ts, "POST", path, "", true); code != http.StatusServiceUnavailable || out["error"] != errSampleOff.Error() {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
}

// waitSample waits for this server's sample-data job to end, and returns
// the status then.
func waitSample(t *testing.T, call func() (int, map[string]any)) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, out := call()
		if code != http.StatusOK {
			t.Fatalf("status %d %v", code, out)
		}
		if out["running"] == false {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job is still running: %v", out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A load whose events OpenSearch refuses fails in the background, and
// the status says so, in plain English with the detail; a size the
// loader does not know is refused. The removal of what it left then runs.
func TestSampleLoadFailsAndRemove(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	bulker := &modeBulker{fakeOS: &fakeOS{}, mode: "down"}
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Bulk: bulker, Server: "siem-a",
		Findings: findings.NewMemory(), Cases: cases.NewMemory()}
	var logs *logBuffer
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Sample = loader
		logs = &logBuffer{}
		s.Log = slog.New(slog.NewTextHandler(logs, nil))
	})
	status := func() (int, map[string]any) { return do(t, ts, "GET", "/api/sample", "", true) }

	if code, out := do(t, ts, "POST", "/api/sample/load", `{"size":"enormous"}`, true); code != http.StatusBadRequest {
		t.Errorf("an unknown size: %d %v", code, out)
	}
	code, out := do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusAccepted || out["op"] != "load" || out["size"] != "small" {
		t.Fatalf("load: %d %v", code, out)
	}
	st := waitSample(t, status)
	if msg, _ := st["error"].(string); !strings.Contains(msg, "could not load the sample data") || st["error_detail"] == nil {
		t.Fatalf("after a failed load: %v", st)
	}
	if !strings.Contains(logs.String(), "sample data load failed") {
		t.Errorf("logs:\n%s", logs.String())
	}
	if st["partial"] == true {
		code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
		if code != http.StatusAccepted || out["op"] != "remove" {
			t.Fatalf("remove: %d %v", code, out)
		}
		waitSample(t, status)
	}
	if !strings.Contains(logs.String(), "sample data load started") {
		t.Errorf("no audit of the load:\n%s", logs.String())
	}
}
