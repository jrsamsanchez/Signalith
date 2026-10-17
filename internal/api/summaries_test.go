package api

import (
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/summary"
)

func TestSummariesStatus(t *testing.T) {
	cov := &summary.Coverage{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Engine.Summaries = cov
		s.Engine.SetDefaults("", 0, 30)
	})
	model := summary.Models()[0]
	through := time.Now().Add(-2 * time.Hour).Truncate(summary.Slot)
	from := through.Add(-48 * time.Hour)
	gap := summary.Gap{From: from.Add(time.Hour), To: from.Add(2 * time.Hour)}
	cov.SetStates(map[string]summary.State{model: {Model: model, From: from, Through: through, Gaps: []summary.Gap{gap}, Rows: 1234, LastError: "too slow"}})

	code, out, raw := call(t, ts, "GET", "/api/summaries", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("get %d %s", code, raw)
	}
	if out["enabled"] != true || out["summary_days"].(float64) != 30 {
		t.Errorf("view %v", out)
	}
	tenants := out["tenants"].([]any)
	if len(tenants) != 1 {
		t.Fatalf("tenants %v", tenants)
	}
	ten := tenants[0].(map[string]any)
	models := ten["models"].([]any)
	if ten["tenant"] != "default" || ten["read"] == nil || len(models) != len(summary.Models()) {
		t.Fatalf("tenant %v", ten)
	}
	m := models[0].(map[string]any)
	if m["model"] != model || m["built"] != true || m["rows"].(float64) != 1234 || m["last_error"] != "too slow" ||
		len(m["gaps"].([]any)) != 1 || len(m["covered"].([]any)) != 2 {
		t.Errorf("model %v", m)
	}
	if b := m["behind_s"].(float64); b < 7200 || b > 7600 {
		t.Errorf("behind %v", b)
	}
	if other := models[1].(map[string]any); other["built"] != false || other["covered"] != nil {
		t.Errorf("unbuilt model %v", other)
	}
}
