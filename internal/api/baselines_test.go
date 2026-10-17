package api

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The page reads every check with its counts, saves settings and
// exceptions over the version it read, and asks for a reset.
func TestBaselinesPage(t *testing.T) {
	srv := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: srv.URL}), "t")
	if err := st.EnsureIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Baselines = st })
	code, out, raw := call(t, ts, "GET", "/api/baselines", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("get %d %s", code, raw)
	}
	checks := out["checks"].([]any)
	if len(checks) != len(baselines.Checks) {
		t.Fatalf("%d checks", len(checks))
	}
	first := checks[0].(map[string]any)
	if first["id"] != baselines.NewCountry || first["on"] != true || first["score"].(float64) != 40 ||
		!strings.Contains(first["waiting"].(string), "IP database") {
		t.Errorf("check %v", first)
	}
	version := out["version"].(string)
	body := `{"version":"` + version + `","settings":{"learning_days":21,"checks":{"unusual-hour":{"off":true},"new-country":{"score":60}},` +
		`"exceptions":[{"id":"ex-made-up","match":{"baseline":"new-country","src_country":" CA ","risk_object":""},"comment":" travel "}]}}`
	code, out, raw = call(t, ts, "PUT", "/api/baselines", body, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("put %d %s", code, raw)
	}
	set, _, _ := st.Settings(context.Background())
	if set.LearningDays != 21 || set.On(baselines.UnusualHour) || set.Score(baselines.NewCountry) != 60 {
		t.Errorf("saved %+v", set)
	}
	ex := set.Exceptions[0]
	if ex.ID == "ex-made-up" || ex.By != "admin" || ex.Added.IsZero() || ex.Match["src_country"] != "CA" || len(ex.Match) != 2 || ex.Comment != "travel" {
		t.Errorf("exception %+v", ex)
	}
	// The old version is refused.
	if code, _, _ = call(t, ts, "PUT", "/api/baselines", body, "admin", "s3cret-pass", nil); code != 409 {
		t.Errorf("stale version: %d", code)
	}
	version = out["version"].(string)
	bad := `{"version":"` + version + `","settings":{"learning_days":400,"ip_database":"ftp://x/y.gz"}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", bad, "admin", "s3cret-pass", nil); code != 400 || !strings.Contains(raw, "learning period") {
		t.Errorf("bad settings: %d %s", code, raw)
	}
	// A save keeps a saved exception's author and time.
	keep := `{"version":"` + version + `","settings":{"exceptions":[{"id":"` + ex.ID + `","by":"mallory","match":{"src_country":"CA"}}]}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", keep, "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("keep %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if got := set.Exceptions[0]; got.ID != ex.ID || got.By != "admin" || !got.Added.Equal(ex.Added) {
		t.Errorf("kept %+v", got)
	}
	if code, _, _ = call(t, ts, "POST", "/api/baselines/nope/reset", "", "admin", "s3cret-pass", nil); code != 404 {
		t.Errorf("unknown check: %d", code)
	}
	if code, _, raw = call(t, ts, "POST", "/api/baselines/rare-process/reset", "", "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("reset %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if set.Checks[baselines.RareProcess].ResetAt.IsZero() {
		t.Error("reset not asked for")
	}
	// A save cannot ask for a reset, nor drop one asked for.
	_, out, _ = call(t, ts, "GET", "/api/baselines", "", "admin", "s3cret-pass", nil)
	version = out["version"].(string)
	sneak := `{"version":"` + version + `","settings":{"checks":{"new-change":{"reset_at":"2030-01-01T00:00:00Z"}}}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", sneak, "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("sneak %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if !set.Checks[baselines.NewChange].ResetAt.IsZero() || set.Checks[baselines.RareProcess].ResetAt.IsZero() {
		t.Errorf("resets %+v", set.Checks)
	}
}
