package api

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

func newRetentionServer(t *testing.T, cfg retention.Config) (*retention.Manager, *retention.Memory, func(method, path, body string) (int, map[string]any)) {
	t.Helper()
	dir := t.TempDir()
	mem := retention.NewMemory()
	mem.DiskTotal, mem.DiskBase = 100*retention.GB, 30*retention.GB
	now := time.Now().UTC()
	for ago := 0; ago < 120; ago++ {
		day := now.AddDate(0, 0, -ago)
		mem.AddIndex(retention.IndexName("signalith", "endpoint", day), retention.GB/10,
			retention.Doc{ID: "a", Source: []byte(`{"user":"bob"}`)})
		mem.AddIndex(retention.IndexName("signalith", "authentication", day), retention.GB/20)
	}
	m := &retention.Manager{
		Cluster: mem, Prefix: "signalith", Config: cfg,
		Store:       retention.NewStore(filepath.Join(dir, "retention.yaml")),
		Archive:     &retention.Archive{Dir: filepath.Join(dir, "archive")},
		HistoryFile: filepath.Join(dir, "retention_history.json"),
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Retention = m })
	// A run a request started may still be writing its history to dir when
	// the test ends: wait for it before dir is removed (cleanups run last
	// first, so this one runs before TempDir's).
	t.Cleanup(m.Wait)
	return m, mem, func(method, path, body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, method, path, body, true)
	}
}

// idle waits for a background run to finish.
func idle(t *testing.T, call func(method, path, body string) (int, map[string]any)) map[string]any {
	t.Helper()
	// A run archives and deletes about a hundred days; slow CI runners
	// (Windows especially) can take well over five seconds.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		_, out := call("GET", "/api/retention", "")
		if sch := out["schedule"].(map[string]any); sch["running"] == false {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return nil
}

func category(out map[string]any, id string) map[string]any {
	for _, c := range out["categories"].([]any) {
		if c := c.(map[string]any); c["id"] == id {
			return c
		}
	}
	return nil
}

func TestRetentionAPI(t *testing.T) {
	_, mem, call := newRetentionServer(t, retention.Config{Days: 90, Policies: map[string]retention.Policy{"risk": {KeepDays: 30}}})

	code, out := call("GET", "/api/retention", "")
	if code != 200 {
		t.Fatalf("get = %d %v", code, out)
	}
	ep := category(out, "endpoint")
	if ep["days"] != float64(120) || ep["source"] != "default" || ep["editable"] != true || ep["oldest_day"] == "" ||
		ep["policy"].(map[string]any)["keep_days"] != float64(90) {
		t.Errorf("endpoint = %v", ep)
	}
	if risk := category(out, "risk"); risk["editable"] != false || risk["note"] != "From signalith.yaml" {
		t.Errorf("risk = %v", risk)
	}
	if intel := category(out, "intel"); intel["editable"] != false || intel["source"] != "feeds" {
		t.Errorf("intel = %v", intel)
	}
	if d := out["default"].(map[string]any); d["source"] != "days" || d["editable"] != true {
		t.Errorf("default = %v", d)
	}
	g := out["guard"].(map[string]any)
	if g["enabled"] != true || g["max_disk_percent"] != float64(85) || g["status"].(map[string]any)["state"] != "ok" {
		t.Errorf("guard = %v", g)
	}
	disk := out["disk"].(map[string]any)
	if disk["percent"] == nil || disk["used_bytes"] == nil || disk["total_bytes"] != float64(100*retention.GB) {
		t.Errorf("disk = %v", disk)
	}
	for _, k := range []string{"total_bytes", "archive", "schedule", "pending", "recent", "notes", "unmanaged"} {
		if out[k] == nil {
			t.Errorf("missing %s in %v", k, out)
		}
	}
	// 29 days of each category are past 90 days.
	if p := out["pending"].(map[string]any); p["delete_days"] != float64(58) {
		t.Errorf("pending = %v", p)
	}

	// Preview, then save.
	code, out = call("POST", "/api/retention/preview", `{"category":"endpoint","policy":{"keep_days":30,"archive":true}}`)
	if code != 200 || out["deletes_data"] != true {
		t.Fatalf("preview = %d %v", code, out)
	}
	if s := out["summary"].(map[string]any); s["delete_days"] != float64(89) || s["archive_days"] != float64(89) {
		t.Errorf("preview summary = %v", s)
	}
	if steps := out["steps"].([]any); len(steps) != 89 || steps[0].(map[string]any)["action"] != "archive" {
		t.Errorf("preview steps = %d", len(steps))
	}
	code, out = call("POST", "/api/retention/preview", `{"category":"endpoint","policy":{"keep_days":3,"compact_after_days":5}}`)
	if code != 400 || out["fields"].([]any)[0] != "compact_after_days" || !strings.HasPrefix(out["error"].(string), "Compact_after_days") {
		t.Errorf("bad preview = %d %v", code, out)
	}
	if code, out := call("POST", "/api/retention/preview", `{"category":"endpoint","policy":{"keepdays":3}}`); code != 400 {
		t.Errorf("typo = %d %v", code, out)
	}

	code, out = call("PUT", "/api/retention/policies/endpoint", `{"keep_days":30,"archive":true}`)
	if code != 200 || out["source"] != "ui" {
		t.Fatalf("put = %d %v", code, out)
	}
	// Saving starts a run, which archives and deletes the old days.
	out = idle(t, call)
	ep = category(out, "endpoint")
	if ep["days"] != float64(31) || ep["source"] != "ui" || ep["policy"].(map[string]any)["archive"] != true {
		t.Errorf("after save: endpoint = %v", ep)
	}
	if last := out["last_run"].(map[string]any); last["trigger"] != "policy_change" || last["by"] != "admin" || last["archived"] != float64(89) {
		t.Errorf("last run = %v", last)
	}
	if recent := out["recent"].([]any); len(recent) < 89 || len(recent) > retention.MaxActions {
		t.Errorf("recent = %d", len(recent))
	}

	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/api/retention/policies/risk", `{"keep_days":10}`},
		{"DELETE", "/api/retention/policies/risk", ``},
	} {
		if code, out := call(tc.method, tc.path, tc.body); code != http.StatusConflict || !strings.Contains(out["error"].(string), "signalith.yaml") {
			t.Errorf("%s %s = %d %v", tc.method, tc.path, code, out)
		}
	}
	if code, _ := call("PUT", "/api/retention/policies/intel", `{"keep_days":10}`); code != 400 {
		t.Errorf("intel = %d", code)
	}
	if code, _ := call("PUT", "/api/retention/policies/nope", `{"keep_days":10}`); code != 404 {
		t.Errorf("unknown = %d", code)
	}
	if code, out := call("PUT", "/api/retention/policies/findings", `{"keep_days":10,"archive":true}`); code != 400 {
		t.Errorf("findings archive = %d %v", code, out)
	}
	idle(t, call)
	if code, out := call("DELETE", "/api/retention/policies/endpoint", ""); code != 200 || out["source"] != "default" {
		t.Errorf("reset = %d %v", code, out)
	}
	idle(t, call)
	if code, out := call("PUT", "/api/retention/default", `{"keep_days":120,"compact_after_days":7}`); code != 200 {
		t.Errorf("default = %d %v", code, out)
	}
	idle(t, call)
	if code, out := call("PUT", "/api/retention/guard", `{"enabled":true,"max_disk_percent":99}`); code != 400 || out["fields"].([]any)[0] != "max_disk_percent" {
		t.Errorf("bad guard = %d %v", code, out)
	}
	if code, out := call("PUT", "/api/retention/guard", `{"enabled":false,"max_disk_percent":80,"min_days":3}`); code != 200 || out["enabled"] != false {
		t.Errorf("guard = %d %v", code, out)
	}
	out = idle(t, call)
	if g := out["guard"].(map[string]any); g["enabled"] != false || g["source"] != "ui" || g["status"].(map[string]any)["state"] != "off" {
		t.Errorf("guard after save = %v", g)
	}
	if d := out["default"].(map[string]any); d["source"] != "ui" || d["policy"].(map[string]any)["compact_after_days"] != float64(7) {
		t.Errorf("default after save = %v", d)
	}

	// Run now.
	if code, out := call("POST", "/api/retention/run", ""); code != 202 || out["started"] != true {
		t.Errorf("run = %d %v", code, out)
	}
	out = idle(t, call)
	if last := out["last_run"].(map[string]any); last["trigger"] != "manual" {
		t.Errorf("last run = %v", last)
	}

	// The archive tab lists the 89 archived days; restore one.
	code, out = call("GET", "/api/retention/archive", "")
	archives := out["archives"].([]any)
	if code != 200 || len(archives) != 89 || out["default_keep_days"] != float64(14) {
		t.Fatalf("archive = %d %v", code, len(archives))
	}
	first := archives[0].(map[string]any)
	if first["category_name"] != "Endpoint" || first["searchable"] != false || first["docs"] != float64(1) || first["sha256"] == "" {
		t.Errorf("archive entry = %v", first)
	}
	id := first["id"].(string)
	if code, out := call("POST", "/api/retention/archive/restore", `{"ids":["nope"]}`); code != 404 {
		t.Errorf("restore unknown = %d %v", code, out)
	}
	if code, out := call("POST", "/api/retention/archive/restore", `{"ids":[]}`); code != 400 {
		t.Errorf("restore nothing = %d %v", code, out)
	}
	code, out = call("POST", "/api/retention/archive/restore", `{"ids":["`+id+`"],"keep_days":3}`)
	if code != 202 || len(out["restores"].([]any)) != 1 {
		t.Fatalf("restore = %d %v", code, out)
	}
	for range 500 {
		_, out = call("GET", "/api/retention/archive", "")
		if r, _ := out["archives"].([]any)[0].(map[string]any)["restore"].(map[string]any); r != nil && r["state"] == "done" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	first = out["archives"].([]any)[0].(map[string]any)
	if first["searchable"] != true || first["restored_until"] == "" || first["restore"].(map[string]any)["restored"] != float64(1) {
		t.Errorf("after restore = %v", first)
	}
	if _, docs, ok := mem.Index(first["index"].(string)); !ok || len(docs) != 1 {
		t.Errorf("restored index has %d docs", len(docs))
	}
	// The restore writes its line in the history file after it shows as
	// done; wait for that, or removing the test's folder can fail.
	idle(t, call)
}

func TestRetentionAPIOff(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/retention", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("no manager = %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/retention", "", false); code != http.StatusUnauthorized {
		t.Errorf("signed out = %d", code)
	}
}

func TestRetentionRefusesCrossSiteChanges(t *testing.T) {
	m, _, _ := newRetentionServer(t, retention.Config{Days: 90})
	ts, _ := newTestServerWith(t, func(s *Server) { s.Retention = m })
	req, _ := http.NewRequest("PUT", ts.URL+"/api/retention/default", strings.NewReader(`{"keep_days":1}`))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site = %d", resp.StatusCode)
	}
	if s, _ := m.Settings(); s.DefaultSource != retention.SourceDays {
		t.Error("a cross-site request changed the default")
	}
}

func TestRetentionAPIReadOnlyServer(t *testing.T) {
	m, mem, call := newRetentionServer(t, retention.Config{Days: 30})
	m.ReadOnly = true
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/api/retention/policies/endpoint", `{"keep_days":5}`},
		{"DELETE", "/api/retention/policies/endpoint", ``},
		{"PUT", "/api/retention/default", `{"keep_days":5}`},
		{"PUT", "/api/retention/guard", `{"enabled":false}`},
		{"POST", "/api/retention/run", ``},
		{"POST", "/api/retention/archive/restore", `{"ids":["x"]}`},
	} {
		code, out := call(tc.method, tc.path, tc.body)
		if code != http.StatusConflict || !strings.Contains(out["error"].(string), "detections.scheduler is off here") {
			t.Errorf("%s %s = %d %v", tc.method, tc.path, code, out)
		}
	}
	_, out := call("GET", "/api/retention", "")
	if sch := out["schedule"].(map[string]any); sch["read_only"] != true {
		t.Errorf("schedule = %v", sch)
	}
	if ep := category(out, "endpoint"); ep["editable"] != false {
		t.Errorf("endpoint = %v", ep)
	}
	// Previews still work: they change nothing.
	if code, _ := call("POST", "/api/retention/preview", `{"default":{"keep_days":10}}`); code != 200 {
		t.Errorf("preview = %d", code)
	}
	if n := len(mem.Calls); n != 0 {
		t.Errorf("a read-only server changed OpenSearch: %v", mem.Calls)
	}
}

func TestRetentionAPIRestoreCheckAndOpenSearchDown(t *testing.T) {
	_, mem, call := newRetentionServer(t, retention.Config{Days: 90})
	if code, out := call("PUT", "/api/retention/policies/endpoint", `{"keep_days":30,"archive":true}`); code != 200 || out["run_started"] != true || out["run_queued"] != false {
		t.Fatalf("put = %d %v", code, out)
	}
	idle(t, call)
	_, out := call("GET", "/api/retention/archive", "")
	var ids []string
	for _, a := range out["archives"].([]any)[:40] {
		ids = append(ids, `"`+a.(map[string]any)["id"].(string)+`"`)
	}
	body := `{"ids":[` + strings.Join(ids, ",") + `]}`
	// 40 restored days of 0.1 GB on a disk that is 33% full: fine.
	code, out := call("POST", "/api/retention/archive/preview", body)
	if code != 200 || out["needs_confirm"] != false || out["days"] != float64(40) || out["bytes"] == float64(0) {
		t.Fatalf("check = %d %v", code, out)
	}
	// Nearly full: the restore must be confirmed.
	mem.DiskBase = 81 * retention.GB
	code, out = call("POST", "/api/retention/archive/restore", body)
	if code != http.StatusConflict || out["check"] == nil || out["check"].(map[string]any)["needs_confirm"] != true {
		t.Fatalf("unconfirmed = %d %v", code, out)
	}
	if code, out := call("POST", "/api/retention/archive/restore", strings.TrimSuffix(body, "}")+`,"confirm":true}`); code != 202 {
		t.Errorf("confirmed = %d %v", code, out)
	}
	time.Sleep(20 * time.Millisecond)
	idle(t, call)
	// OpenSearch down: previews say so with 503, saving still works.
	mem.Fail["indices"] = errors.New("connection refused")
	code, out = call("POST", "/api/retention/preview", `{"default":{"keep_days":10}}`)
	if code != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), "OpenSearch") {
		t.Errorf("preview with OpenSearch down = %d %v", code, out)
	}
}
