package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

func TestDetectionsCRUD(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "GET", "/api/detections", "", true)
	if code != 200 || len(body["detections"].([]any)) < 15 {
		t.Fatalf("list = %d %v", code, body)
	}

	code, body = do(t, ts, "GET", "/api/detections/auth-brute-force", "", true)
	if code != 200 || body["source"] != "builtin" || body["enabled"] != true {
		t.Fatalf("get = %d %v", code, body)
	}

	// Disabling a built-in saves an override.
	code, body = do(t, ts, "PUT", "/api/detections/auth-brute-force",
		`{"title":"Brute force from $src$","query":"datamodel=Authentication action=failure | stats count by src | where count > 20","severity":"high","enabled":false,"mitre":["T1110"]}`, true)
	if code != 200 || body["source"] != "override" || body["enabled"] != false || body["schedule"] != "5m" {
		t.Fatalf("put = %d %v", code, body)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/auth-brute-force", "", true)
	if code != 200 || body["reverted"] == nil {
		t.Fatalf("revert = %d %v", code, body)
	}

	// Validation returns every problem.
	code, body = do(t, ts, "POST", "/api/detections", `{"id":"x","query":"| bad","severity":"nope"}`, true)
	if code != 400 || len(body["problems"].([]any)) < 3 {
		t.Fatalf("invalid create = %d %v", code, body)
	}
	code, _ = do(t, ts, "POST", "/api/detections", `{"id":"my-rule","title":"Mine","query":"user=bob","mitre":["T1078"]}`, true)
	if code != 201 {
		t.Fatalf("create = %d", code)
	}
	code, _ = do(t, ts, "POST", "/api/detections", `{"id":"my-rule","title":"Mine","query":"user=bob"}`, true)
	if code != 409 {
		t.Errorf("duplicate create = %d", code)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/my-rule", "", true)
	if code != 200 || body["deleted"] != true {
		t.Errorf("delete = %d %v", code, body)
	}
	code, _ = do(t, ts, "GET", "/api/detections/my-rule", "", true)
	if code != 404 {
		t.Errorf("get deleted = %d", code)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/detections/auth-brute-force/yaml", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	y, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(y), "id: auth-brute-force") || !strings.Contains(resp.Header.Get("Content-Type"), "yaml") {
		t.Errorf("yaml export = %s", y)
	}
}

func TestDetectionTestAndRunRaiseFindings(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/detections/test",
		`{"title":"Failures from $src$","query":"datamodel=Authentication action=failure | stats count by src | where count >= 10","lookback":"1h"}`, true)
	if code != 200 {
		t.Fatalf("test = %d %v", code, body)
	}
	titles := body["titles"].([]any)
	if len(titles) != 1 || titles[0] != "Failures from 10.0.0.9" {
		t.Errorf("titles = %v", titles)
	}
	code, _ = do(t, ts, "POST", "/api/detections/test", `{"query":"user=x earliest=-1h"}`, true)
	if code != 400 {
		t.Errorf("earliest in test query = %d", code)
	}

	code, body = do(t, ts, "POST", "/api/detections/auth-brute-force/run", "", true)
	if code != 200 {
		t.Fatalf("run = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/findings?status=new&since=-1h", "", true)
	if code != 200 {
		t.Fatalf("findings = %d %v", code, body)
	}
	list := body["findings"].([]any)
	if len(list) == 0 {
		t.Fatal("run raised no findings")
	}
	id := list[0].(map[string]any)["id"].(string)

	code, body = do(t, ts, "PATCH", "/api/findings/"+id, `{"status":"in_progress","owner":"sam","comment":"looking"}`, true)
	if code != 200 || body["status"] != "in_progress" || len(body["history"].([]any)) != 2 {
		t.Fatalf("patch = %d %v", code, body)
	}
	if code, _ := do(t, ts, "PATCH", "/api/findings/"+id, `{"status":"done"}`, true); code != 400 {
		t.Errorf("bad status = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/findings/"+id, "", true)
	if code != 200 || body["detection"] == nil || body["finding"].(map[string]any)["comments"] == nil {
		t.Errorf("get = %d %v", code, body)
	}
	code, body = do(t, ts, "POST", "/api/findings/bulk", fmt.Sprintf(`{"ids":[%q,"missing"],"update":{"status":"closed","disposition":"false_positive"}}`, id), true)
	if code != 200 || body["updated"] != float64(1) || body["failed"].(map[string]any)["missing"] == nil {
		t.Errorf("bulk = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/findings/summary", "", true)
	if code != 200 || body["by_status"].(map[string]any)["closed"] != float64(1) {
		t.Errorf("summary = %d %v", code, body)
	}
	if code, _ := do(t, ts, "GET", "/api/findings/nope", "", true); code != 404 {
		t.Errorf("missing finding = %d", code)
	}
}

func TestManualFindingAndCoverage(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/findings", `{"title":"Odd logon","severity":"low","query":"user=bob","result":{"user":"bob","count":3}}`, true)
	if code != 201 || body["detection_id"] != "manual" || body["entities"].(map[string]any)["user"] != "bob" {
		t.Fatalf("create = %d %v", code, body)
	}
	if code, _ := do(t, ts, "POST", "/api/findings", `{"title":""}`, true); code != 400 {
		t.Errorf("empty title = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/coverage", "", true)
	if code != 200 {
		t.Fatal(code)
	}
	sum := body["summary"].(map[string]any)
	if sum["enabled"].(float64) < 10 || len(body["tactics"].([]any)) < 12 {
		t.Errorf("coverage summary = %v", sum)
	}
}

func TestSigmaEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)
	rule := "title: Whoami\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\\\whoami.exe'\n  condition: sel\nlevel: low\ntags: [attack.t1033]\n"
	req, _ := http.NewRequest("POST", ts.URL+"/api/detections/sigma", strings.NewReader(rule))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Content-Type", "application/yaml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `process_name=whoami.exe`) {
		t.Errorf("sigma = %d %s", resp.StatusCode, b)
	}
	code, body := do(t, ts, "POST", "/api/detections/sigma", "title: x\n", true)
	if code != 400 || !strings.Contains(body["error"].(string), "detection") {
		t.Errorf("bad sigma = %d %v", code, body)
	}
}

// TestHealthWarnsOfLateDetections: a detection that has been due for
// longer than its schedule interval (every worker busy) is named on the
// Health page, and its run state says how far behind it is.
func TestHealthWarnsOfLateDetections(t *testing.T) {
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv = s })
	_, h := do(t, ts, "GET", "/api/health", "", true)
	if strings.Contains(fmt.Sprint(h["warnings"]), "behind schedule") {
		t.Fatalf("warned before anything ran: %v", h["warnings"])
	}
	// First seen an hour ago, due every five minutes, and not run since.
	srv.Scheduler.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	srv.Scheduler.RunDue(context.Background())
	_, h = do(t, ts, "GET", "/api/health", "", true)
	brute, _ := srv.Detections.Get("auth-brute-force")
	if w := fmt.Sprint(h["warnings"]); !strings.Contains(w, "Detections are running behind schedule. ") || !strings.Contains(w, "‘"+brute.BaseTitle()+"’") {
		t.Errorf("warnings = %v", w)
	}
	_, got := do(t, ts, "GET", "/api/detections/auth-brute-force", "", true)
	if st, _ := got["state"].(map[string]any); st == nil || st["next_run"] == nil {
		t.Errorf("state = %v", got["state"])
	}

	// Missed runs older than the catch-up limit are skipped.
	srv.Scheduler.Now = time.Now
	srv.Scheduler.SetCatchUp(10 * time.Minute)
	srv.Scheduler.RunDue(context.Background())
	_, h = do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(h["warnings"]); !strings.Contains(w, "missed runs of") || !strings.Contains(w, "were skipped") {
		t.Errorf("warnings after skipped runs = %v", w)
	}

	// A lone server that does not run the scheduler cannot tell.
	srv.Config.Detections.Scheduler = false
	_, h = do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(h["warnings"]); strings.Contains(w, "behind schedule") || strings.Contains(w, "skipped") {
		t.Errorf("scheduler off, warnings = %v", w)
	}
	// With several servers the run state is shared: one that does not
	// run the detections warns as the one that does.
	srv.Cluster = &fakeCluster{holder: "siem-a"}
	_, h = do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(h["warnings"]); !strings.Contains(w, "behind schedule") || !strings.Contains(w, "were skipped") {
		t.Errorf("another server runs the detections, warnings = %v", w)
	}
}

func TestContentPacks(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "GET", "/api/detections/packs", "", true)
	packs, _ := body["packs"].([]any)
	if code != 200 || len(packs) != 2 {
		t.Fatalf("packs = %d %v", code, body)
	}
	p := packs[0].(map[string]any)
	if p["name"] != "sigmahq" || p["license"] != "DRL-1.1" || p["rules"].(float64) < 500 || p["enabled"].(float64) != 0 {
		t.Fatalf("pack = %v", p)
	}
	if p := packs[1].(map[string]any); p["name"] != "splunk" || p["license"] != "Apache-2.0" || p["format"] != "splunk" || p["rules"].(float64) < 100 {
		t.Fatalf("splunk pack = %v", p)
	}

	// Turn two pack rules and a built-in on or off at once; pack rules keep
	// coming from the binary, so only the choice is saved.
	code, body = do(t, ts, "GET", "/api/detections", "", true)
	var ids []string
	for _, x := range body["detections"].([]any) {
		d := x.(map[string]any)
		if d["source"] == "pack" && len(ids) < 2 {
			ids = append(ids, d["id"].(string))
		}
	}
	code, body = do(t, ts, "POST", "/api/detections/enable", fmt.Sprintf(`{"ids":["%s","%s"],"enabled":true}`, ids[0], ids[1]), true)
	if code != 200 || body["changed"].(float64) != 2 {
		t.Fatalf("enable = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/detections/"+ids[0], "", true)
	if code != 200 || body["enabled"] != true || body["source"] != "pack" || body["origin"] == nil {
		t.Fatalf("enabled pack rule = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/detections/packs", "", true)
	on := 0.0
	for _, x := range body["packs"].([]any) {
		on += x.(map[string]any)["enabled"].(float64)
	}
	if on != 2 {
		t.Errorf("packs after enabling = %v", body["packs"])
	}
	// An unknown ID changes nothing.
	code, _ = do(t, ts, "POST", "/api/detections/enable", fmt.Sprintf(`{"ids":["%s","no-such-rule"],"enabled":false}`, ids[0]), true)
	if code != 404 {
		t.Errorf("unknown id = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/detections/"+ids[0], "", true)
	if body["enabled"] != true {
		t.Errorf("a refused request changed %s", ids[0])
	}
	if code, _ = do(t, ts, "POST", "/api/detections/enable", `{"ids":[],"enabled":true}`, true); code != 400 {
		t.Errorf("empty = %d", code)
	}
	// Pack rules cannot be deleted.
	if code, _ = do(t, ts, "DELETE", "/api/detections/"+ids[1], "", true); code != 400 {
		t.Errorf("delete pack rule = %d", code)
	}
}

// The run state is shared: a server that does not run the detections
// shows the last run, skipped runs and "Run now" the other servers
// recorded, and its own "Run now" is recorded with who asked.
func TestDetectionsShowSharedRunState(t *testing.T) {
	shared := detect.NewMemoryRunStore()
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.Scheduler.Runtime, s.Scheduler.NodeID = shared, "siem-b"
	})
	ctx := context.Background()
	lastRun := time.Now().Add(-2 * time.Minute).UTC().Truncate(time.Second)
	from, to := lastRun.Add(-10*time.Hour), lastRun.Add(-6*time.Hour)
	st := detect.DetState{Kind: "detstate", DetectionID: "auth-brute-force", LastRun: lastRun, LastSlot: lastRun,
		NextSlot: lastRun.Add(5 * time.Minute), LastResults: 4, LastDuplicates: 1, Schedule: "5m", Enabled: true, Node: "siem-a", Epoch: 3,
		Skipped: detect.Skipped{From: from, To: to, At: lastRun, Count: 48}}
	if _, err := shared.Create(ctx, "signalith_runtime", "detstate:auth-brute-force", st, false); err != nil {
		t.Fatal(err)
	}
	_, out := do(t, ts, "GET", "/api/detections", "", true)
	if out["runs_on"] != "siem-a" || out["state_error"] != nil {
		t.Errorf("runs_on %v state_error %v", out["runs_on"], out["state_error"])
	}
	var got map[string]any
	for _, d := range out["detections"].([]any) {
		if d.(map[string]any)["id"] == "auth-brute-force" {
			got = d.(map[string]any)["state"].(map[string]any)
		}
	}
	sk, _ := got["skipped"].(map[string]any)
	if got["last_run"] != lastRun.Format(time.RFC3339) || got["node"] != "siem-a" || got["last_duplicates"] != float64(1) ||
		sk == nil || sk["count"] != float64(48) {
		t.Fatalf("state on another server = %v", got)
	}

	code, res := do(t, ts, "POST", "/api/detections/auth-brute-force/run", "", true)
	if code != 200 {
		t.Fatalf("run now = %d %v", code, res)
	}
	_, one := do(t, ts, "GET", "/api/detections/auth-brute-force", "", true)
	state := one["state"].(map[string]any)
	m, _ := state["manual"].(map[string]any)
	if m == nil || m["by"] != "admin" || m["node"] != "siem-b" || m["results"] != res["results"] {
		t.Errorf("manual = %v (run %v)", state["manual"], res)
	}
	// Run now leaves the schedule's state alone.
	if state["last_run"] != lastRun.Format(time.RFC3339) || state["last_slot"] != lastRun.Format(time.RFC3339) {
		t.Errorf("state after Run now = %v", state)
	}
}
