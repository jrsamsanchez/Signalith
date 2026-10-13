package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
	// Ran an hour ago, due every five minutes, and not run since.
	srv.Scheduler.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	d, err := srv.Detections.Get("auth-brute-force")
	if err != nil {
		t.Fatal(err)
	}
	srv.Scheduler.Run(context.Background(), d)
	_, h = do(t, ts, "GET", "/api/health", "", true)
	if w := fmt.Sprint(h["warnings"]); !strings.Contains(w, "Detections are running behind schedule. auth-brute-force waited") {
		t.Errorf("warnings = %v", w)
	}
	_, got := do(t, ts, "GET", "/api/detections/auth-brute-force", "", true)
	if st, _ := got["state"].(map[string]any); st == nil || st["next_run"] == nil {
		t.Errorf("state = %v", got["state"])
	}

	// A server that does not run the scheduler cannot tell.
	srv.Config.Detections.Scheduler = false
	_, h = do(t, ts, "GET", "/api/health", "", true)
	if strings.Contains(fmt.Sprint(h["warnings"]), "behind schedule") {
		t.Errorf("scheduler off, warnings = %v", h["warnings"])
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
