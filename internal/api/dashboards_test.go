package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDashboardsAPI(t *testing.T) {
	ts, _ := newTestServer(t)

	code, out := do(t, ts, "GET", "/api/dashboards", "", true)
	list := out["dashboards"].([]any)
	if code != 200 || len(list) != 2 || list[0].(map[string]any)["id"] != "posture" || list[1].(map[string]any)["id"] != "malware" {
		t.Fatalf("empty list = %d %v", code, out)
	}

	// Create without an id: one is made from the title.
	code, out = do(t, ts, "POST", "/api/dashboards", `{"title":"Auth watch","time_range":"7d","panels":[
		{"title":"Failures by source","query":"datamodel=Authentication action=failure | stats count by src"},
		{"title":"Failures","query":"datamodel=Authentication action=failure | stats count","compare":true}]}`, true)
	if code != 201 || out["id"] != "auth-watch" {
		t.Fatalf("create = %d %v", code, out)
	}
	panels := out["panels"].([]any)
	if panels[0].(map[string]any)["viz"] != "bar" || panels[1].(map[string]any)["viz"] != "single" {
		t.Errorf("suggested vizs = %v", panels)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards", `{"id":"auth-watch","title":"Again"}`, true); code != 409 {
		t.Errorf("duplicate = %d", code)
	}
	code, out = do(t, ts, "POST", "/api/dashboards", `{"title":"","panels":[{"title":"x","query":"a=1 | stats avg","viz":"pie"}]}`, true)
	if code != 400 || len(out["problems"].([]any)) != 3 {
		t.Errorf("invalid = %d %v", code, out)
	}

	code, out = do(t, ts, "GET", "/api/dashboards/auth-watch", "", true)
	if code != 200 || out["title"] != "Auth watch" || out["time_range"] != "7d" {
		t.Errorf("get = %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/dashboards/nope", "", true); code != 404 {
		t.Errorf("missing = %d", code)
	}

	// Add a panel from the Search page, then reorder and save.
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/panels", `{"title":"Broken","query":"* | timechart span=soon count"}`, true)
	if code != 200 || len(out["panels"].([]any)) != 3 {
		t.Fatalf("add panel = %d %v", code, out)
	}
	code, out = do(t, ts, "PUT", "/api/dashboards/auth-watch", `{"title":"Auth watch","time_range":"24h","panels":[
		{"title":"Failures","query":"datamodel=Authentication action=failure | stats count","viz":"single","compare":true},
		{"title":"Broken","query":"* | timechart span=soon count","viz":"line"},
		{"title":"Failures by source","query":"datamodel=Authentication action=failure | stats count by src","viz":"bar"}]}`, true)
	if code != 200 || out["panels"].([]any)[0].(map[string]any)["title"] != "Failures" {
		t.Fatalf("put = %d %v", code, out)
	}
	if code, _ := do(t, ts, "PUT", "/api/dashboards/auth-watch", `{"id":"other","title":"x"}`, true); code != 400 {
		t.Errorf("id mismatch = %d", code)
	}

	// Run: the broken panel reports its error and the others still work.
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/run", `{"range":"4h"}`, true)
	if code != 200 || out["range"] != "4h" {
		t.Fatalf("run = %d %v", code, out)
	}
	res := out["panels"].([]any)
	single, broken, bar := res[0].(map[string]any), res[1].(map[string]any), res[2].(map[string]any)
	if single["error"] != nil || fmt.Sprint(single["value"]) != "2" || single["previous"] == nil || single["earliest"] != "-4h" {
		t.Errorf("single = %v", single)
	}
	if !strings.Contains(fmt.Sprint(broken["error"]), "span") || broken["result"] != nil {
		t.Errorf("broken = %v", broken)
	}
	if bar["error"] != nil || len(bar["result"].(map[string]any)["rows"].([]any)) != 2 {
		t.Errorf("bar = %v", bar)
	}
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/run", "", true)
	if code != 200 || out["range"] != "24h" {
		t.Errorf("default range = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards/auth-watch/run", `{"range":"soon"}`, true); code != 400 {
		t.Errorf("bad range = %d", code)
	}

	// Preview an unsaved panel.
	code, out = do(t, ts, "POST", "/api/panels/run", `{"range":"24h","panel":{"title":"p","query":"datamodel=Authentication | stats count by src"}}`, true)
	if code != 200 || out["panel"].(map[string]any)["viz"] != "bar" || out["result"].(map[string]any)["error"] != nil {
		t.Errorf("preview = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/panels/run", `{"panel":{}}`, true); code != 400 {
		t.Errorf("empty preview = %d", code)
	}

	// YAML download.
	req, _ := http.NewRequest("GET", ts.URL+"/api/dashboards/auth-watch/yaml", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "id: auth-watch\ntitle: Auth watch\n") || !strings.Contains(resp.Header.Get("Content-Disposition"), "auth-watch.yaml") {
		t.Errorf("yaml = %s", b)
	}

	code, out = do(t, ts, "GET", "/api/dashboards", "", true)
	if code != 200 || len(out["dashboards"].([]any)) != 3 {
		t.Errorf("list = %v", out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/posture", "", true); code != 400 {
		t.Errorf("delete posture = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/auth-watch", "", true); code != 204 {
		t.Errorf("delete = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/auth-watch", "", true); code != 404 {
		t.Errorf("delete again = %d", code)
	}
}

func TestDashboardsOff(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Dashboards = nil })
	code, out := do(t, ts, "GET", "/api/dashboards", "", true)
	if code != 200 || len(out["dashboards"].([]any)) != 2 || out["error"] == nil {
		t.Errorf("list = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards", `{"title":"x"}`, true); code != 503 {
		t.Errorf("create = %d", code)
	}
	// Posture still works without custom dashboards.
	if code, _ := do(t, ts, "GET", "/api/posture", "", true); code != 200 {
		t.Errorf("posture = %d", code)
	}
}

func TestPostureAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	do(t, ts, "POST", "/api/findings", `{"title":"Manual","severity":"high","result":{"src":"10.0.0.9"}}`, true)
	code, out := do(t, ts, "GET", "/api/posture?range=7d", "", true)
	if code != 200 || out["range"] != "7d" {
		t.Fatalf("posture = %d %v", code, out)
	}
	ind := map[string]any{}
	for _, i := range out["indicators"].([]any) {
		m := i.(map[string]any)
		ind[m["id"].(string)] = m["value"]
	}
	if fmt.Sprint(ind["open_findings"]) != "1" || fmt.Sprint(ind["new_findings"]) != "1" || len(ind) != 6 {
		t.Errorf("indicators = %v", ind)
	}
	h := out["health"].(map[string]any)
	if h["total"].(float64) < 20 || h["enabled"].(float64) < 10 {
		t.Errorf("health = %v", h)
	}
	if out["queries"].(map[string]any)["events_by_datamodel"] == nil {
		t.Errorf("queries = %v", out["queries"])
	}
	for _, bad := range []string{"soon", "1000d"} {
		if code, _ := do(t, ts, "GET", "/api/posture?range="+bad, "", true); code != 400 {
			t.Errorf("range %s = %d", bad, code)
		}
	}
}

// The built-in Malware dashboard is listed, read and run without the
// custom dashboards store, and can never be changed.
func TestBuiltinMalwareDashboardAPI(t *testing.T) {
	for _, storeOn := range []bool{true, false} {
		ts, _ := newTestServerWith(t, func(s *Server) {
			if !storeOn {
				s.Dashboards = nil
			}
		})
		code, out := do(t, ts, "GET", "/api/dashboards", "", true)
		list, _ := out["dashboards"].([]any)
		if code != 200 || len(list) < 2 {
			t.Fatalf("store %v: list = %d %v", storeOn, code, out)
		}
		p, m := list[0].(map[string]any), list[1].(map[string]any)
		if p["id"] != "posture" || p["builtin"] != true || m["id"] != "malware" || m["title"] != "Malware" || m["builtin"] != true || m["panels"] != float64(11) {
			t.Errorf("store %v: list = %v", storeOn, list)
		}

		code, out = do(t, ts, "GET", "/api/dashboards/malware", "", true)
		if code != 200 || out["title"] != "Malware" || out["builtin"] != true || out["time_range"] != "7d" || len(out["panels"].([]any)) != 11 {
			t.Errorf("store %v: get = %d %v", storeOn, code, out)
		}

		req, _ := http.NewRequest("GET", ts.URL+"/api/dashboards/malware/yaml", nil)
		req.SetBasicAuth("admin", "s3cret-pass")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(string(b), "id: malware\ntitle: Malware\n") || strings.Contains(string(b), "builtin") {
			t.Errorf("store %v: yaml = %d %s", storeOn, resp.StatusCode, b)
		}

		code, out = do(t, ts, "POST", "/api/dashboards/malware/run", `{"range":"24h"}`, true)
		if code != 200 || out["range"] != "24h" || len(out["panels"].([]any)) != 11 {
			t.Errorf("store %v: run = %d %v", storeOn, code, out)
		}
		for i, pr := range out["panels"].([]any) {
			if e := pr.(map[string]any)["error"]; e != nil {
				t.Errorf("store %v: panel %d error %v", storeOn, i, e)
			}
		}

		const readOnly = "The Malware dashboard is built in and can\u2019t be changed. Make a copy to change it."
		for _, c := range []struct{ method, path, body string }{
			{"PUT", "/api/dashboards/malware", `{"title":"Mine","panels":[]}`},
			{"DELETE", "/api/dashboards/malware", ""},
			{"POST", "/api/dashboards/malware/panels", `{"title":"x","query":"datamodel=Malware | stats count"}`},
		} {
			code, out := do(t, ts, c.method, c.path, c.body, true)
			if code != 400 || out["error"] != readOnly {
				t.Errorf("store %v: %s %s = %d %v", storeOn, c.method, c.path, code, out)
			}
		}
		if storeOn {
			for _, id := range []string{"malware", "posture"} {
				code, out := do(t, ts, "POST", "/api/dashboards", `{"id":"`+id+`","title":"Mine"}`, true)
				if code != 409 || out["error"] != "That id belongs to a built-in dashboard. Choose another." {
					t.Errorf("create %s = %d %v", id, code, out)
				}
			}
			// A copy of the built-in is an ordinary dashboard with a new id.
			code, out := do(t, ts, "POST", "/api/dashboards", `{"title":"Malware","panels":[{"title":"n","query":"datamodel=Malware | stats count"}]}`, true)
			if code != 201 || out["id"] != "malware-2" || out["builtin"] != nil {
				t.Errorf("copy = %d %v", code, out)
			}
		}
	}
}

// A viewer can open and run the built-in dashboard; changing it still
// needs the analyst role, which is checked before the built-in refusal.
func TestBuiltinDashboardRoles(t *testing.T) {
	ts, _ := newRoleServer(t)
	if code, out := doAs(t, ts, "vera", "role-password", "GET", "/api/dashboards/malware", ""); code != 200 || out["builtin"] != true {
		t.Errorf("viewer get = %d %v", code, out)
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "POST", "/api/dashboards/malware/run", ""); code != 200 {
		t.Errorf("viewer run = %d", code)
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "DELETE", "/api/dashboards/malware", ""); code != 403 {
		t.Errorf("viewer delete = %d", code)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "DELETE", "/api/dashboards/malware", ""); code != 400 {
		t.Errorf("analyst delete = %d", code)
	}
}
