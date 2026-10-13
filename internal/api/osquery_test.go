package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

const enrollBody = `{"enroll_secret":%q,"host_identifier":"4C4C4544-0000","host_details":{
	"os_version":{"name":"Ubuntu","version":"24.04","platform":"ubuntu","platform_like":"debian"},
	"osquery_info":{"version":"5.19.0"},
	"system_info":{"hostname":"web1","cpu_brand":"Xeon\u0000\u0000","physical_memory":"8589934592","uuid":"4C4C4544-0000"}}}`

func osqueryServer(t *testing.T) (*endpoint.Store, func(method, path, body string, auth bool) (int, map[string]any), *fakeOS) {
	t.Helper()
	st := endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
	ts, fos := newTestServerWith(t, func(s *Server) { s.Endpoints = st })
	return st, func(method, path, body string, auth bool) (int, map[string]any) {
		return do(t, ts, method, path, body, auth)
	}, fos
}

func TestOsqueryEnrollConfigLog(t *testing.T) {
	_, call, fos := osqueryServer(t)
	if code, body := call("POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "wrong"), false); code != 401 || body["node_invalid"] != true {
		t.Fatalf("bad secret = %d %v", code, body)
	}
	code, body := call("POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false)
	key, _ := body["node_key"].(string)
	if code != 200 || len(key) != 64 {
		t.Fatalf("enroll = %d %v", code, body)
	}
	if code, body := call("POST", "/api/osquery/config", `{"node_key":"`+strings.Repeat("0", 64)+`"}`, false); code != 401 || body["node_invalid"] != true {
		t.Fatalf("unknown key = %d %v", code, body)
	}
	code, body = call("POST", "/api/osquery/config", `{"node_key":"`+key+`"}`, false)
	sched, _ := body["schedule"].(map[string]any)
	if code != 200 || sched["signalith_software"] == nil || sched["signalith_fim"] == nil {
		t.Fatalf("config = %d %v", code, body)
	}

	logBody := `{"node_key":"` + key + `","log_type":"result","data":[{"name":"signalith_software","unixTime":` +
		fmt.Sprint(nowUnix()) + `,"diffResults":{"added":[{"name":"openssl","version":"3.0.2"}],"removed":[]}}]}`
	if code, body := call("POST", "/api/osquery/log", logBody, false); code != 200 {
		t.Fatalf("log = %d %v", code, body)
	}
	found := false
	for _, d := range fos.bulk {
		b, _ := json.Marshal(d)
		if strings.Contains(string(b), `"openssl"`) && strings.Contains(string(b), "Inventory") {
			found = true
		}
	}
	if !found {
		t.Fatalf("software event not stored: %+v", fos.bulk)
	}

	code, body = call("GET", "/api/endpoints", "", true)
	eps, _ := body["endpoints"].([]any)
	if code != 200 || len(eps) != 1 {
		t.Fatalf("endpoints = %d %v", code, body)
	}
	ep := eps[0].(map[string]any)
	if ep["hostname"] != "web1" || ep["platform"] != "linux" || ep["cpu"] != "Xeon" || ep["online"] != true {
		t.Errorf("endpoint = %v", ep)
	}
	if code, _ := call("GET", "/api/endpoints", "", false); code != 401 {
		t.Errorf("unauthenticated list = %d", code)
	}
}

func TestOsqueryLiveQueryAndRemove(t *testing.T) {
	_, call, _ := osqueryServer(t)
	_, body := call("POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false)
	key := body["node_key"].(string)
	_, body = call("GET", "/api/endpoints", "", true)
	id := body["endpoints"].([]any)[0].(map[string]any)["id"].(string)

	if code, _ := call("POST", "/api/endpoints/queries", `{"sql":"","targets":["`+id+`"]}`, true); code != 400 {
		t.Errorf("empty SQL = %d", code)
	}
	code, body := call("POST", "/api/endpoints/queries", `{"sql":"SELECT 1 AS one;","all":true}`, true)
	qid, _ := body["id"].(string)
	if code != 200 || qid == "" {
		t.Fatalf("new query = %d %v", code, body)
	}
	_, body = call("POST", "/api/osquery/distributed/read", `{"node_key":"`+key+`"}`, false)
	if qs, _ := body["queries"].(map[string]any); qs[qid] != "SELECT 1 AS one;" {
		t.Fatalf("read = %v", body)
	}
	_, body = call("POST", "/api/osquery/distributed/read", `{"node_key":"`+key+`"}`, false)
	if qs, _ := body["queries"].(map[string]any); len(qs) != 0 {
		t.Fatalf("query sent twice: %v", body)
	}
	if code, _ := call("POST", "/api/osquery/distributed/write", `{"node_key":"`+key+`","queries":{"`+qid+`":[{"one":"1"}]},"statuses":{"`+qid+`":0}}`, false); code != 200 {
		t.Fatalf("write = %d", code)
	}
	_, body = call("GET", "/api/endpoints/queries/"+qid, "", true)
	res, _ := body["results"].([]any)
	if len(res) != 1 || res[0].(map[string]any)["state"] != "done" {
		t.Fatalf("results = %v", body)
	}

	// Settings: a save from a stale version is refused.
	_, body = call("GET", "/api/endpoints/settings", "", true)
	set, _ := json.Marshal(body["settings"])
	ver := body["version"].(string)
	if code, body := call("PUT", "/api/endpoints/settings", `{"settings":`+string(set)+`,"version":"`+ver+`"}`, true); code != 200 {
		t.Fatalf("save settings = %d %v", code, body)
	}
	if code, _ := call("PUT", "/api/endpoints/settings", `{"settings":`+string(set)+`,"version":"`+ver+`"}`, true); code != 409 {
		t.Errorf("stale save = %d", code)
	}

	// Removing with block refuses the host's next enrollment.
	if code, body := call("DELETE", "/api/endpoints/"+id+"?block=true", "", true); code != 200 || body["blocked"] != true {
		t.Fatalf("remove = %d %v", code, body)
	}
	if code, body := call("POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false); code != 403 || body["node_invalid"] != true {
		t.Fatalf("blocked enroll = %d %v", code, body)
	}
	_, body = call("GET", "/api/endpoints/blocked", "", true)
	if bl, _ := body["blocked"].([]any); len(bl) != 1 {
		t.Fatalf("blocked = %v", body)
	}
	if code, _ := call("DELETE", "/api/endpoints/blocked/4C4C4544-0000", "", true); code != 200 {
		t.Fatalf("unblock = %d", code)
	}
	if code, _ := call("POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false); code != 200 {
		t.Fatalf("enroll after unblock = %d", code)
	}
}

func TestOsqueryWithoutEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, "tok-0123456789abcdef"), false); code != 503 {
		t.Errorf("enroll with no store = %d", code)
	}
}

func nowUnix() int64 { return time.Now().Unix() }
