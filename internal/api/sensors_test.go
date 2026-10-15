package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sensortune"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// flakyDocs fails reads while down is set.
type flakyDocs struct {
	sensortune.Docs
	down bool
}

func (f *flakyDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if f.down {
		return nil, store.Version{}, false, errors.New("opensearch is down")
	}
	return f.Docs.Get(ctx, index, id)
}

// newTuningServer is newSensorServer with a tuning store and the log
// kept.
func newTuningServer(t *testing.T) (*httptest.Server, *Server, *flakyDocs, *syncBuffer) {
	t.Helper()
	ts, srv := newSensorServer(t)
	docs := &flakyDocs{Docs: endpoint.NewMemoryDocs()}
	logs := &syncBuffer{}
	srv.Log = slog.New(slog.NewTextHandler(logs, nil))
	srv.SensorTuning = sensortune.NewStore(docs, "st")
	return ts, srv, docs, logs
}

func putTuning(t *testing.T, ts *httptest.Server, user, pass string, tuning map[string]string, version string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"tuning": tuning, "version": version})
	code, out, _ := call(t, ts, "PUT", "/api/sensors/tuning", string(b), user, pass, nil)
	return code, out
}

// Every route a sensor calls takes only an active sensor token.
func TestSensorRoutesTakeOnlySensorTokens(t *testing.T) {
	ts, _, _, _ := newTuningServer(t)
	_, sensor := makeToken(t, ts, "sensor ok", "sensor")
	_, linux := makeToken(t, ts, "linux agents", "linux")
	_, osq := makeToken(t, ts, "osquery hosts", "osquery")
	revokedID, revoked := makeToken(t, ts, "sensor gone", "sensor")
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+revokedID+"/revoke", "", "admin", adminPass, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	for _, path := range []string{"/api/sensor/config?server=https://siem.example.com:8443", "/api/sensor/seen", "/api/sensor/tuning"} {
		for _, c := range []struct {
			name, token string
			code        int
		}{
			{"none", "", 401}, {"garbage", "sgl_" + strings.Repeat("b", 52), 401}, {"not a token", "hello", 401}, {"revoked", revoked, 401},
			{"shared", "tok-0123456789abcdef", 403}, {"linux", linux, 403}, {"osquery", osq, 403}, {"sensor", sensor, 200},
		} {
			code, _, body := sensorGet(t, ts, path, c.token)
			if code != c.code {
				t.Errorf("%s with %s: %d %s", path, c.name, code, body)
			}
			if c.code != 200 && (strings.Contains(body, "[disable]") || strings.Contains(body, "Tag ")) {
				t.Errorf("%s with %s: refused but answered %s", path, c.name, body)
			}
		}
	}
	// A browser session is no sensor token either.
	if code, _, _ := call(t, ts, "GET", "/api/sensor/tuning", "", "admin", adminPass, nil); code != 401 {
		t.Errorf("admin session on the sensor route: %d", code)
	}
}

// A sensor token cannot enroll osquery hosts.
func TestOsqueryEnrollRefusesSensorToken(t *testing.T) {
	ts, srv := newSensorServer(t)
	srv.Endpoints = endpoint.NewStore(endpoint.NewMemoryDocs(), "st")
	_, sensor := makeToken(t, ts, "nsm token", "sensor")
	_, osq := makeToken(t, ts, "osquery hosts", "osquery")
	code, body := do(t, ts, "POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, sensor), false)
	if code != 401 || body["node_invalid"] != true || !strings.Contains(fmt.Sprint(body["error"]), "network sensor's token") {
		t.Errorf("sensor token: %d %v", code, body)
	}
	if id, ok := srv.EnrollToken(sensor); ok || id != "" {
		t.Error("EnrollToken took a sensor token")
	}
	if code, body := do(t, ts, "POST", "/api/osquery/enroll", fmt.Sprintf(enrollBody, osq), false); code != 200 || body["node_key"] == nil {
		t.Errorf("osquery token: %d %v", code, body)
	}
}

func TestSensorTuningRoutes(t *testing.T) {
	ts, _, docs, logs := newTuningServer(t)
	_, sensor := makeToken(t, ts, "nsm token", "sensor")

	// Admins only.
	for _, u := range []string{"vera", "andy"} {
		for _, r := range []struct{ method, path, body string }{{"GET", "/api/sensors", ""}, {"GET", "/api/sensors/tuning", ""}, {"PUT", "/api/sensors/tuning", `{"tuning":{},"version":"0.0"}`}} {
			if code, _, _ := call(t, ts, r.method, r.path, r.body, u, "role-password", nil); code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d", u, r.method, r.path, code)
			}
		}
	}

	// Nothing saved yet: an empty tuning, which the sensor gets too.
	code, out, raw := call(t, ts, "GET", "/api/sensors/tuning", "", "admin", adminPass, nil)
	if code != 200 || out["saved"] != false || out["version"] != "0.0" {
		t.Fatalf("first read: %d %s", code, raw)
	}
	code, h, body := sensorGet(t, ts, "/api/sensor/tuning", sensor)
	if code != 200 || body != string((sensortune.Tuning{}).Bundle()) || h.Get("ETag") != `"`+(sensortune.Tuning{}).Hash()+`"` ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/plain") || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("empty bundle: %d %v %q", code, h, body)
	}

	// A refused line: its field and line, nothing saved.
	code, out = putTuning(t, ts, "admin", adminPass, map[string]string{"disable": "2014520\nrm -rf /"}, "0.0")
	if code != 400 || out["field"] != "disable" || out["line"] != 2.0 || !strings.Contains(fmt.Sprint(out["error"]), "Rules to turn off, line 2") {
		t.Errorf("bad line: %d %v", code, out)
	}
	if code, out := putTuning(t, ts, "admin", adminPass, map[string]string{"shell": "x"}, "0.0"); code != 400 {
		t.Errorf("unknown field: %d %v", code, out)
	}

	// Saved, with a warning for a SID outside the local range.
	want := map[string]string{"disable": "2014520\r\n", "threshold": "suppress gen_id 1, sig_id 2013028, track by_src, ip 10.0.0.5",
		"local": "alert tcp any any -> $HOME_NET 23 (msg:\"Telnet\"; sid:42; rev:1;)"}
	code, out = putTuning(t, ts, "admin", adminPass, want, "0.0")
	if code != 200 || out["saved"] != true || out["updated_by"] != "admin" || out["version"] == "0.0" {
		t.Fatalf("save: %d %v", code, out)
	}
	if w, _ := out["warnings"].([]any); len(w) != 1 || !strings.Contains(fmt.Sprint(w[0]), "sid 42") {
		t.Errorf("warnings: %v", out["warnings"])
	}
	saved := sensortune.Tuning{Disable: "2014520", Threshold: want["threshold"], Local: want["local"]}
	if out["hash"] != saved.Hash()[:12] {
		t.Errorf("hash %v", out["hash"])
	}
	if l := logs.String(); !strings.Contains(l, `msg="sensor rule tuning saved"`) || !strings.Contains(l, "by=admin") || !strings.Contains(l, "disabled=1") || !strings.Contains(l, "rules=1") {
		t.Errorf("audit: %s", l)
	}
	version := out["version"].(string)

	// Someone saving from the old version is refused.
	if code, out := putTuning(t, ts, "admin", adminPass, map[string]string{"disable": "1"}, "0.0"); code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "someone else saved") {
		t.Errorf("stale save: %d %v", code, out)
	}

	// The sensor gets it, then 304 with its ETag.
	code, h, body = sensorGet(t, ts, "/api/sensor/tuning", sensor)
	etag := h.Get("ETag")
	if code != 200 || body != string(saved.Bundle()) || etag != `"`+saved.Hash()+`"` {
		t.Fatalf("bundle: %d %v\n%s", code, h, body)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/sensor/tuning", nil)
	req.Header.Set("Authorization", "Bearer "+sensor)
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", resp.StatusCode)
	}

	// OpenSearch down with nothing read yet: 503, never an empty bundle.
	ts2, srv2, docs2, _ := newTuningServer(t)
	_, sensor2 := makeToken(t, ts2, "nsm token", "sensor")
	docs2.down = true
	if code, h, body := sensorGet(t, ts2, "/api/sensor/tuning", sensor2); code != 503 || h.Get("Retry-After") == "" || strings.Contains(body, "[disable]") {
		t.Errorf("store down: %d %v %s", code, h, body)
	}
	_ = srv2
	// Down after a read: the last copy is served.
	docs.down = true
	if code, _, body := sensorGet(t, ts, "/api/sensor/tuning", sensor); code != 200 || body != string(saved.Bundle()) {
		t.Errorf("cached: %d %s", code, body)
	}
	if code, _ := putTuning(t, ts, "admin", adminPass, map[string]string{"disable": "1"}, version); code != 502 {
		t.Errorf("save while down: %d", code)
	}
}

// statusLine is a sensor's status line, as status.sh writes it.
func statusLine(at time.Time, extra string) string {
	line := `{"kind":"signalith-sensor-status","v":1,"time":"` + at.UTC().Format(time.RFC3339) + `","host":"nsm-01","role":"sensor",` +
		`"zeek":{"version":"8.0.4","running":true},"suricata":{"version":"8.0.1","running":true},` +
		`"rules":{"updated":"` + at.Add(-2*time.Hour).UTC().Format(time.RFC3339) + `","count":48211,"update":"ok"},` +
		`"interface":{"name":"eth1","link":"up","drop_percent":0.2},"disk":{"free_percent":60},"time_synced":true` + extra + `}`
	rec, _ := json.Marshal([]map[string]any{{"log": line}})
	return string(rec)
}

func TestSensorsList(t *testing.T) {
	ts, _, _, _ := newTuningServer(t)
	_, sensor := makeToken(t, ts, "nsm-01 token", "sensor")
	_, unused := makeToken(t, ts, "spare", "sensor")
	_ = unused
	makeToken(t, ts, "linux", "linux")
	hdr := map[string]string{"X-Signalith-Tag": "sensor.status", "X-Signalith-Agent": "nsm-01"}
	now := time.Now()
	if code, body := agentSend(t, ts.URL, "/api/ingest", sensor, statusLine(now, `,"warnings":[]`), hdr); code != 200 {
		t.Fatalf("send: %d %s", code, body)
	}
	_, out, raw := call(t, ts, "GET", "/api/sensors", "", "admin", adminPass, nil)
	var got struct {
		Sensors []sensorRow       `json:"sensors"`
		Summary map[string]int    `json:"summary"`
		Tokens  []json.RawMessage `json:"tokens"`
		Tuning  map[string]any    `json:"tuning"`
	}
	b, _ := json.Marshal(out)
	if err := json.Unmarshal(b, &got); err != nil || len(got.Sensors) != 1 {
		t.Fatalf("sensors: %v %s", err, raw)
	}
	s := got.Sensors[0]
	if s.Name != "nsm-01" || s.State != "healthy" || len(s.Problems) != 0 || s.Status == nil || s.TokenName != "nsm-01 token" || s.RulesAgeSec < 7000 {
		t.Errorf("row: %+v", s)
	}
	if got.Summary["total"] != 1 || got.Summary["healthy"] != 1 || got.Tuning["saved"] != false {
		t.Errorf("summary %v tuning %v", got.Summary, got.Tuning)
	}
	// Sensor tokens only, with the sensors that use them.
	if len(got.Tokens) != 2 || !strings.Contains(raw, `"used_by":["nsm-01"]`) || !strings.Contains(raw, `"used_by":[]`) || strings.Contains(raw, `"name":"linux"`) {
		t.Errorf("tokens: %s", raw)
	}
}

func TestSensorChecks(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour).Format(time.RFC3339)
	healthy := func() *ingest.SensorStatus {
		return &ingest.SensorStatus{Zeek: &ingest.SensorTool{Running: true}, Suricata: &ingest.SensorTool{Running: true}, Link: "up",
			RulesUpdated: fresh, RulesUpdate: "ok", TimeSynced: true, TuningHash: "abcdefabcdef", TuningResult: "ok"}
	}
	tn := tuningNow{Hash: "abcdefabcdef", Saved: now.Add(-time.Hour)}
	problems := func(a agentinv.Agent, tn tuningNow, token string) (out []string, tuning sensorCheck) {
		for _, c := range sensorChecks(a, tn, token, now) {
			if !c.OK {
				out = append(out, c.ID)
			}
			if c.ID == "tuning" {
				tuning = c
			}
		}
		return out, tuning
	}
	for name, c := range map[string]struct {
		a      agentinv.Agent
		tn     tuningNow
		token  string
		want   string
		tuning string
	}{
		"healthy":       {agentinv.Agent{LastSeen: now, Sensor: healthy()}, tn, "active", "", "current"},
		"silent":        {agentinv.Agent{LastSeen: now.Add(-20 * time.Minute), Sensor: healthy()}, tn, "active", "silent", "current"},
		"by hand":       {agentinv.Agent{LastSeen: now, Tag: "zeek.conn"}, tn, "active", "no_status", ""},
		"revoked token": {agentinv.Agent{LastSeen: now, Sensor: healthy()}, tn, "revoked", "token", "current"},
		"drops": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus { s := healthy(); s.DropPercent = 7; return s }()},
			tn, "active", "drops", "current"},
		"rules old": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus { s := healthy(); s.RulesUpdated = "2026-10-01T00:00:00Z"; return s }()},
			tn, "active", "rules_old", "current"},
		"rules failed and warnings": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus {
			s := healthy()
			s.RulesUpdate, s.Warnings = "failed", []string{"capture_ip", "no_traffic", "disk_low"}
			s.Zeek.Running = false
			return s
		}()}, tn, "active", "zeek_stopped capture_ip no_traffic disk_low rules_failed", "current"},
		"tuning pending": {agentinv.Agent{LastSeen: now, Sensor: healthy()}, tuningNow{Hash: "111111111111", Saved: now.Add(-5 * time.Minute)}, "active", "", "pending"},
		"tuning stale":   {agentinv.Agent{LastSeen: now, Sensor: healthy()}, tuningNow{Hash: "111111111111", Saved: now.Add(-time.Hour)}, "active", "tuning", "stale"},
		"tuning failed": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus {
			s := healthy()
			s.TuningResult, s.TuningError, s.Warnings = "failed", "rule 3 invalid", []string{"tuning_failed"}
			return s
		}()}, tuningNow{Hash: "111111111111", Saved: now.Add(-5 * time.Minute)}, "active", "tuning", "failed"},
		"old script, tuning saved": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus {
			s := healthy()
			s.TuningResult, s.TuningHash = "", ""
			return s
		}()}, tn, "active", "tuning", "old_script"},
		"old script, nothing saved": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus {
			s := healthy()
			s.TuningResult, s.TuningHash = "", ""
			return s
		}()}, tuningNow{Hash: "e3b0c44298fc"}, "active", "", "none"},
		"never fetched, nothing saved": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus {
			s := healthy()
			s.TuningResult, s.TuningHash = "unreachable", ""
			return s
		}()}, tuningNow{Hash: "e3b0c44298fc"}, "active", "", "none"},
		"tuning unreadable": {agentinv.Agent{LastSeen: now, Sensor: healthy()}, tuningNow{}, "active", "", "unknown"},
		"clock": {agentinv.Agent{LastSeen: now, Sensor: func() *ingest.SensorStatus { s := healthy(); s.TimeSynced = false; s.Link = "down"; return s }()},
			tn, "active", "capture_link time_not_synced", "current"},
	} {
		got, tuning := problems(c.a, c.tn, c.token)
		if strings.Join(got, " ") != c.want || tuning.State != c.tuning {
			t.Errorf("%s: problems %v tuning %+v", name, got, tuning)
		}
	}
}
