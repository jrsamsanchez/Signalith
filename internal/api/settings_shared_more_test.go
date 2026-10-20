// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// threeServers is siem-b (this server), siem-a, which waits for a restart
// for syslog.udp, and siem-c, offline.
func threeServers() *statusCluster {
	return &statusCluster{st: cluster.Status{Self: "n_b", Servers: []cluster.ServerStatus{
		{NodeID: "n_b", Name: "siem-b", Self: true, State: cluster.StateReady, Detail: &cluster.Heartbeat{NodeID: "n_b", Name: "siem-b"}},
		{NodeID: "n_a", Name: "siem-a", State: cluster.StateReady, Detail: &cluster.Heartbeat{NodeID: "n_a", Name: "siem-a",
			NodeURL: "https://10.0.0.5:8443", RestartNeeded: []string{"syslog.udp"}, SettingsRefused: []string{"search.max_events"},
			Restart: &cluster.RestartStatus{Busy: true}}},
		{NodeID: "n_c", Name: "siem-c", State: cluster.StateOffline},
	}}}
}

// nodeSettings is memSettings with other servers' layers and nodecfg
// documents, and answers to checks and restarts a test sets.
type nodeSettings struct {
	*memSettings
	mu       sync.Mutex
	others   map[string]*config.Shared
	nodecfg  map[string]*shared.NodeCfg
	layerErr map[string]error

	checkRes      *clustercfg.SettingsCheckResult
	checkAnswered bool
	checkErr      error
	checked       []clustercfg.SettingsCheckArgs

	restartErr error
	restarted  [][]string
	sequential []bool
}

func newNodeSettings() *nodeSettings {
	return &nodeSettings{memSettings: newMemSettings(), others: map[string]*config.Shared{}, nodecfg: map[string]*shared.NodeCfg{}, layerErr: map[string]error{}}
}

func (n *nodeSettings) Layer(ctx context.Context, node string) (*config.Shared, *shared.NodeCfg, error) {
	if node == "" {
		return n.memSettings.Layer(ctx, node)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.layerErr[node]; err != nil {
		return nil, nil, err
	}
	sh := n.others[node]
	if sh == nil {
		n.memSettings.mu.Lock()
		sh = n.memSettings.sh.Clone()
		n.memSettings.mu.Unlock()
	}
	return sh.Clone(), n.nodecfg[node], nil
}

func (n *nodeSettings) Check(_ context.Context, _, _ string, args clustercfg.SettingsCheckArgs) (*clustercfg.SettingsCheckResult, bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.checked = append(n.checked, args)
	return n.checkRes, n.checkAnswered, n.checkErr
}

func (n *nodeSettings) Restart(_ context.Context, _ string, servers []string, sequential bool) (*shared.Request, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.restartErr != nil {
		return nil, n.restartErr
	}
	n.restarted = append(n.restarted, servers)
	n.sequential = append(n.sequential, sequential)
	return &shared.Request{ID: "rq-1"}, nil
}

func newNodeSettingsServer(t *testing.T) (*nodeSettings, *Server, func(method, path, body string) (int, map[string]any)) {
	t.Helper()
	ns := newNodeSettings()
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings, s.Cluster = ns, threeServers() })
	return ns, srv, func(method, path, body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, method, path, body, true)
	}
}

// Another server's page shows the shared settings as this server has
// them and that server's own settings from its nodecfg: as changed on a
// page, as refused at its start, and as it runs them from its
// environment.
func TestSharedOtherServerView(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	at := time.Now().Add(-time.Hour)
	ns.others["n_a"] = &config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{},
		Refused: map[string]config.SharedRefusal{"search.max_events": {Reason: "too many for this server", At: at}}}
	ns.nodecfg["n_a"] = &shared.NodeCfg{
		Values: map[string]shared.PageValue{
			"server.listen":   {Value: json.RawMessage(`"0.0.0.0:7443"`), Rev: 4, From: shared.From{By: "bob", Node: "siem-b", At: at}},
			"syslog.udp":      {Value: json.RawMessage(`"0.0.0.0:514"`), Rev: 2, Refused: "the port is taken", RefusedAt: at, From: shared.From{By: "eve"}},
			"server.node_url": {Value: json.RawMessage(`"https://10.0.0.5:8443"`), Rev: 1},
		},
		Running: map[string]shared.RunningValue{
			"syslog.udp":             {Value: json.RawMessage(`"0.0.0.0:5514"`), Source: config.FromFile},
			"server.max_connections": {Value: json.RawMessage(`300`), Source: config.FromEnv, Env: "SIGNALITH_SERVER_MAX_CONNECTIONS"},
		},
		Migrated: []shared.MigratedValue{{Key: "search.max_events", Value: json.RawMessage(`300`), Shared: json.RawMessage(`2000`)}},
	}
	code, view := call("GET", "/api/settings?server=siem-a", "")
	if code != http.StatusOK {
		t.Fatalf("siem-a's page: %d %v", code, view)
	}
	if sv, _ := view["server"].(map[string]any); sv["name"] != "siem-a" || sv["node_url"] != "https://10.0.0.5:8443" {
		t.Errorf("server %v", view["server"])
	}
	boot, _ := view["bootstrap"].(map[string]any)
	if s, _ := boot["elsewhere"].(string); !strings.Contains(s, "on its own Settings page, at https://10.0.0.5:8443.") {
		t.Errorf("bootstrap %v", boot)
	}
	restart, _ := view["restart"].(map[string]any)
	if restart["in_progress"] != true || restart["needed"] != true || restart["available"] != true {
		t.Errorf("restart %v", restart)
	}
	listen := field(t, view, "server.listen")
	if src, _ := listen["source"].(map[string]any); listen["value"] != "0.0.0.0:7443" || src["kind"] != "page" || src["by"] != "bob" || listen["version"] != float64(4) {
		t.Errorf("listen %v", listen)
	}
	udp := field(t, view, "syslog.udp")
	if ref, _ := udp["refused"].(map[string]any); udp["value"] != "0.0.0.0:5514" || ref["reason"] != "the port is taken" || udp["pending"] != true {
		t.Errorf("syslog.udp %v", udp)
	}
	maxc := field(t, view, "server.max_connections")
	if maxc["value"] != float64(300) || maxc["locked"] != true {
		t.Errorf("max connections %v", maxc)
	}
	if u := field(t, view, "server.node_url"); u["value"] != "https://10.0.0.5:8443" || u["version"] != float64(1) {
		t.Errorf("node url %v", u)
	}
	if src, _ := field(t, view, "syslog.tcp")["source"].(map[string]any); src["kind"] != "default" {
		t.Errorf("syslog.tcp source %v", src)
	}
	if kept, _ := field(t, view, "search.max_events")["kept"].(map[string]any); kept["reason"] != "too many for this server" {
		t.Errorf("kept %v", kept)
	}
	for _, sec := range view["sections"].([]any) {
		for _, f := range sec.(map[string]any)["fields"].([]any) {
			if k := f.(map[string]any)["key"]; k == "opensearch.url" {
				t.Errorf("another server's page shows %v", k)
			}
		}
	}
	if m, _ := view["migrated"].([]any); len(m) != 1 {
		t.Errorf("migrated %v", view["migrated"])
	}

	// An offline server cannot be asked to restart, and has no address.
	code, view = call("GET", "/api/settings?server=n_c", "")
	if restart, _ := view["restart"].(map[string]any); code != http.StatusOK || restart["available"] != false || restart["in_progress"] != false {
		t.Errorf("siem-c: %d %v", code, view["restart"])
	}
	if boot, _ := view["bootstrap"].(map[string]any); boot["elsewhere"] != "Change the connection and folder settings of siem-c on its own Settings page." {
		t.Errorf("siem-c bootstrap %v", boot)
	}

	if code, out := call("GET", "/api/settings?server=siem-zz", ""); code != http.StatusNotFound || !strings.Contains(out["error"].(string), `no server "siem-zz"`) {
		t.Errorf("an unknown server: %d %v", code, out)
	}
	ns.layerErr["n_a"] = errors.New("OpenSearch timed out")
	if code, out := call("GET", "/api/settings?server=siem-a", ""); code != http.StatusInternalServerError || !strings.Contains(out["error"].(string), "the settings of siem-a cannot be read now: OpenSearch timed out") {
		t.Errorf("a layer that cannot be read: %d %v", code, out)
	}
}

// This server's page, shared, says which servers wait for a restart for
// a shared setting that needs one.
func TestSharedOwnViewServers(t *testing.T) {
	_, _, call := newNodeSettingsServer(t)
	code, view := call("GET", "/api/settings", "")
	if code != http.StatusOK {
		t.Fatalf("page: %d %v", code, view)
	}
	if sv, _ := view["server"].(map[string]any); sv["name"] != "siem-b" {
		t.Errorf("server %v", view["server"])
	}
	if list, _ := view["servers"].([]any); len(list) != 3 {
		t.Errorf("servers %v", view["servers"])
	}
	if view["writable"] != true || view["etag"] != `"1"` {
		t.Errorf("writable %v etag %v", view["writable"], view["etag"])
	}
}

// A change of another server's own settings is checked on that server
// when it answers: its problems refuse the save, its questions are asked
// first. One that does not answer, cannot be asked or is offline is
// saved with a note saying it checks the change when it starts.
func TestSharedPutOtherServer(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	ns.nodecfg["n_a"] = &shared.NodeCfg{Running: map[string]shared.RunningValue{
		"server.max_connections": {Value: json.RawMessage(`300`), Source: config.FromEnv, Env: "SIGNALITH_SERVER_MAX_CONNECTIONS"}}}

	ns.checkAnswered, ns.checkRes = true, &clustercfg.SettingsCheckResult{Fields: map[string]string{"syslog.udp": "the port is in use on siem-a"}}
	code, out := call("PUT", "/api/settings", `{"server":"siem-a","values":{"syslog.udp":"0.0.0.0:1514"}}`)
	if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields["syslog.udp"] != "the port is in use on siem-a" {
		t.Fatalf("a change siem-a refuses: %d %v", code, out)
	}
	if len(ns.checked) != 1 || string(ns.checked[0].Values["syslog.udp"]) != `"0.0.0.0:1514"` {
		t.Errorf("checked %v", ns.checked)
	}

	ns.checkRes = &clustercfg.SettingsCheckResult{Problems: []string{"siem-a cannot read its certificate"}}
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","values":{"syslog.udp":"0.0.0.0:1514"}}`)
	if msg, _ := out["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "siem-a cannot read its certificate") {
		t.Fatalf("a problem on siem-a: %d %v", code, out)
	}

	ns.checkRes = &clustercfg.SettingsCheckResult{Confirm: []string{"server.listen", "syslog.udp"}}
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","check_only":true,"values":{"server.listen":"0.0.0.0:9443"}}`)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("check only: %d %v", code, out)
	}
	if conf, _ := out["confirm"].([]any); len(conf) != 1 || conf[0].(map[string]any)["key"] != "server.listen" {
		t.Errorf("confirm %v", out["confirm"])
	}
	if len(ns.sh.Server) != 0 {
		t.Errorf("check only saved %v", ns.sh.Server)
	}

	ns.checkAnswered, ns.checkRes = false, nil
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","values":{"syslog.udp":"0.0.0.0:1514"}}`)
	if code != http.StatusOK || !slices.Contains(toList(out["notes"]), "siem-a did not answer in time; it checks this change when it starts.") {
		t.Fatalf("no answer: %d %v", code, out)
	}
	if !slices.Contains(toList(out["saved"]), "syslog.udp") || out["versions"].(map[string]any)["syslog.udp"] != float64(1) {
		t.Errorf("saved %v versions %v", out["saved"], out["versions"])
	}

	ns.checkErr = errors.New("no route")
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","values":{"syslog.udp":"0.0.0.0:2514"}}`)
	if notes := toList(out["notes"]); code != http.StatusOK || len(notes) != 1 || !strings.Contains(notes[0], "could not be asked to check this change (no route)") {
		t.Fatalf("cannot ask: %d %v", code, out)
	}

	code, out = call("PUT", "/api/settings", `{"server":"siem-c","values":{"syslog.udp":"0.0.0.0:3514"}}`)
	if code != http.StatusOK || !slices.Contains(toList(out["notes"]), "siem-c is offline; it checks this change when it starts.") {
		t.Fatalf("offline: %d %v", code, out)
	}

	// A type error is found here, before asking.
	before := len(ns.checked)
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","values":{"server.max_connections":"many"}}`)
	if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields["server.max_connections"] == nil {
		t.Fatalf("a type error: %d %v", code, out)
	}
	if len(ns.checked) != before {
		t.Error("asked siem-a to check a change already refused")
	}

	// The connection settings of another server are changed on its own page.
	code, out = call("PUT", "/api/settings", `{"server":"siem-a","values":{"opensearch.username":"siem"}}`)
	if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || !strings.Contains(fields["opensearch.username"].(string), "Settings page of siem-a itself") {
		t.Fatalf("a connection setting: %d %v", code, out)
	}

	// A layer that cannot be read refuses the change.
	ns.layerErr["n_a"] = errors.New("timed out")
	if code, out := call("PUT", "/api/settings", `{"server":"siem-a","values":{"syslog.udp":"0.0.0.0:1514"}}`); code != http.StatusServiceUnavailable {
		t.Errorf("a layer that cannot be read: %d %v", code, out)
	}
}

// Try again of a shared value another server refused takes the refusal
// out of that server's settings.
func TestSharedPutRetryOnOtherServer(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	ns.others["n_a"] = &config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{},
		Refused: map[string]config.SharedRefusal{"search.max_events": {Reason: "too many", At: time.Now()}}}
	code, out := call("PUT", "/api/settings", `{"server":"siem-a","retry":["search.max_events","search.default_earliest"]}`)
	if code != http.StatusOK || !slices.Equal(toList(out["saved"]), []string{"search.max_events"}) {
		t.Fatalf("retry: %d %v", code, out)
	}
}

// The body of a change is checked first.
func TestSharedPutBadRequests(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{"values":`, http.StatusBadRequest, ""},
		{`{"scope":"galaxy","values":{}}`, http.StatusBadRequest, `no settings have the scope "galaxy"`},
		{`{"server":"siem-zz","values":{}}`, http.StatusNotFound, `no server "siem-zz"`},
	} {
		code, out := call("PUT", "/api/settings", c.body)
		if msg, _ := out["error"].(string); code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	// A save refused as stale without a part saved before is a plain 412.
	ns.memSettings.sh.Cluster["search.max_events"] = config.SharedValue{Value: json.RawMessage(`100`), Rev: 3,
		From: config.Source{By: "carol", Node: "siem-a", At: time.Now()}}
	code, out := call("PUT", "/api/settings", `{"values":{"search.max_events":777},"if_version":{"search.max_events":1}}`)
	if code != http.StatusPreconditionFailed || out["changed_by"] != "carol" || out["saved"] != nil {
		t.Errorf("stale: %d %v", code, out)
	}
	// Reset all with a scope takes back only that scope.
	if code, out := call("PUT", "/api/settings", `{"scope":"server","reset_all":true}`); code != http.StatusOK {
		t.Errorf("reset all: %d %v", code, out)
	}
}

func TestSplitEdit(t *testing.T) {
	at := time.Now()
	parts := splitEdit(sharedSettingsRequest{settingsRequest: settingsRequest{
		Values: map[string]any{"search.max_events": 5, "server.listen": "0.0.0.0:1", "opensearch.username": "u", "no.such": 1, "detections.scheduler": true},
		Clear:  []string{"assistant.api_key"}, Reset: []string{"syslog.udp"}, Retry: []string{"search.default_earliest"}, ResetAll: true,
	}}, "admin", at)
	var scopes []config.Scope
	for _, p := range parts {
		scopes = append(scopes, p.scope)
	}
	if !slices.Equal(scopes, []config.Scope{config.ScopeCluster, config.ScopeServer, config.ScopeBootstrap}) {
		t.Fatalf("scopes %v", scopes)
	}
	cl, sv, bs := parts[0].edit, parts[1].edit, parts[2].edit
	if cl.Values["no.such"] != 1 || cl.Values["search.max_events"] != 5 || cl.ResetAll || !slices.Equal(cl.Retry, []string{"search.default_earliest"}) {
		t.Errorf("cluster part %+v", cl)
	}
	if sv.Values["detections.scheduler"] != true || !sv.ResetAll || !slices.Equal(sv.Reset, []string{"syslog.udp"}) || sv.By != "admin" {
		t.Errorf("server part %+v", sv)
	}
	if bs.Values["opensearch.username"] != "u" || !bs.ResetAll {
		t.Errorf("bootstrap part %+v", bs)
	}
	// One scope named keeps the change whole.
	parts = splitEdit(sharedSettingsRequest{Scope: "cluster", settingsRequest: settingsRequest{Values: map[string]any{"server.listen": "x"}, ResetAll: true}}, "admin", at)
	if len(parts) != 1 || parts[0].scope != config.ScopeCluster || !parts[0].edit.ResetAll || parts[0].edit.Values["server.listen"] != "x" {
		t.Errorf("one scope: %+v", parts)
	}
	if got := editKeys(config.Edit{Values: map[string]any{"b": 1, "a": 2}, Clear: []string{"c", "a"}, Reset: []string{"d"}, Retry: []string{"b"}}); !slices.Equal(got, []string{"a", "b", "c", "d"}) {
		t.Errorf("editKeys %v", got)
	}
}

// POST /api/cluster/restart asks the servers named, once each, in order,
// and refuses an offline server, an unknown one and an empty list.
func TestClusterRestart(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{`, http.StatusBadRequest, ""},
		{`{"servers":[]}`, http.StatusBadRequest, "name the servers to restart"},
		{`{"servers":["siem-zz"]}`, http.StatusBadRequest, `no server "siem-zz"`},
		{`{"servers":[""]}`, http.StatusBadRequest, `no server ""`},
		{`{"servers":["siem-c"]}`, http.StatusConflict, "siem-c is offline"},
	} {
		code, out := call("POST", "/api/cluster/restart", c.body)
		if msg, _ := out["error"].(string); code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	code, out := call("POST", "/api/cluster/restart", `{"servers":["siem-a","n_b","SIEM-A"],"sequential":true}`)
	if code != http.StatusAccepted || out["request_id"] != "rq-1" || !slices.Equal(toList(out["servers"]), []string{"siem-a", "siem-b"}) {
		t.Fatalf("restart: %d %v", code, out)
	}
	if len(ns.restarted) != 1 || !slices.Equal(ns.restarted[0], []string{"n_a", "n_b"}) || !ns.sequential[0] {
		t.Errorf("restarted %v %v", ns.restarted, ns.sequential)
	}
	ns.restartErr = &shared.PausedError{Why: "OpenSearch refuses writes"}
	if code, out := call("POST", "/api/cluster/restart", `{"servers":["siem-a"]}`); code != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), "OpenSearch refuses writes") {
		t.Errorf("paused: %d %v", code, out)
	}
	ns.restartErr = errors.New("no requests")
	if code, out := call("POST", "/api/cluster/restart", `{"servers":["siem-a"]}`); code != http.StatusServiceUnavailable || out["error"] != "no requests" {
		t.Errorf("an error: %d %v", code, out)
	}
}

func TestClusterRestartNotShared(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", nil)
	if code, out := do(t, ts, "POST", "/api/cluster/restart", `{"servers":["siem-a"]}`, true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "not shared") {
		t.Errorf("not shared: %d %v", code, out)
	}
}

// CheckOwnEdit checks a change asked for on another server's page against
// this server's settings.
func TestCheckOwnEdit(t *testing.T) {
	_, srv, _ := newSettingsServer(t, "", nil)
	if _, err := srv.CheckOwnEdit(context.Background(), "admin", clustercfg.SettingsCheckArgs{}); err == nil || !strings.Contains(err.Error(), "not shared") {
		t.Errorf("not shared: %v", err)
	}
	_, srv, _ = newNodeSettingsServer(t)
	if _, err := srv.CheckOwnEdit(context.Background(), "admin", clustercfg.SettingsCheckArgs{Values: map[string]json.RawMessage{"syslog.udp": json.RawMessage(`{`)}}); err == nil || !strings.HasPrefix(err.Error(), "syslog.udp: ") {
		t.Errorf("bad JSON: %v", err)
	}
	res, err := srv.CheckOwnEdit(context.Background(), "admin", clustercfg.SettingsCheckArgs{Values: map[string]json.RawMessage{"server.max_connections": json.RawMessage(`"many"`)}})
	if err != nil || res.Fields["server.max_connections"] == "" {
		t.Errorf("a bad value: %+v %v", res, err)
	}
	res, err = srv.CheckOwnEdit(context.Background(), "admin", clustercfg.SettingsCheckArgs{Values: map[string]json.RawMessage{"server.listen": json.RawMessage(`"0.0.0.0:9443"`)}})
	if err != nil || len(res.Fields) != 0 || !slices.Contains(res.Changed, "server.listen") || !slices.Contains(res.Confirm, "server.listen") {
		t.Errorf("a new listen address: %+v %v", res, err)
	}
}

// ApplySettings puts what applies at once into use.
func TestApplySettings(t *testing.T) {
	_, srv, _ := newSettingsServer(t, "", nil)
	old := srv.conf()
	next := *old
	next.Search.MaxEvents = old.Search.MaxEvents + 11
	got := srv.ApplySettings(old, &next)
	if !slices.Contains(got, "search.max_events") {
		t.Errorf("applied %v", got)
	}
	if srv.conf().Search.MaxEvents != next.Search.MaxEvents {
		t.Errorf("max events in use %d", srv.conf().Search.MaxEvents)
	}
	if got := srv.ApplySettings(&next, &next); len(got) != 0 {
		t.Errorf("nothing changed, applied %v", got)
	}
}

func TestNodeCfgValue(t *testing.T) {
	if v := NodeCfgValue(nil)("server.listen"); v != nil {
		t.Errorf("nil nodecfg: %v", v)
	}
	nc := &shared.NodeCfg{
		Values: map[string]shared.PageValue{
			"server.listen":           {Value: json.RawMessage(`"0.0.0.0:7443"`)},
			"syslog.udp":              {Value: json.RawMessage(`"0.0.0.0:514"`), Refused: "taken"},
			"cluster.leader_eligible": {Value: json.RawMessage(`false`)},
		},
		Running: map[string]shared.RunningValue{"syslog.udp": {Value: json.RawMessage(`"0.0.0.0:5514"`)}, "syslog.tcp": {Value: json.RawMessage(`{`)}},
	}
	get := NodeCfgValue(nc)
	for key, want := range map[string]any{"server.listen": "0.0.0.0:7443", "syslog.udp": "0.0.0.0:5514", "detections.scheduler": false, "syslog.tcp": nil, "syslog.tls": nil} {
		if got := get(key); got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
}

// The export of shared settings has the shared ones as YAML and each
// server's own as comments, saying which servers cannot be read.
func TestExportSharedSettings(t *testing.T) {
	ns, _, call := newNodeSettingsServer(t)
	ns.nodecfg["n_a"] = &shared.NodeCfg{Values: map[string]shared.PageValue{"server.listen": {Value: json.RawMessage(`"0.0.0.0:7443"`)}}}
	ns.layerErr["n_c"] = errors.New("not found")
	code, out := call("GET", "/api/settings/export", "")
	text, _ := out["yaml"].(string)
	if code != http.StatusOK || out["filename"] != "signalith-settings.yaml" {
		t.Fatalf("export: %d %v", code, out)
	}
	for _, want := range []string{
		"# Settings shared by the servers of this cluster, exported from siem-b on ",
		"\nsearch:\n",
		"# siem-a's own settings: for that server alone",
		"# siem-b's own settings:",
		"0.0.0.0:7443",
		"# siem-c's own settings cannot be read now (not found).",
		"the old name of cluster.leader_eligible",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("export is missing %q:\n%s", want, text)
		}
	}
	_, out = call("GET", "/api/settings/export?server=siem-a", "")
	text, _ = out["yaml"].(string)
	if !strings.Contains(text, "siem-a's own settings") || strings.Contains(text, "siem-b's own settings") || strings.Contains(text, "siem-c") {
		t.Errorf("export for siem-a:\n%s", text)
	}
}

// A member whose settings are not shared yet says which servers' version
// cannot read them.
func TestSettingsPending(t *testing.T) {
	seen := 2 * time.Hour * 24 * 365
	cl := &statusCluster{st: cluster.Status{Self: "n_b", Servers: []cluster.ServerStatus{
		{NodeID: "n_b", Name: "siem-b", Self: true},
		{NodeID: "n_a", Name: "siem-a", Version: "1.2.0", Detail: &cluster.Heartbeat{LevelMax: 1}},
		{NodeID: "n_c", Name: "siem-c", Version: "1.0.0"},
		{NodeID: "n_d", Name: "siem-d", Version: "1.9.0", Detail: &cluster.Heartbeat{LevelMax: shared.LevelSharedSettings}},
		{NodeID: "n_e", Name: "siem-e", Version: "0.9.0", SeenAgo: &seen},
	}}}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Shared, s.Cluster = &memberShared{}, cl })
	code, view := do(t, ts, "GET", "/api/settings", "", true)
	p, _ := view["shared_pending"].(map[string]any)
	if code != http.StatusOK || p == nil {
		t.Fatalf("page: %d %v", code, view["shared_pending"])
	}
	var names []string
	for _, sv := range p["servers"].([]any) {
		names = append(names, sv.(map[string]any)["name"].(string))
	}
	if !slices.Equal(names, []string{"siem-a", "siem-c"}) {
		t.Errorf("waiting for %v", names)
	}
	srv.Cluster = nil
	if p := srv.settingsPending(); p == nil || len(p.Servers) != 0 {
		t.Errorf("no cluster: %+v", p)
	}
	srv.Shared = nil
	if p := srv.settingsPending(); p != nil {
		t.Errorf("no member: %+v", p)
	}
}

func TestSharedSmallHelpers(t *testing.T) {
	if rawValue(nil) != nil || rawValue(json.RawMessage(`{`)) != nil || rawValue(json.RawMessage(`"x"`)) != "x" {
		t.Error("rawValue")
	}
	at := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	for src, want := range map[config.Source]string{
		{Applied: "env", Node: "siem-a", At: at}: "applied from the environment on siem-a, 4 Mar",
		{Applied: "yaml", Node: "siem-b"}:        "applied from signalith.yaml on siem-b",
		{Kind: config.FromPage}:                  "",
	} {
		if got := sourceWords(src); got != want {
			t.Errorf("sourceWords(%+v) = %q, want %q", src, got, want)
		}
	}
	if got := redactedRaw(json.RawMessage(`5`)); string(got) != "5" {
		t.Errorf("redactedRaw of a number %s", got)
	}
	if got := redactedRaw(nil); got != nil {
		t.Errorf("redactedRaw(nil) %s", got)
	}
}
