package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// fastSharedCheck makes followShared look every second during the test.
func fastSharedCheck(t *testing.T) {
	sharedCheckEvery.Store(int64(time.Second))
	t.Cleanup(func() { sharedCheckEvery.Store(int64(30 * time.Second)) })
}

// settingsShared waits for rs to take the settings of the Settings page
// from the shared settings, and signs in again: the switch to the shared
// users before it signs everyone out once.
func (rs *running) settingsShared() {
	rs.t.Helper()
	rs.usersShared()
	eventually(rs.t, rs.r.node.Name()+" takes its settings from the shared settings", func() bool {
		srv := rs.r.srv.Load()
		return rs.r.sharedContent.settingsOn.Load() && srv != nil && srv.Running().SharedSettings()
	})
	eventually(rs.t, "signed in to "+rs.r.node.Name(), func() bool {
		if rs.signedIn("") {
			return true
		}
		rs.signInAs("admin", "s3cret-pass")
		return false
	})
}

// putSettings sends a change of the Settings page and returns the answer.
func (rs *running) putSettings(body string) (int, map[string]any) {
	rs.t.Helper()
	code, out, err := rs.call("", "PUT", "/api/settings", body)
	if err != nil {
		rs.t.Fatal(err)
	}
	return code, out
}

// running returns the configuration rs runs with now.
func (rs *running) running() *config.Config { return rs.r.srv.Load().Running() }

// twoMembers starts A, which founds the cluster, and B, which joins it,
// both taking their settings from the shared settings.
func twoMembers(t *testing.T, extraA, extraB string) (a, b *running, fos *ostest.Server) {
	t.Helper()
	t.Setenv(clusterKeyFileEnv, "")
	fos = ostest.New(t)
	a = startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a", extra: extraA})
	a.settingsShared()
	giveKey(t, a)
	b = startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b", extra: extraB})
	b.settingsShared()
	for _, rs := range []*running{a, b} {
		eventually(t, rs.r.node.Name()+" sees both servers", func() bool {
			n := 0
			for _, sv := range rs.r.node.Status().Servers {
				if sv.Detail != nil && sv.Detail.SettingsRev != nil {
					n++
				}
			}
			return n == 2
		})
	}
	return a, b, fos
}

// W5 and W13: a shared setting that applies at once, changed on A, is in
// use on B within a poll, without a restart: the session timeout (B's
// session store), the search defaults, the assistant, the oldest event
// age; and a server's own node address, changed for B on A, is what B's
// heartbeat says.
func TestSharedSettingsApplyLive(t *testing.T) {
	fastSharedCheck(t)
	a, b, fos := twoMembers(t, "", "")
	starts := b.starts()

	code, out := a.putSettings(`{"values":{"auth.session_timeout":"3h","search.default_earliest":"-2h","search.max_events":777,` +
		`"ingest.max_event_age":"10d","assistant.provider":"openai","assistant.url":"http://127.0.0.1:1/v1","assistant.model":"m1"}}`)
	if code != http.StatusOK {
		t.Fatalf("save on A: %d %v", code, out)
	}
	for _, k := range []string{"auth.session_timeout", "search.default_earliest", "ingest.max_event_age", "assistant.model"} {
		if !slices.Contains(toStrings(out["applied"]), k) {
			t.Errorf("%s was not applied on A at once: %v", k, out["applied"])
		}
	}
	eventually(t, "B uses the new session timeout", func() bool {
		p := b.r.sharedContent.users.cur.Load()
		return b.running().SessionIdle() == 3*time.Hour && p != nil && p.sessions.Idle() == 3*time.Hour
	})
	eventually(t, "B uses the other settings changed on A", func() bool {
		c := b.running()
		return c.Search.DefaultEarliest == "-2h" && c.Search.MaxEvents == 777 && c.Ingest.MaxEventAge == "10d" &&
			c.Assistant.Model == "m1" && c.Assistant.Provider == "openai"
	})
	if b.starts() != starts {
		t.Errorf("B restarted to apply them: %s, then %s", starts, b.starts())
	}

	// B's own node address, changed on A's page.
	code, out = a.putSettings(`{"server":"siem-b","values":{"server.node_url":"http://siem-b.example:9000"}}`)
	if code != http.StatusOK {
		t.Fatalf("save of B's node address on A: %d %v", code, out)
	}
	eventually(t, "B's heartbeat carries its new node address", func() bool {
		hb := fos.Source("signalith_runtime", "node:"+b.r.node.ID())
		return hb["node_url"] == "http://siem-b.example:9000"
	})
	if a.running().Server.NodeURL == "http://siem-b.example:9000" {
		t.Error("B's node address is in use on A")
	}
	if b.starts() != starts {
		t.Errorf("B restarted to apply its node address: %s, then %s", starts, b.starts())
	}
}

// nodeCfgOf reads a server's nodecfg document from the fake.
func nodeCfgOf(t *testing.T, fos *ostest.Server, rs *running) shared.NodeCfg {
	t.Helper()
	var nc shared.NodeCfg
	sharedBody(t, fos, shared.NodeCfgID(rs.r.node.ID()), &nc)
	return nc
}

// heartbeatList reads a list from a server's heartbeat in the fake.
func heartbeatList(fos *ostest.Server, rs *running, field string) []string {
	hb := fos.Source("signalith_runtime", "node:"+rs.r.node.ID())
	return toStrings(hb[field])
}

// W7: one of B's own settings changed on A's page lands in B's nodecfg
// document, and B lists it as waiting for a restart within a poll. B's
// own writes to its nodecfg meanwhile (what it runs) refuse no later
// change; a change made from an older reading of the same setting is
// refused with 412.
func TestServerSettingEditedElsewhere(t *testing.T) {
	fastSharedCheck(t)
	a, b, fos := twoMembers(t, "", "")
	udp := freeAddr(t)
	code, out := a.putSettings(`{"server":"siem-b","values":{"syslog.udp":"` + udp + `"}}`)
	if code != http.StatusOK {
		t.Fatalf("save of B's syslog address on A: %d %v", code, out)
	}
	if out["server"].(map[string]any)["name"] != "siem-b" {
		t.Errorf("the answer is not B's page: %v", out["server"])
	}
	versions, _ := out["versions"].(map[string]any)
	rev, _ := versions["syslog.udp"].(float64)
	if rev < 1 {
		t.Fatalf("versions %v", out["versions"])
	}
	nc := nodeCfgOf(t, fos, b)
	if v := nc.Values["syslog.udp"]; string(v.Value) != `"`+udp+`"` || v.From.Node != "siem-a" {
		t.Fatalf("B's nodecfg: %+v", v)
	}
	if a.running().Syslog.UDP == udp {
		t.Error("A uses B's syslog address")
	}
	eventually(t, "B's heartbeat lists the change as waiting for a restart", func() bool {
		return slices.Contains(heartbeatList(fos, b, "restart_needed"), "syslog.udp")
	})
	eventually(t, "B wrote what it runs", func() bool {
		nc := nodeCfgOf(t, fos, b)
		return !nc.RunningAt.IsZero() && nc.Running["syslog.udp"].Source != ""
	})
	tcp := freeAddr(t)
	code, out = a.putSettings(`{"server":"siem-b","values":{"syslog.tcp":"` + tcp + `"},"if_version":{"syslog.udp":` +
		strconv.FormatInt(int64(rev), 10) + `,"syslog.tcp":0}}`)
	if code != http.StatusOK {
		t.Fatalf("a second change after B's own writes: %d %v", code, out)
	}
	code, out = a.putSettings(`{"server":"siem-b","values":{"syslog.udp":""},"if_version":{"syslog.udp":0}}`)
	if code != http.StatusPreconditionFailed {
		t.Fatalf("a change from an older reading: %d %v", code, out)
	}
	// B's page, asked on A, shows the values with their revisions.
	code, view, _ := a.call("", "GET", "/api/settings?server=siem-b", "")
	if code != http.StatusOK {
		t.Fatalf("B's page on A: %d %v", code, view)
	}
	f := settingsField(t, view, "syslog.tcp")
	if f["value"] != tcp || f["scope"] != "server" {
		t.Errorf("syslog.tcp on B's page: %v", f)
	}
}

// W8: a change of B's own settings made on A is checked on B while it
// answers, and refused at the field there: B's certificate file does not
// exist. With B stopped, it is saved with a note; B then cannot start
// with it, starts without its own settings, and refuses them in its
// nodecfg document.
func TestServerSettingCheckedThere(t *testing.T) {
	fastSharedCheck(t)
	a, b, fos := twoMembers(t, "", "")
	missing := filepath.Join(b.dir, "missing")
	body := `{"server":"siem-b","values":{"server.tls.mode":"files","server.tls_cert":"` + filepath.ToSlash(filepath.Join(missing, "cert.pem")) +
		`","server.tls_key":"` + filepath.ToSlash(filepath.Join(missing, "key.pem")) + `"}}`
	code, out := a.putSettings(body)
	fields, _ := out["fields"].(map[string]any)
	if code != http.StatusBadRequest || fields["server.tls_cert"] == nil {
		t.Fatalf("a missing certificate file on B: %d %v", code, out)
	}
	if nc := nodeCfgOf(t, fos, b); nc.Values["server.tls_cert"].Value != nil {
		t.Fatal("the refused change was saved")
	}

	dir, id := b.dir, b.r.node.ID()
	b.stop()
	eventually(t, "A sees B stopped", func() bool {
		for _, sv := range a.r.node.Status().Servers {
			if sv.NodeID == id {
				return sv.State == cluster.StateStopped || sv.State == cluster.StateOffline
			}
		}
		return false
	})
	code, out = a.putSettings(body)
	if code != http.StatusOK || !strings.Contains(strings.Join(toStrings(out["notes"]), " "), "offline") {
		t.Fatalf("the change for B while it is stopped: %d %v", code, out)
	}
	code, out, _ = a.call("", "POST", "/api/cluster/restart", `{"servers":["siem-b"]}`)
	if code != http.StatusConflict {
		t.Errorf("a restart of a stopped server: %d %v", code, out)
	}

	b = startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b", dir: dir})
	if !strings.Contains(b.logs.String(), `msg="settings from the Settings page are not in use"`) {
		t.Errorf("B did not say it started without its own settings:\n%s", b.logs.String())
	}
	if b.running().Server.TLSMode() != config.TLSOff {
		t.Errorf("B runs with HTTPS %s", b.running().Server.TLSMode())
	}
	eventually(t, "B refuses its own settings that kept it from starting", func() bool {
		nc := nodeCfgOf(t, fos, b)
		return nc.Values["server.tls_cert"].Refused != "" && nc.Values["server.tls.mode"].Refused != ""
	})
	// A's page of B says so at the fields.
	code, view, _ := a.call("", "GET", "/api/settings?server=siem-b", "")
	if f := settingsField(t, view, "server.tls_cert"); code != http.StatusOK || f["refused"] == nil {
		t.Errorf("B's certificate file on A's page: %d %v", code, f)
	}
}

// restartServers asks rs to restart servers, one after the other, and
// returns the request's id.
func (rs *running) restartServers(servers ...string) string {
	rs.t.Helper()
	b, _ := json.Marshal(map[string]any{"servers": servers, "sequential": true})
	code, out, err := rs.call("", "POST", "/api/cluster/restart", string(b))
	id, _ := out["request_id"].(string)
	if err != nil || code != http.StatusAccepted || id == "" {
		rs.t.Fatalf("restart of %v: %d %v %v", servers, code, out, err)
	}
	return id
}

// request waits for the request id to be over, and returns it.
func (rs *running) request(id string) *shared.Request {
	rs.t.Helper()
	var req *shared.Request
	deadline := time.Now().Add(60 * time.Second)
	for {
		r, ok, err := rs.r.shared.Requests().Get(context.Background(), id)
		if err == nil && ok && r.Over() {
			req = r
			break
		}
		if time.Now().After(deadline) {
			rs.t.Fatalf("request %s is not over: %+v", id, r)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return req
}

// restartResults reads the results of a restart request.
func restartResults(t *testing.T, req *shared.Request) clustercfg.RestartResults {
	t.Helper()
	var res clustercfg.RestartResults
	if err := json.Unmarshal(req.Result, &res); err != nil {
		t.Fatalf("results of %s: %v (%s)", req.ID, err, req.Result)
	}
	return res
}

// W14: a shared setting that waits for a restart, changed on A, waits on
// both; restarting both from A's page runs one at a time: B restarts only
// once A's restart is over and A serves again. Both then use it.
func TestSequentialRestart(t *testing.T) {
	fastSharedCheck(t)
	a, b, fos := twoMembers(t, "", "")
	code, out := a.putSettings(`{"values":{"syslog.allow":["10.0.0.0/8"]}}`)
	if code != http.StatusOK || !slices.Contains(toStrings(out["after_restart"]), "syslog.allow") {
		t.Fatalf("save on A: %d %v", code, out)
	}
	for _, rs := range []*running{a, b} {
		eventually(t, rs.r.node.Name()+" waits for a restart", func() bool {
			return slices.Contains(heartbeatList(fos, rs, "restart_needed"), "syslog.allow")
		})
	}
	req := a.request(a.restartServers("siem-a", "siem-b"))
	if req.State != shared.RequestDone {
		t.Fatalf("request %+v\n%s\n%s", req, a.logs.String(), b.logs.String())
	}
	res := restartResults(t, req)
	ra, rb := res[a.r.node.ID()], res[b.r.node.ID()]
	if !ra.OK || !rb.OK || ra.BootID != a.r.shared.BootID() || !slices.Contains(rb.Keys, "syslog.allow") {
		t.Fatalf("results %+v", res)
	}
	la, lb := a.r.RestartStatus().Last, b.r.RestartStatus().Last
	if la == nil || lb == nil || !la.OK || !lb.OK {
		t.Fatalf("last restarts %+v %+v", la, lb)
	}
	if aDone := la.At.Add(time.Duration(la.TookMS) * time.Millisecond); lb.At.Before(aDone) {
		t.Errorf("B restarted at %s, before A's restart ended at %s", lb.At, aDone)
	}
	for _, rs := range []*running{a, b} {
		if got := rs.running().Syslog.Allow; !slices.Equal(got, []string{"10.0.0.0/8"}) {
			t.Errorf("%s runs syslog.allow %v", rs.r.node.Name(), got)
		}
		eventually(t, rs.r.node.Name()+" waits for no restart", func() bool {
			return len(heartbeatList(fos, rs, "restart_needed")) == 0
		})
	}
}

// W15: a shared setting B cannot start with: B's part of the restart goes
// back to the settings it ran, fails, and the request stops before A's
// part. B refuses the shared value in its nodecfg, with the value it
// keeps, its heartbeat lists it, and it keeps running with its own value;
// a new shared value takes the refusal's place.
func TestRestartRefusedOnOneServer(t *testing.T) {
	fastSharedCheck(t)
	a, b, fos := twoMembers(t, "", "")
	failB := b.r.failStart
	b.r.failStart = func(c *config.Config) error {
		if slices.Contains(c.Syslog.Allow, "10.9.9.0/24") {
			return keyed(errors.New("syslog.allow cannot be used on this server"), "syslog.allow")
		}
		return failB(c)
	}
	code, out := a.putSettings(`{"values":{"syslog.allow":["10.9.9.0/24"]}}`)
	if code != http.StatusOK {
		t.Fatalf("save on A: %d %v", code, out)
	}
	eventually(t, "B waits for a restart", func() bool {
		return slices.Contains(heartbeatList(fos, b, "restart_needed"), "syslog.allow")
	})
	before := a.r.RestartStatus().Last
	req := a.request(a.restartServers("siem-b", "siem-a"))
	if req.State != shared.RequestFailed || req.Status[a.r.node.ID()] == shared.RequestDone {
		t.Fatalf("request %+v", req)
	}
	rb := restartResults(t, req)[b.r.node.ID()]
	if rb.OK || !rb.RolledBack || !slices.Contains(rb.Keys, "syslog.allow") {
		t.Fatalf("B's part %+v", rb)
	}
	if got := a.r.RestartStatus().Last; got != before {
		t.Errorf("A restarted: %+v", got)
	}
	// B ran with the default, which it keeps: nothing to write down.
	nc := nodeCfgOf(t, fos, b)
	ref, ok := nc.Refused["syslog.allow"]
	if !ok || len(ref.Kept) != 0 || ref.Reason == "" {
		t.Fatalf("B's refusal %+v (kept %s)", nc.Refused, ref.Kept)
	}
	eventually(t, "B's heartbeat lists the refusal", func() bool {
		return slices.Contains(heartbeatList(fos, b, "settings_refused"), "syslog.allow") &&
			!slices.Contains(heartbeatList(fos, b, "restart_needed"), "syslog.allow")
	})
	if got := b.running().Syslog.Allow; len(got) != 0 {
		t.Errorf("B runs syslog.allow %v", got)
	}
	eventually(t, "A's page says B refused it", func() bool {
		code, view, _ := a.call("", "GET", "/api/settings", "")
		f := settingsField(t, view, "syslog.allow")
		servers, _ := f["servers"].(map[string]any)
		return code == http.StatusOK && servers["siem-b"] == "refused" && servers["siem-a"] == "waiting"
	})

	code, out = a.putSettings(`{"values":{"syslog.allow":["10.8.0.0/16"]}}`)
	if code != http.StatusOK {
		t.Fatalf("second save on A: %d %v", code, out)
	}
	eventually(t, "B no longer refuses it, and waits for a restart", func() bool {
		return !slices.Contains(heartbeatList(fos, b, "settings_refused"), "syslog.allow") &&
			slices.Contains(heartbeatList(fos, b, "restart_needed"), "syslog.allow")
	})
}

// W16: a restart by request that moves B's web page is confirmed by A,
// which probes B's new address with the move's token; without a probe,
// B goes back to its old address once the wait is over, and its part
// fails saying why.
func TestRemoteRestartMovesWebPage(t *testing.T) {
	fastSharedCheck(t)
	a, b, _ := twoMembers(t, "", "")
	to := freeAddr(t)
	code, out := a.putSettings(`{"server":"siem-b","values":{"server.listen":"` + to + `"}}`)
	if code != http.StatusOK {
		t.Fatalf("B's address on A: %d %v", code, out)
	}
	req := a.request(a.restartServers("siem-b"))
	rb := restartResults(t, req)[b.r.node.ID()]
	if req.State != shared.RequestDone || !rb.OK || rb.Move == nil || !rb.Move.Confirmed || rb.Move.To != "http://"+to {
		t.Fatalf("request %+v, B's part %+v", req, rb)
	}
	if !strings.Contains(b.logs.String(), `msg="new web address confirmed: someone reached it"`) {
		t.Errorf("B did not log the confirmation:\n%s", b.logs.String())
	}
	if b.r.web.cfg.Server.Listen != to {
		t.Fatalf("B answers at %s", b.r.web.cfg.Server.Listen)
	}

	// Again, with nobody to probe: a request made without A's page.
	moveWait = time.Second
	t.Cleanup(func() { moveWait = api.MoveWait })
	back := freeAddr(t)
	code, out = a.putSettings(`{"server":"siem-b","values":{"server.listen":"` + back + `"}}`)
	if code != http.StatusOK {
		t.Fatalf("B's address on A again: %d %v", code, out)
	}
	sent, err := a.r.shared.Requests().SubmitTo(context.Background(), clustercfg.RequestRestart, []string{b.r.node.ID()}, true, clustercfg.RestartArgs{}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	req = a.request(sent.ID)
	rb = restartResults(t, req)[b.r.node.ID()]
	if req.State != shared.RequestFailed || rb.OK || !rb.RolledBack || !strings.Contains(rb.Error, "Nobody opened Signalith at") {
		t.Fatalf("request %+v, B's part %+v", req, rb)
	}
	eventually(t, "B answers at its address before", func() bool { return b.r.web.cfg.Server.Listen == to })
}

// clusterCmd runs signalith cluster for rs, and returns what it printed.
func (rs *running) clusterCmd(args ...string) (string, error) {
	rs.t.Helper()
	var out, errOut strings.Builder
	err := runCluster(append(args, "-c", filepath.Join(rs.dir, "signalith.yaml")), os.Stdin, &out, &errOut)
	return out.String() + errOut.String(), err
}

// W22 and W13: the export of a member's settings carries the shared
// settings, and every server's own only as comments marked for that
// server, cluster.leader_eligible and detections.scheduler among them;
// signalith cluster apply -f of it changes nothing. A file that changes
// retention.interval and a setting of the page applies on both servers
// without a restart; one with a server's own setting is refused.
func TestExportAndApply(t *testing.T) {
	fastSharedCheck(t)
	a, b, _ := twoMembers(t, "", "")
	code, out, _ := a.call("", "GET", "/api/settings/export", "")
	text, _ := out["yaml"].(string)
	if code != http.StatusOK || text == "" {
		t.Fatalf("export: %d %v", code, out)
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "leader_eligible:"):
			if !strings.Contains(trimmed, "# this server only") {
				t.Errorf("leader_eligible is not marked: %q", line)
			}
		case strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "scheduler:"):
			if !strings.Contains(trimmed, "the old name of cluster.leader_eligible") {
				t.Errorf("detections.scheduler is not marked: %q", line)
			}
		case !strings.HasPrefix(trimmed, "#") && (strings.Contains(trimmed, "leader_eligible") || strings.Contains(trimmed, "scheduler:")):
			t.Errorf("a server's own setting outside the comments: %q", line)
		}
	}
	if !strings.Contains(text, "# siem-a's own settings") || !strings.Contains(text, "# siem-b's own settings") {
		t.Errorf("the servers' own settings are not there:\n%s", text)
	}
	file := filepath.Join(t.TempDir(), "shared.yaml")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := config.ReadSettingsFile(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range f.FileKeys() {
		if config.ScopeOf(k) != config.ScopeCluster {
			t.Errorf("the export sets %s, of scope %q", k, config.ScopeOf(k))
		}
	}
	printed, err := a.clusterCmd("apply", "-f", file, "-yes")
	if err != nil || !strings.Contains(printed, "Nothing to change") {
		t.Fatalf("apply of the export: %v\n%s", err, printed)
	}
	// The command line's export is the same file.
	cli, err := b.clusterCmd("export", "-settings")
	if err != nil || !strings.Contains(cli, "# siem-a's own settings") || !strings.Contains(cli, "auth:\n  session_timeout:") {
		t.Fatalf("cluster export -settings: %v\n%s", err, cli)
	}

	if err := os.WriteFile(file, []byte("retention:\n  interval: 2h\nsearch:\n  max_events: 4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	printed, err = b.clusterCmd("apply", "-f", file, "-yes")
	if err != nil || !strings.Contains(printed, "retention.interval") || !strings.Contains(printed, "search.max_events: 10000 -> 4321") {
		t.Fatalf("apply: %v\n%s", err, printed)
	}
	for _, rs := range []*running{a, b} {
		eventually(t, rs.r.node.Name()+" uses the applied settings", func() bool {
			c := rs.running()
			return c.Search.MaxEvents == 4321 && c.RetentionInterval() == 2*time.Hour
		})
	}
	if err := os.WriteFile(file, []byte("server:\n  listen: 127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if printed, err = a.clusterCmd("apply", "-f", file, "-yes"); err == nil || !strings.Contains(err.Error(), "server.listen: it is one server's own setting") {
		t.Fatalf("apply of a server's own setting: %v\n%s", err, printed)
	}
}

// W23, from the command line: signalith cluster apply with another
// auth.admin_user renames the built-in admin on every server; the old
// name no longer signs in, the new one does, with the same password.
func TestApplyRenamesBuiltinAdmin(t *testing.T) {
	fastSharedCheck(t)
	a, b, _ := twoMembers(t, "", "")
	file := filepath.Join(t.TempDir(), "admin.yaml")
	if err := os.WriteFile(file, []byte("auth:\n  admin_user: root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	printed, err := a.clusterCmd("apply", "-f", file, "-yes")
	if err != nil || !strings.Contains(printed, "renamed to root") {
		t.Fatalf("apply: %v\n%s", err, printed)
	}
	eventually(t, "B knows the built-in admin as root", func() bool {
		name, _, ok := b.r.sharedContent.users.docs.Builtin()
		return ok && name == "root"
	})
	if code := b.signInAs("admin", "s3cret-pass"); code != http.StatusUnauthorized {
		t.Errorf("the old name signs in on B: %d", code)
	}
	if code := b.signInAs("root", "s3cret-pass"); code != http.StatusOK {
		t.Errorf("the new name on B: %d", code)
	}
	if printed, err = a.clusterCmd("apply", "-f", file, "-yes"); err != nil || !strings.Contains(printed, "Nothing to change") {
		t.Errorf("apply again: %v\n%s", err, printed)
	}
}

// toStrings turns a JSON list into strings.
func toStrings(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// W25: while this server cannot use the shared settings in OpenSearch
// (degraded), a change of the shared settings or of its own settings is
// refused (503); one of the settings it needs to reach OpenSearch is
// saved in settings.yaml, and the restart in place that applies it keeps
// the shared values, from the copy in cache.enc.
func TestSharedSettingsWhileDegraded(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rs.settingsShared()
	if code, out := rs.putSettings(`{"values":{"auth.session_timeout":"3h"}}`); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	// The shared settings cannot be read; OpenSearch itself answers.
	fos := rs.os
	down := ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
	fos.SetFault(func(_, p string) *ostest.Fault {
		if strings.Contains(p, shared.ConfigIndex("signalith")) {
			return &down
		}
		return nil
	})
	t.Cleanup(func() { fos.SetFault(nil) })
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if m, _ := rs.r.shared.Mode(); m == shared.ModeDegraded {
			break
		}
		if time.Now().After(deadline) {
			m, why := rs.r.shared.Mode()
			t.Fatalf("the server is %s (%s), not degraded", m, why)
		}
	}
	for _, body := range []string{`{"values":{"search.max_events":777}}`, `{"values":{"server.node_url":"http://siem.example:9000"}}`} {
		if code, out := rs.putSettings(body); code != http.StatusServiceUnavailable {
			t.Errorf("the change %s while degraded: %d %v", body, code, out)
		}
	}
	if code, out := rs.putSettings(`{"values":{"opensearch.username":"svc-siem"}}`); code != http.StatusOK {
		t.Fatalf("a change of the OpenSearch username while degraded: %d %v", code, out)
	}
	if _, res := rs.restart(); res == nil || !res.OK {
		t.Fatalf("the restart while degraded: %+v\n%s", res, rs.logs.String())
	}
	c := rs.running()
	if c.OpenSearch.Username != "svc-siem" {
		t.Errorf("the OpenSearch username in use: %q", c.OpenSearch.Username)
	}
	if c.SessionIdle() != 3*time.Hour || c.Search.MaxEvents == 777 {
		t.Errorf("the shared values in use after the restart: session timeout %s, max events %d", c.SessionIdle(), c.Search.MaxEvents)
	}
	if v := c.Source("auth.session_timeout"); v.Kind != config.FromShared {
		t.Errorf("the session timeout comes from %+v", v)
	}
}

// W26: a listen address saved for this server that it cannot listen on
// keeps it from starting with its own settings: it starts without them,
// says so, and refuses the address in its nodecfg document. With
// OpenSearch refusing writes, signalith settings reset -local sets such a
// setting aside for the next start; it is refused in the shared settings
// once OpenSearch takes writes again, and setaside.json goes.
func TestStartWithoutServerSettings(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	settleRetryEvery.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { settleRetryEvery.Store(int64(5 * time.Second)) })
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rs.settingsShared()
	fos, dir, path := rs.os, rs.dir, filepath.Join(rs.dir, "signalith.yaml")
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	saveListen := func(rs *running) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		raw, _ := json.Marshal(held.Addr().String())
		if err := clustercfg.MutateNodeCfg(ctx, rs.r.shared, rs.r.node.ID(), "admin", func(nc *shared.NodeCfg) error {
			if nc.Values == nil {
				nc.Values = map[string]shared.PageValue{}
			}
			v := nc.Values["server.listen"]
			v.Value, v.Rev, v.Refused, v.RefusedAt = raw, v.Rev+1, "", time.Time{}
			v.From = shared.From{By: "admin", Node: rs.r.node.ID(), At: time.Now()}
			nc.Values["server.listen"] = v
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	saveListen(rs)
	rs.stop()

	rs = startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, dir: dir})
	if !strings.Contains(rs.logs.String(), "started without this server's own settings saved on a Settings page") {
		t.Errorf("the server did not say it started without its own settings:\n%s", rs.logs.String())
	}
	if got := rs.running().Server.Listen; got == held.Addr().String() {
		t.Errorf("the server listens on %s", got)
	}
	eventually(t, "the server refuses the listen address it could not use", func() bool {
		return nodeCfgOf(t, fos, rs).Values["server.listen"].Refused != ""
	})

	// Saved again, then set aside with OpenSearch refusing writes.
	saveListen(rs)
	rs.stop()
	fos.Block(true)
	t.Cleanup(func() { fos.Block(false) })
	out, err := capture(t, func() error { return cmdSettings([]string{"reset", "-local", "-c", path, "server.listen"}) })
	if err != nil || !strings.Contains(out, "Set aside server.listen") {
		t.Fatalf("settings reset -local: %v\n%s", err, out)
	}
	stateDir := config.StateDirFor(path)
	if l, _ := readSetAside(stateDir); l == nil || !slices.Contains(l.Keys, "server.listen") {
		t.Fatalf("setaside.json: %+v", l)
	}
	rs = startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, dir: dir})
	if strings.Contains(rs.logs.String(), "could not start with the settings saved") {
		t.Errorf("the server did not start with server.listen set aside:\n%s", rs.logs.String())
	}
	if got := rs.running().Server.Listen; got == held.Addr().String() {
		t.Errorf("the server listens on %s, set aside", got)
	}
	if nodeCfgOf(t, fos, rs).Values["server.listen"].Refused != "" {
		t.Error("server.listen was refused in the shared settings while OpenSearch refused writes")
	}
	fos.Block(false)
	eventually(t, "the setting set aside is refused in the shared settings, and setaside.json goes", func() bool {
		_, err := os.Stat(setAsideFile(stateDir))
		return errors.Is(err, os.ErrNotExist) && nodeCfgOf(t, fos, rs).Values["server.listen"].Refused != ""
	})
}

// signalith settings reset on a member whose settings are shared: a
// shared setting goes back to its default for every server, at once; one
// of the server's own leaves its nodecfg document.
func TestSettingsResetOnMember(t *testing.T) {
	fastSharedCheck(t)
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rs.settingsShared()
	def := rs.running().Search.MaxEvents
	if code, out := rs.putSettings(`{"values":{"search.max_events":777,"server.node_url":"http://siem.example:9000"}}`); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	path := filepath.Join(rs.dir, "signalith.yaml")
	// The command treats the server as a member once its copy of the
	// shared settings is written, which happens in the background.
	eventually(t, "the server writes its copy of the shared settings", func() bool {
		_, err := os.Stat(shared.CachePath(config.StateDirFor(path)))
		return err == nil
	})
	out, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "search.max_events"}) })
	if err != nil || !strings.Contains(out, "Reset search.max_events for every server of the cluster") {
		t.Fatalf("reset of a shared setting: %v\n%s", err, out)
	}
	eventually(t, "the default of search.max_events applies again", func() bool { return rs.running().Search.MaxEvents == def })
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "server.node_url"}) })
	if err != nil || !strings.Contains(out, "Reset server.node_url of this server's own settings") {
		t.Fatalf("reset of one of the server's own settings: %v\n%s", err, out)
	}
	if _, ok := nodeCfgOf(t, rs.os, rs).Values["server.node_url"]; ok {
		t.Error("server.node_url is still in the nodecfg document")
	}
	if _, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "search.max_events"}) }); err == nil {
		t.Error("a second reset of the same setting did not say nothing was reset")
	}
}

// A shared setting that needs a restart, changed in signalith.yaml, is
// applied to the shared value before the restart loads the
// configuration, so it is in use after that restart, not only after the
// next one.
func TestFileChangeAppliesAtRestart(t *testing.T) {
	fastSharedCheck(t)
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a", extra: "syslog:\n  allow: [10.1.0.0/16]\n"})
	a.settingsShared()
	eventually(t, "A's files are recorded in the shared settings", func() bool {
		nc, _ := a.r.shared.NodeCfg().Get()
		return nc != nil && nc.SettingsApplied != ""
	})
	path := filepath.Join(a.dir, "signalith.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "10.1.0.0/16", "10.2.0.0/16", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, res := a.restart(); !res.OK {
		t.Fatalf("restart: %+v", res)
	}
	if got := a.running().Syslog.Allow; !slices.Equal(got, []string{"10.2.0.0/16"}) {
		t.Errorf("A runs syslog.allow %v after the restart", got)
	}
	if !strings.Contains(a.logs.String(), "syslog.allow applied from signalith.yaml on siem-a") {
		t.Errorf("not audited:\n%s", a.logs.String())
	}
}
