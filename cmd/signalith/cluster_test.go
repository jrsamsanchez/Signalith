package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// eventually waits up to 20 seconds for ok.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An in-process restart keeps the job lease and its epoch, restarts the
// jobs under it, and never locks the state folder again.
func TestRestartKeepsTheJobLease(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true})
	node := rs.r.node
	eventually(t, "this server runs the jobs", node.RunsJobs)
	epoch := node.Lease().Epoch()
	// The server founds the cluster and restarts its components in place
	// to take their content from it: the jobs start a second time.
	eventually(t, "the detection scheduler starts with the shared settings", func() bool {
		return rs.r.sharedContent.on.Load() && strings.Count(rs.logs.String(), `msg="detection scheduler started"`) == 2
	})
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	eventually(t, "the jobs start again", func() bool {
		return strings.Count(rs.logs.String(), `msg="detection scheduler started"`) == 3
	})
	if !node.RunsJobs() || node.Lease().Epoch() != epoch || rs.r.node != node {
		t.Errorf("after the restart: runs %v epoch %d (was %d)", node.RunsJobs(), node.Lease().Epoch(), epoch)
	}
	lease := rs.os.Source("signalith_runtime", "lease:jobs")
	if lease["holder"] != node.ID() || fmt.Sprint(lease["epoch"]) != strconv.FormatInt(epoch, 10) {
		t.Errorf("lease %v", lease)
	}
	if l := rs.logs.String(); strings.Contains(l, "gave up the background jobs") || strings.Count(l, "now runs the background jobs") != 1 {
		t.Errorf("the lease changed hands:\n%s", l)
	}
	// The process still holds the state folder's lock, from its start.
	if _, err := cluster.OpenLocal(filepath.Dir(rs.r.path), cluster.LocalOptions{}); err == nil || !strings.Contains(err.Error(), "another Signalith process uses") {
		t.Errorf("open the state folder again: %v", err)
	}
}

// Stopping the server hands the jobs over at once and says it stopped.
func TestStopReleasesTheJobLease(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true})
	node := rs.r.node
	eventually(t, "this server runs the jobs", node.RunsJobs)
	rs.stop()
	lease := rs.os.Source("signalith_runtime", "lease:jobs")
	if lease["holder"] != "" || lease["released_by"] != node.ID() || lease["release_reason"] != "the server is stopping" {
		t.Errorf("lease after stop %v", lease)
	}
	if hb := rs.os.Source("signalith_runtime", "node:"+node.ID()); hb["state"] != cluster.StateStopped || hb["name"] != "siem-test" {
		t.Errorf("heartbeat after stop %v", hb)
	}
}

// A server with detections.scheduler off never takes the jobs.
func TestSchedulerOffNeverRunsTheJobs(t *testing.T) {
	rs := startRunner(t, nil, nil)
	eventually(t, "the first heartbeat", func() bool {
		return rs.os.Source("signalith_runtime", "node:"+rs.r.node.ID()) != nil
	})
	time.Sleep(300 * time.Millisecond)
	if rs.r.node.RunsJobs() || rs.os.Source("signalith_runtime", "lease:jobs") != nil {
		t.Error("a server with detections.scheduler off took the jobs")
	}
	if l := rs.logs.String(); strings.Contains(l, "detection scheduler started") {
		t.Errorf("the scheduler started:\n%s", l)
	}
	code, out, _ := rs.call("", "GET", "/api/cluster", "")
	servers, _ := out["servers"].([]any)
	if code != 200 || len(servers) != 1 {
		t.Fatalf("api/cluster %d %v", code, out)
	}
	if s := servers[0].(map[string]any); s["name"] != "siem-test" || s["jobs"] != "not_eligible" || s["self"] != true ||
		!strings.Contains(s["not_eligible"].(string), "detections.scheduler is off") {
		t.Errorf("this server %v", s)
	}
}

// Turning detections.scheduler off on the Settings page and restarting in
// place, while this server holds the job lease, starts no job with the new
// settings, even before the lease is given up in the background.
func TestSchedulerTurnedOffStartsNoJob(t *testing.T) {
	var mu sync.Mutex
	var started []string
	jobStarting = func(name string, c *config.Config) {
		mu.Lock()
		defer mu.Unlock()
		started = append(started, fmt.Sprintf("%s scheduler=%v", name, c.Detections.Scheduler))
	}
	t.Cleanup(func() { jobStarting = nil })
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	node := rs.r.node
	// The founding of the cluster, and the restarts that switch to the
	// shared settings, end before the settings are changed: this test is
	// about the jobs, not about a change made during that switch.
	rs.settingsShared()
	eventually(t, "this server runs the jobs", node.RunsJobs)
	eventually(t, "the jobs start", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(started) > 0
	})
	for range 3 {
		rs.save(`{"detections.scheduler":false}`)
		if _, res := rs.restart(); !res.OK {
			t.Fatalf("restart %+v\n%s", res, rs.logs.String())
		}
		eventually(t, "the jobs are given up", func() bool { return !node.RunsJobs() })
		rs.save(`{"detections.scheduler":true}`)
		if _, res := rs.restart(); !res.OK {
			t.Fatalf("restart %+v\n%s", res, rs.logs.String())
		}
		eventually(t, "this server runs the jobs again", node.RunsJobs)
	}
	rs.stop()
	mu.Lock()
	defer mu.Unlock()
	for _, s := range started {
		if strings.HasSuffix(s, "scheduler=false") {
			t.Errorf("a job started with detections.scheduler off: %v", started)
			break
		}
	}
}

// A server whose restart starts neither the new settings nor the previous
// ones tells the other servers so: its heartbeat says down, lists no
// syslog listeners (nothing listens on them) and names the problem, and it
// gives the jobs up. Once it starts again, it is ready and runs them.
func TestDownServerSaysSoInItsHeartbeat(t *testing.T) {
	var broken atomic.Bool
	downRetry = 200 * time.Millisecond
	t.Cleanup(func() { downRetry = 30 * time.Second })
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	syslogAddr := udp.LocalAddr().String()
	udp.Close()
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, page: map[string]any{"syslog.udp": syslogAddr},
		fail: func(*config.Config) error {
			if broken.Load() {
				return errors.New("broken on purpose")
			}
			return nil
		}})
	node := rs.r.node
	heartbeat := func() map[string]any { return rs.os.Source("signalith_runtime", "node:"+node.ID()) }
	listed := func(hb map[string]any) string {
		sl, _ := hb["syslog"].(map[string]any)
		s, _ := sl["udp"].(string)
		return s
	}
	eventually(t, "this server runs the jobs", node.RunsJobs)
	eventually(t, "the heartbeat lists the syslog listener", func() bool { return listed(heartbeat()) == syslogAddr })
	// The server founds the cluster and restarts its components in place
	// by itself; that restart is over before the next one is made to fail,
	// or it would be the one that fails and the server would be down
	// before the restart below is asked for.
	eventually(t, "the components take the shared content", func() bool {
		ct := rs.r.sharedContent
		return ct.on.Load() && ct.users.on.Load() == rs.r.shared.SharedUsers() && !rs.r.RestartStatus().InProgress
	})
	broken.Store(true)
	if _, res := rs.restart(); res.OK {
		t.Fatalf("restart worked: %+v", res)
	}
	eventually(t, "the heartbeat says down", func() bool {
		hb := heartbeat()
		return hb["state"] == cluster.StateDown && listed(hb) == ""
	})
	eventually(t, "the jobs are given up", func() bool { return !node.RunsJobs() })
	if ok, why := node.Ready(); ok || why != cluster.NotReadyDown {
		t.Errorf("Ready: %v %q", ok, why)
	}
	if hb := heartbeat(); hb["listen"] != rs.addr || !strings.Contains(fmt.Sprint(hb["problems"]), "could not start") || hb["leader_eligible"] != false {
		t.Errorf("heartbeat while down: %v", hb)
	}
	// It starts again with the settings that work (the page's syslog.udp
	// was set aside as the likely cause).
	broken.Store(false)
	eventually(t, "the heartbeat says ready again", func() bool {
		hb := heartbeat()
		return hb["state"] == cluster.StateReady && !strings.Contains(fmt.Sprint(hb["problems"]), "could not start")
	})
	eventually(t, "this server runs the jobs again", node.RunsJobs)
}

// /livez and /readyz answer without signing in, and say nothing more than
// whether this server is alive and ready.
func TestProbes(t *testing.T) {
	rs := startRunner(t, nil, nil)
	get := func(path string) (int, map[string]any, http.Header) {
		resp, err := http.Get("http://" + rs.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %s", path, raw)
		}
		return resp.StatusCode, out, resp.Header
	}
	if code, out, h := get("/livez"); code != 200 || out["live"] != true || len(out) != 1 || h.Get("Cache-Control") != "no-store" {
		t.Errorf("livez %d %v", code, out)
	}
	eventually(t, "ready", func() bool { code, _, _ := get("/readyz"); return code == 200 })
	if code, out, _ := get("/readyz"); code != 200 || out["ready"] != true || len(out) != 1 {
		t.Errorf("readyz %d %v", code, out)
	}
	resp, err := http.Post("http://"+rs.addr+"/readyz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /readyz = %d", resp.StatusCode)
	}
}

// With HTTPS on, /livez and /readyz answer over HTTPS and over plain HTTP
// on the same port, where everything else is sent to HTTPS: a load
// balancer that checks over plain HTTP learns whether the server is ready
// instead of getting a redirect.
func TestProbesWithHTTPS(t *testing.T) {
	rs := startRunnerWith(t, runOptions{})
	if rs.scheme != "https" {
		t.Fatalf("HTTPS is off: %s", rs.scheme)
	}
	for _, c := range []struct {
		name   string
		client *http.Client
		base   string
	}{{"https", rs.client, "https://" + rs.addr}, {"plain", noFollow, "http://" + rs.addr}} {
		for _, path := range []string{"/livez", "/readyz"} {
			eventually(t, c.name+path, func() bool {
				resp, err := c.client.Get(c.base + path)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return resp.StatusCode == 200 && strings.Contains(string(raw), "true")
			})
		}
	}
	// Anything else over plain HTTP is still sent to HTTPS.
	resp, err := noFollow.Get("http://" + rs.addr + "/livez/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("plain /livez/x = %d", resp.StatusCode)
	}
}

func TestReadiness(t *testing.T) {
	f := &front{}
	if ok, why := f.readiness(); ok || why != "starting" {
		t.Errorf("before start: %v %s", ok, why)
	}
	f.resume(http.NotFoundHandler(), http.NotFoundHandler())
	if ok, why := f.readiness(); !ok || why != "" {
		t.Errorf("running: %v %s", ok, why)
	}
	f.ready = func() (bool, string) { return false, cluster.NotReadyOpenSearch }
	if ok, why := f.readiness(); ok || why != "opensearch" {
		t.Errorf("without OpenSearch: %v %s", ok, why)
	}
	f.pause(time.Millisecond)
	if ok, why := f.readiness(); ok || why != "restarting" {
		t.Errorf("restarting: %v %s", ok, why)
	}
	f.resume(downHandler, downHandler)
	if ok, why := f.readiness(); ok || why != "down" {
		t.Errorf("down: %v %s", ok, why)
	}
}

// The same detections copied to Windows, with CRLF line ends and a byte
// order mark, have the same fingerprint; a real change does not.
func TestDetectionsFingerprintIgnoresLineEnds(t *testing.T) {
	unix, win := t.TempDir(), t.TempDir()
	rule := "id: brute\ntitle: Brute force\nquery: event.action=failed | stats count by user\n"
	if err := os.WriteFile(filepath.Join(unix, "brute.yaml"), []byte(rule), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(win, "brute.yaml"), []byte("\ufeff"+strings.ReplaceAll(rule, "\n", "\r\n")), 0o666); err != nil {
		t.Fatal(err)
	}
	if a, b := detectionsFingerprint(unix), detectionsFingerprint(win); a != b {
		t.Errorf("line ends change the fingerprint: %s %s", a, b)
	}
	if err := os.WriteFile(filepath.Join(win, "brute.yaml"), []byte(strings.Replace(rule, "Brute", "Brutal", 1)), 0o666); err != nil {
		t.Fatal(err)
	}
	if detectionsFingerprint(unix) == detectionsFingerprint(win) {
		t.Error("a changed rule has the same fingerprint")
	}
}

// U26: the server that runs the background jobs founds the cluster; an
// in-process restart keeps the shared settings' runtime, its watcher (not
// started twice) and cache.enc, and the server stays a member.
func TestRestartKeepsTheSharedSettings(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rt := rs.r.shared
	eventually(t, "the server founds the cluster", func() bool { m, _ := rt.Mode(); return m == shared.ModeMember })
	id := rt.Status().ClusterID
	cache := shared.CachePath(rs.dir)
	eventually(t, "cache.enc is written", func() bool { _, err := os.Stat(cache); return err == nil })
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if rs.r.shared != rt {
		t.Fatal("the restart made a new runtime")
	}
	if m, why := rt.Mode(); m != shared.ModeMember || rt.Status().ClusterID != id {
		t.Errorf("after the restart: %s (%s), cluster %s (was %s)", m, why, rt.Status().ClusterID, id)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Errorf("cache.enc after the restart: %v", err)
	}
	l := rs.logs.String()
	if n := strings.Count(l, `msg="shared settings watcher started"`); n != 1 {
		t.Errorf("the watcher started %d times", n)
	}
	if n := strings.Count(l, `msg="founded the cluster`); n != 1 {
		t.Errorf("founded %d times:\n%s", n, l)
	}
	node := rs.r.node
	eventually(t, "the heartbeat says member", func() bool {
		hb := rs.os.Source("signalith_runtime", "node:"+node.ID())
		return hb["mode"] == string(shared.ModeMember) && hb["cluster_kid"] == rt.Status().ClusterKID
	})
	resp, err := http.Get("http://" + rs.addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/readyz = %d", resp.StatusCode)
	}
	if !node.RunsJobs() {
		t.Error("the member does not run the jobs")
	}
}

// A member whose components still take their content from its own files
// (the restart in place that switches them has not run yet) does not say
// it is a member in its heartbeat: its API would still refuse what a
// member allows, such as a feed added on a server that does not run the
// background jobs.
func TestHeartbeatSaysMemberOnceTheComponentsSwitched(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rt := rs.r.shared
	eventually(t, "the components take the shared content", func() bool {
		m, _ := rt.Mode()
		return m == shared.ModeMember && rs.r.sharedContent.on.Load()
	})
	if got := sharedStatus(rt, rs.r.sharedContent).Mode; got != string(shared.ModeMember) {
		t.Errorf("switched: %q, want member", got)
	}
	// The same runtime, with components that have not switched yet.
	if got := sharedStatus(rt, &sharedContent{}).Mode; got != string(shared.ModeStarting) {
		t.Errorf("not switched yet: %q, want starting", got)
	}
}
