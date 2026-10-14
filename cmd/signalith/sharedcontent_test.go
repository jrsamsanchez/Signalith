package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// sharedBody reads the body of a shared document straight from the fake.
func sharedBody(t *testing.T, fos *ostest.Server, id string, v any) bool {
	t.Helper()
	src := fos.Source(shared.ConfigIndex("signalith"), id)
	if src == nil {
		return false
	}
	body, _ := src["body"].(string)
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return true
}

// leaseFingerprints is the files fingerprint the job lease carries.
func leaseFingerprints(fos *ostest.Server) map[string]any {
	l := fos.Source("signalith_runtime", "lease:jobs")
	fp, _ := l["fingerprints"].(map[string]any)
	return fp
}

// giveKey hands the next server started the cluster key of rs, in a key
// file, as SIGNALITH_CLUSTER_KEY_FILE does.
func giveKey(t *testing.T, rs *running) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.key")
	if err := os.WriteFile(path, []byte(rs.r.shared.Hub().Keys().Active().Text()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(clusterKeyFileEnv, path)
}

// U23 and U28: the founder's lease moves to the shared sentinel; a
// retention change on B, which does not run the jobs, is applied by A,
// the leader, through a request; and B, a member, takes the jobs over
// when A stops.
func TestSharedContentAcrossServers(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a", extra: "retention:\n  days: 30\nintel:\n  allow_loopback_feeds: true\n"})
	eventually(t, "A founds the cluster and takes its content from it", func() bool {
		return a.r.sharedContent.on.Load() && a.r.node.RunsJobs()
	})
	sentinel := cluster.SharedFingerprint(a.r.shared.Status().ClusterID)
	eventually(t, "the lease carries the shared fingerprint", func() bool {
		fp := leaseFingerprints(fos)
		return fp["retention"] == sentinel && fp["feeds"] == sentinel
	})
	var ret clustercfg.RetentionBody
	if !sharedBody(t, fos, clustercfg.RetentionID, &ret) || ret.Days == nil || *ret.Days != 30 || ret.Confirm != nil {
		t.Fatalf("imported retention %+v", ret)
	}

	giveKey(t, a)
	b := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b", extra: "retention:\n  days: 45\nintel:\n  allow_loopback_feeds: true\n"})
	eventually(t, "B joins and takes its content from the cluster", func() bool { return b.r.sharedContent.on.Load() })
	if b.r.node.RunsJobs() {
		t.Fatal("B runs the jobs")
	}
	// B's signalith.yaml says 45 at its first start as a member: that is
	// drift, not a change. So is its admin password hash, made for the
	// same password with another salt than A's, which the cluster uses.
	eventually(t, "B's heartbeat names the drift", func() bool {
		hb := fos.Source("signalith_runtime", "node:"+b.r.node.ID())
		d, _ := hb["settings_drift"].(map[string]any)
		return fmt.Sprint(d["yaml"]) == "[retention.days auth.admin_password_hash]"
	})

	b.signIn()
	code, out, err := b.call("", "GET", "/api/retention", "")
	if err != nil || code != 200 {
		t.Fatalf("overview on B: %d %v %v", code, out, err)
	}
	if def, _ := out["default"].(map[string]any); def == nil || def["editable"] != true {
		t.Fatalf("B cannot edit the shared policies: %v", out["default"])
	}
	// A change with a stale version is refused.
	code, _, _ = b.callWith("PUT", "/api/retention/default", `{"keep_days":3}`, map[string]string{"If-Match": `"stale"`})
	if code != 412 {
		t.Fatalf("stale If-Match: %d", code)
	}
	code, out, _ = b.call("", "PUT", "/api/retention/default", `{"keep_days":3}`)
	id, _ := out["request_id"].(string)
	if code != 200 || id == "" {
		t.Fatalf("change on B: %d %v", code, out)
	}
	var req map[string]any
	eventually(t, "A runs retention for B's change", func() bool {
		code, req, _ = b.call("", "GET", "/api/requests/"+id, "")
		return code == 200 && req["state"] == shared.RequestDone
	})
	if req["claimed_by"] != a.r.node.ID() || req["type"] != clustercfg.RequestRetentionRun {
		t.Fatalf("request %v", req)
	}
	a.signIn()
	eventually(t, "A enforces the policy changed on B", func() bool {
		code, out, _ := a.call("", "GET", "/api/retention", "")
		def, _ := out["default"].(map[string]any)
		pol, _ := def["policy"].(map[string]any)
		return code == 200 && pol["keep_days"] == float64(3)
	})
	eventually(t, "A ran retention for the change", func() bool {
		_, out, _ := a.call("", "GET", "/api/retention", "")
		last, _ := out["last_run"].(map[string]any)
		return last != nil && last["trigger"] == "policy_change"
	})
	// Run now on B asks A as well.
	code, out, _ = b.call("", "POST", "/api/retention/run", "")
	if code != 202 || out["request_id"] == nil {
		t.Fatalf("run on B: %d %v", code, out)
	}

	// A feed added on B is downloaded by A; Refresh on B asks A.
	var hits atomic.Int64
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("203.0.113.9\n"))
	}))
	defer feed.Close()
	code, out, _ = b.call("", "POST", "/api/intel/feeds", `{"name":"blocklist","url":"`+feed.URL+`","format":"lines","type":"ip","interval":"24h"}`)
	if code != 200 {
		t.Fatalf("add a feed on B: %d %v", code, out)
	}
	eventually(t, "A downloads the feed added on B", func() bool { return hits.Load() == 1 })
	code, out, _ = b.call("", "POST", "/api/intel/feeds/blocklist/refresh", "")
	id, _ = out["request_id"].(string)
	if code != 202 || id == "" {
		t.Fatalf("refresh on B: %d %v", code, out)
	}
	eventually(t, "A downloads it again for B", func() bool {
		code, req, _ = b.call("", "GET", "/api/requests/"+id, "")
		return code == 200 && req["state"] == shared.RequestDone
	})
	if hits.Load() != 2 {
		t.Errorf("%d downloads, want 2", hits.Load())
	}
	// Each feed's version, and a change made with a stale one.
	code, out, _ = b.call("", "GET", "/api/intel/feeds", "")
	etags, _ := out["etags"].(map[string]any)
	tag, _ := etags["blocklist"].(string)
	if code != 200 || tag == "" || out["manage"] != true || out["shared"] != true {
		t.Fatalf("feeds on B: %d %v", code, out)
	}
	code, _, _ = b.callWith("PUT", "/api/intel/feeds/blocklist", `{"description":"x"}`, map[string]string{"If-Match": `"f-stale"`})
	if code != 412 {
		t.Fatalf("stale feed change: %d", code)
	}
	code, _, _ = b.callWith("PUT", "/api/intel/feeds/blocklist", `{"description":"x"}`, map[string]string{"If-Match": tag})
	if code != 200 {
		t.Fatalf("feed change: %d", code)
	}

	// A stops: B, a member with the same shared fingerprint, takes over.
	a.stop()
	eventually(t, "B takes the jobs over", b.r.node.RunsJobs)
}

// U24: a server that does not run the background jobs, upgraded first,
// does not found the cluster; the one that does founds it with its own
// retention policies, which wait to be confirmed because the first
// server's own policies differ.
func TestFoundingWaitsForConfirmation(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	b := startRunnerWith(t, runOptions{server: plainHTTP, os: fos, name: "siem-b", extra: "retention:\n  days: 45\n"})
	eventually(t, "B's heartbeat with its retention fingerprint", func() bool {
		hb := fos.Source("signalith_runtime", "node:"+b.r.node.ID())
		fp, _ := hb["files_fingerprint"].(map[string]any)
		return fp["retention"] != nil && fp["retention"] != ""
	})
	if m, _ := b.r.shared.Mode(); m == shared.ModeMember || fos.Source(shared.ConfigIndex("signalith"), shared.ClusterDocID) != nil {
		t.Fatalf("a server that does not run the jobs founded the cluster (%s)", m)
	}
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a", extra: "retention:\n  days: 30\n"})
	eventually(t, "A founds the cluster", func() bool { return a.r.sharedContent.on.Load() })
	var ret clustercfg.RetentionBody
	if !sharedBody(t, fos, clustercfg.RetentionID, &ret) || ret.Confirm == nil || ret.Confirm.Servers["siem-b"] == "" {
		t.Fatalf("retention after founding %+v", ret)
	}
	a.signIn()
	code, out, _ := a.call("", "GET", "/api/retention", "")
	if hold, _ := out["hold"].(map[string]any); code != 200 || hold == nil || !strings.Contains(fmt.Sprint(hold["reason"]), "siem-b") {
		t.Fatalf("overview on A: %d %v", code, out["hold"])
	}
	code, out, _ = a.call("", "POST", "/api/retention/policies/confirm", "")
	if code != 200 || out["confirmed"] != true {
		t.Fatalf("confirm: %d %v", code, out)
	}
	if code, _, _ = a.call("", "POST", "/api/retention/policies/confirm", ""); code != 409 {
		t.Fatalf("second confirm: %d", code)
	}
	if !sharedBody(t, fos, clustercfg.RetentionID, &ret) || ret.Confirm != nil {
		t.Fatalf("still held %+v", ret.Confirm)
	}
	// B keeps working from its own files: it has no key.
	if m, _ := b.r.shared.Mode(); !m.Legacy() || b.r.sharedContent.on.Load() {
		t.Fatalf("B: %s, shared %v", m, b.r.sharedContent.on.Load())
	}
}

// U25: OpenSearch cannot be reached at the start and there is no copy:
// the server serves from its files (legacy a). When OpenSearch answers,
// it founds the cluster and switches to the shared content with a
// restart in place, keeping the job lease.
func TestSwitchToMemberAfterOutage(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	down := ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
	fos.SetFault(func(string, string) *ostest.Fault { return &down })
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a"})
	if m, _ := rs.r.shared.Mode(); m != shared.ModeLegacyA || rs.r.sharedContent.on.Load() {
		t.Fatalf("mode %s, shared %v", m, rs.r.sharedContent.on.Load())
	}
	fos.SetFault(nil)
	eventually(t, "the server runs the jobs", rs.r.node.RunsJobs)
	epoch := rs.r.node.Lease().Epoch()
	eventually(t, "it founds and switches with a restart in place", func() bool {
		return rs.r.sharedContent.on.Load() && strings.Contains(rs.logs.String(), `msg="restarted in place"`)
	})
	if !rs.r.node.RunsJobs() || rs.r.node.Lease().Epoch() != epoch {
		t.Errorf("the lease changed: runs %v epoch %d (was %d)", rs.r.node.RunsJobs(), rs.r.node.Lease().Epoch(), epoch)
	}
	if n := strings.Count(rs.logs.String(), `msg="restarted in place"`); n != 1 {
		t.Errorf("%d restarts in place", n)
	}
}

// callWith is call with request headers.
func (rs *running) callWith(method, path, body string, headers map[string]string) (int, map[string]any, error) {
	rs.t.Helper()
	req, _ := http.NewRequest(method, rs.scheme+"://"+rs.addr+path, strings.NewReader(body))
	req.Header.Set("Cookie", rs.cookie)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := rs.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}
