package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// enrolled is a store with two Linux hosts and a Windows one, web1
// passing the first Linux check and failing the second, web2 not checked
// yet, and win1 reporting an error.
func enrolled(t *testing.T, docs endpoint.Docs) (*endpoint.Store, []checks.Check) {
	t.Helper()
	ctx := context.Background()
	st := endpoint.NewStore(docs, "signalith")
	seen := time.Now().Add(-time.Minute).UTC()
	nodes := []*endpoint.Node{
		{ID: "n1", HostIdentifier: "uuid-1", Hostname: "web1", Platform: endpoint.Linux, EnrolledAt: seen, LastSeen: seen},
		{ID: "n2", HostIdentifier: "uuid-2", Platform: endpoint.Linux, EnrolledAt: seen, LastSeen: seen.Add(-time.Hour)},
		{ID: "n3", HostIdentifier: "uuid-3", Hostname: "win1", Platform: endpoint.Windows, EnrolledAt: seen, LastSeen: seen},
	}
	for _, n := range nodes {
		if err := st.Enroll(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	lx, win := checks.For(endpoint.Linux), checks.For(endpoint.Windows)
	if len(lx) < 3 || len(win) < 1 {
		t.Fatalf("checks: %d linux, %d windows", len(lx), len(win))
	}
	if err := st.SaveChecks(ctx, nodes[0], []endpoint.CheckResult{
		{ID: lx[0].ID, Result: "pass", At: seen}, {ID: lx[1].ID, Result: "fail", Detail: "PermitRootLogin yes", At: seen}, {ID: lx[2].ID, Result: "n/a", At: seen},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveChecks(ctx, nodes[2], []endpoint.CheckResult{{ID: win[0].ID, Result: "error", Detail: "query failed", At: seen}}); err != nil {
		t.Fatal(err)
	}
	return st, append(lx[:3:3], win[0])
}

// The checks page counts each check's results across the hosts of its
// platform and lists the hosts failing it; one host's page lists its own
// results, pending where it has not reported one.
func TestEndpointChecksPages(t *testing.T) {
	docs := newFailDocs()
	st, cs := enrolled(t, docs)
	ts, _ := newTestServerWith(t, func(s *Server) { s.Endpoints = st })
	code, out := do(t, ts, "GET", "/api/endpoints/checks", "", true)
	if code != http.StatusOK || out["hosts"] != float64(3) {
		t.Fatalf("checks %d %v", code, out["hosts"])
	}
	byID := map[string]map[string]any{}
	for _, c := range out["checks"].([]any) {
		m := c.(map[string]any)
		byID[m["id"].(string)] = m
	}
	counts := func(id string) map[string]any { return byID[id]["counts"].(map[string]any) }
	if c := counts(cs[0].ID); c["pass"] != float64(1) || c["pending"] != float64(1) {
		t.Errorf("%s counts %v", cs[0].ID, c)
	}
	fail := byID[cs[1].ID]
	if c := fail["counts"].(map[string]any); c["fail"] != float64(1) {
		t.Errorf("%s counts %v", cs[1].ID, c)
	}
	if f := fail["failing"].([]any); len(f) != 1 || f[0].(map[string]any)["hostname"] != "web1" || f[0].(map[string]any)["detail"] != "PermitRootLogin yes" {
		t.Errorf("failing %v", fail["failing"])
	}
	if c := counts(cs[3].ID); c["error"] != float64(1) {
		t.Errorf("windows counts %v", c)
	}
	tot := out["totals"].(map[string]any)
	if tot["pass"] != float64(1) || tot["fail"] != float64(1) || tot["n/a"] != float64(1) || tot["error"] != float64(1) {
		t.Errorf("totals %v", tot)
	}

	code, out = do(t, ts, "GET", "/api/endpoints/n1", "", true)
	if code != http.StatusOK || out["endpoint"].(map[string]any)["online"] != true {
		t.Fatalf("host %d %v", code, out)
	}
	results := map[string]string{}
	for _, c := range out["checks"].([]any) {
		m := c.(map[string]any)
		results[m["check"].(map[string]any)["id"].(string)] = m["result"].(string)
	}
	if len(results) != len(checks.For(endpoint.Linux)) || results[cs[0].ID] != "pass" || results[cs[1].ID] != "fail" || results[checks.For(endpoint.Linux)[3].ID] != "pending" {
		t.Errorf("results %v", results)
	}
	if code, out := do(t, ts, "GET", "/api/endpoints/n2", "", true); code != http.StatusOK || out["endpoint"].(map[string]any)["online"] != false {
		t.Errorf("an offline host %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/endpoints/nope", "", true); code != http.StatusNotFound {
		t.Errorf("a missing host %d", code)
	}

	// Reads that fail are a 502.
	for _, c := range []struct {
		fail func(string, string) error
		path string
	}{
		{failOn("search", `"node"`), "/api/endpoints/checks"},
		{failOn("search", `"checks"`), "/api/endpoints/checks"},
		{failOn("get", "chk:"), "/api/endpoints/n1"},
	} {
		docs.failing(c.fail)
		if code, _ := do(t, ts, "GET", c.path, "", true); code != http.StatusBadGateway {
			t.Errorf("%s with a failing store: %d", c.path, code)
		}
		docs.failing(nil)
	}
	if code, out := do(t, ts, "GET", "/api/endpoints/checks", "", true); code != http.StatusOK {
		t.Errorf("after: %d %v", code, out)
	}
}

// The compliance snapshot gathers each part that is set up: the hosts'
// configuration checks, vulnerability scans, notifications, response
// actions and playbooks, threat intel feeds, retention, users and asset
// lists.
func TestComplianceSnapshotParts(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	st, cs := enrolled(t, endpoint.NewMemoryDocs())
	vst := vulnscan.NewStore(endpoint.NewMemoryDocs(), "signalith")
	ctx := context.Background()
	sc, err := vst.NewScan(ctx, vulnscan.Target{ID: "office", Name: "Office"}, vulnscan.TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	finished := time.Now().Add(-2 * time.Hour).UTC()
	if err := vst.UpdateScan(ctx, sc.ID, map[string]any{"state": vulnscan.StateDone, "finished_at": finished}); err != nil {
		t.Fatal(err)
	}
	notes := &notify.Manager{}
	if _, err := notes.Save(notify.Input{Channels: []notify.ChannelInput{{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x"}}}); err != nil {
		t.Fatal(err)
	}
	feeds := &intel.Feeds{Store: intel.NewStore(intel.NewMemory()), File: filepath.Join(t.TempDir(), "intel_feeds.yaml"), List: []intel.Feed{
		{Name: "on", URL: "https://feeds.invalid/a.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true},
		{Name: "off", URL: "https://feeds.invalid/b.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1},
	}}
	var srv *Server
	newTestServerWith(t, func(s *Server) {
		srv = s
		s.Endpoints = st
		s.Vulns = &Vulns{Store: vst}
		s.Notify = &Notify{Settings: notes, Sender: &notify.Senders{}}
		s.Respond = &respond.Runner{Actions: &respond.Actions{File: filepath.Join(t.TempDir(), "response.yaml"), Log: s.Log}, Store: &respond.Memory{}, Log: s.Log}
		s.Playbooks = &Playbooks{Manager: &playbooks.Manager{}}
		s.Feeds = feeds
		s.Retention = &retention.Manager{Config: retention.Config{Default: &retention.Policy{KeepDays: 90},
			Policies: map[string]retention.Policy{"endpoint": {KeepDays: 30}, "network": {KeepDays: 30, Archive: true}}}}
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(ctx, users.NewUser{Username: "andy", Role: users.Analyst, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	snap := srv.complianceSnapshot(ctx, httptest.NewRequest("GET", "/api/compliance", nil))
	if snap.Hosts != 3 {
		t.Errorf("hosts %d", snap.Hosts)
	}
	stats := map[string]int{}
	for _, c := range snap.Checks {
		switch c.ID {
		case cs[0].ID:
			stats["pass"], stats["pending"] = c.Pass, c.Pending
		case cs[1].ID:
			stats["fail"] = c.Fail
			if len(c.Failing) != 1 || c.Failing[0].Hostname != "web1" {
				t.Errorf("failing %v", c.Failing)
			}
		case cs[2].ID:
			stats["na"] = c.NA
		case cs[3].ID:
			stats["error"] = c.Error
		}
	}
	if stats["pass"] != 1 || stats["pending"] != 1 || stats["fail"] != 1 || stats["na"] != 1 || stats["error"] != 1 {
		t.Errorf("check stats %v", stats)
	}
	if snap.Vulns == nil || !snap.Vulns.LastScan.Equal(finished) {
		t.Errorf("vulns %+v", snap.Vulns)
	}
	if snap.Notify == nil || snap.Notify.Channels != 1 || snap.Notify.Rules != 0 {
		t.Errorf("notify %+v", snap.Notify)
	}
	if snap.Response == nil || snap.Response.Actions != 0 || snap.Response.Playbooks != 0 {
		t.Errorf("response %+v", snap.Response)
	}
	if snap.Intel == nil || snap.Intel.Feeds != 1 || snap.Intel.Fresh != 0 {
		t.Errorf("intel %+v", snap.Intel)
	}
	if rt := snap.Retention; rt == nil || rt.KeepDays != 90 || len(rt.Shorter) != 1 || !strings.Contains(rt.Shorter[0], "(30 days)") {
		t.Errorf("retention %+v", snap.Retention)
	}
	if snap.Users == nil || snap.Users.Named != 1 || snap.Users.Directory {
		t.Errorf("users %+v", snap.Users)
	}
	if snap.Assets != 0 {
		t.Errorf("assets %d", snap.Assets)
	}
	if snap.Findings == nil || snap.Cases == nil {
		t.Errorf("findings %+v cases %+v", snap.Findings, snap.Cases)
	}

	// A store that cannot list the hosts leaves the checks out.
	docs := newFailDocs()
	docs.failing(failOn("search", `"node"`))
	srv.Endpoints = endpoint.NewStore(docs, "signalith")
	if snap := srv.complianceSnapshot(ctx, httptest.NewRequest("GET", "/api/compliance", nil)); snap.Checks != nil || snap.Hosts != 0 {
		t.Errorf("no hosts: %d %v", snap.Hosts, snap.Checks)
	}
	docs.failing(failOn("search", `"checks"`))
	if snap := srv.complianceSnapshot(ctx, httptest.NewRequest("GET", "/api/compliance", nil)); snap.Checks != nil {
		t.Errorf("no checks: %v", snap.Checks)
	}
}

func TestComplianceDataWithoutSearch(t *testing.T) {
	snap := &compliance.Snapshot{Data: map[string]compliance.DataSeen{}}
	(&Server{}).complianceData(context.Background(), snap)
	if snap.DataErr != "search is not available" {
		t.Errorf("DataErr %q", snap.DataErr)
	}
	for _, c := range []struct {
		v    any
		want float64
	}{{json.Number("12.5"), 12.5}, {" 7 ", 7}, {"x", 0}, {nil, 0}, {true, 0}, {3, 3}} {
		if got := cellNumber(c.v); got != c.want {
			t.Errorf("cellNumber(%#v) = %v, want %v", c.v, got, c.want)
		}
	}
}
