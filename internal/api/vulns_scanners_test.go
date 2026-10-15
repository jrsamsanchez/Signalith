package api

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// offlineCluster is fakeCluster, with siem-a stopped once off is set.
type offlineCluster struct {
	*fakeCluster
	off *atomic.Bool
}

func (o offlineCluster) Status() cluster.Status {
	st := o.fakeCluster.Status()
	if o.off.Load() {
		st.Servers[0].State = cluster.StateStopped
	}
	return st
}

// Each network names the server that scans it: only one of the servers
// can be picked, the Scanners page lists every server with the networks
// it scans and its own check, and Scan now refuses a stopped scanner.
func TestVulnScanners(t *testing.T) {
	st := vulnscan.NewStore(endpoint.NewMemoryDocs(), "signalith")
	sc := &vulnscan.Scanner{Store: st, Server: "siem-b", NodeID: "n_b", Leader: func() bool { return false },
		Checker: &vulnscan.Checker{FindNmap: func() string { return "" },
			Reach: func(_ context.Context, e string) vulnscan.Route {
				return vulnscan.Route{Entry: e, Direct: true, Iface: "eth1"}
			}}}
	off := &atomic.Bool{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = offlineCluster{&fakeCluster{holder: "siem-a"}, off}
		s.Vulns = &Vulns{Store: st, Scanner: sc}
	})
	code, out, _ := call(t, ts, "GET", "/api/vulns", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("vulns %d %v", code, out)
	}
	version := out["version"].(string)
	body := func(scanner string) string {
		return `{"version":"` + version + `","settings":{"cve_lookup":false,"targets":[{"id":"plant","name":"Plant floor","networks":["10.20.0.0/24"],` +
			`"ports":"top100","enabled":true,"schedule":{"every":"manual"},"scanner":"` + scanner + `"}]}}`
	}
	if code, out, _ = call(t, ts, "PUT", "/api/vulns/settings", body("n_nobody"), "admin", "s3cret-pass", nil); code != 400 {
		t.Fatalf("an unknown scanner: %d %v", code, out)
	}
	if code, out, _ = call(t, ts, "PUT", "/api/vulns/settings", body("n_b"), "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	servers := out["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("servers = %v", servers)
	}
	a, b := servers[0].(map[string]any), servers[1].(map[string]any)
	if a["name"] != "siem-a" || a["runs_jobs"] != true || len(a["networks"].([]any)) != 0 ||
		b["id"] != "n_b" || b["self"] != true || len(b["networks"].([]any)) != 1 || b["report"] != nil {
		t.Errorf("servers = %v", servers)
	}

	code, out, _ = call(t, ts, "GET", "/api/vulns/scanners?fresh=1", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("scanners %d %v", code, out)
	}
	b = out["servers"].([]any)[1].(map[string]any)
	rep, _ := b["report"].(map[string]any)
	if b["ready"] != false || rep == nil || rep["node_id"] != "n_b" {
		t.Fatalf("siem-b = %v", b)
	}
	found := false
	for _, c := range rep["checks"].([]any) {
		if c.(map[string]any)["id"] == "reach:plant" {
			found = true
		}
	}
	if !found {
		t.Errorf("no reach check: %v", rep["checks"])
	}

	// The network moves to siem-a, which then stops.
	_, out, _ = call(t, ts, "GET", "/api/vulns", "", "admin", "s3cret-pass", nil)
	version = out["version"].(string)
	if code, out, _ = call(t, ts, "PUT", "/api/vulns/settings", body("n_a"), "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("move %d %v", code, out)
	}
	off.Store(true)
	code, out, _ = call(t, ts, "POST", "/api/vulns/networks/plant/scan", "{}", "admin", "s3cret-pass", nil)
	if code != 409 {
		t.Errorf("scan on a stopped scanner: %d %v", code, out)
	}
}
