//go:build integration && linux

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeNmap writes a script that answers like Nmap: its version, and a
// scan that finds one host with SSH open. Each scan's targets are noted
// in scanned.
func fakeNmap(t *testing.T, dir, host string) (path, scanned string) {
	t.Helper()
	path, scanned = filepath.Join(dir, "nmap"), filepath.Join(dir, "scanned.txt")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Nmap version 7.94 ( https://nmap.org )"; exit 0; fi
for last; do :; done
echo "$last" >> ` + scanned + `
cat <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="syn-ack"/><address addr="` + host + `" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port></ports></host>
<runstats><finished time="1760400100" elapsed="1" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
XML
`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, scanned
}

type vulnsView struct {
	Version string `json:"version"`
	Targets []struct {
		ID       string `json:"id"`
		LastScan *struct {
			State     string `json:"state"`
			Scanner   string `json:"scanner"`
			ScannerID string `json:"scanner_id"`
			Error     string `json:"error"`
		} `json:"last_scan"`
	} `json:"targets"`
	Hosts []struct {
		Address  string `json:"address"`
		TargetID string `json:"target_id"`
	} `json:"hosts"`
	Servers []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Networks []struct {
			ID string `json:"id"`
		} `json:"networks"`
		Ready *bool `json:"ready"`
	} `json:"servers"`
}

// A network names the server that scans it: that server, which does not
// run the background jobs, runs its scans, and the results show on every
// server. The server running the jobs scans the networks that name none.
func TestClusterZoneScanner(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	nmapA, scannedA := fakeNmap(t, filepath.Join(h.root, "nmap-a"), "192.0.2.10")
	nmapB, scannedB := fakeNmap(t, filepath.Join(h.root, "nmap-b"), "10.20.0.10")
	a := h.startLeader("siem-a", serverOptions{env: []string{"SIGNALITH_NMAP=" + nmapA}})
	b := h.start("siem-b", serverOptions{noJobs: true, env: []string{"SIGNALITH_NMAP=" + nmapB}})
	var nodeB string
	waitUntil(t, 45*time.Second, "both servers listed", func() bool {
		v, ok := a.view()
		if !ok || len(v.Servers) != 2 {
			return false
		}
		for _, sv := range v.Servers {
			if sv.Name == "siem-b" && sv.State == "ready" {
				nodeB = sv.NodeID
			}
		}
		return nodeB != ""
	})
	var v vulnsView
	if code := a.call("GET", "/api/vulns", nil, &v); code != 200 {
		t.Fatalf("GET /api/vulns: %d", code)
	}
	net := func(id, name, addr, scanner string) map[string]any {
		return map[string]any{"id": id, "name": name, "networks": []string{addr}, "ports": "22", "enabled": true,
			"schedule": map[string]any{"every": "manual"}, "scanner": scanner}
	}
	body := map[string]any{"version": v.Version, "settings": map[string]any{"cve_lookup": false, "targets": []any{
		net("office", "Office LAN", "192.0.2.10", ""), net("plant", "Plant floor", "10.20.0.10", nodeB)}}}
	if code := a.call("PUT", "/api/vulns/settings", body, &v); code != 200 {
		t.Fatalf("save: %d", code)
	}
	for _, id := range []string{"plant", "office"} {
		if code := a.call("POST", "/api/vulns/networks/"+id+"/scan", map[string]any{}, nil); code != 202 {
			t.Fatalf("scan %s: %d", id, code)
		}
	}
	done := func(v vulnsView, id string) (state, scanner string) {
		for _, tg := range v.Targets {
			if tg.ID == id && tg.LastScan != nil {
				return tg.LastScan.State, tg.LastScan.ScannerID
			}
		}
		return "", ""
	}
	waitUntil(t, 90*time.Second, "both networks scanned", func() bool {
		var got vulnsView
		if b.call("GET", "/api/vulns", nil, &got) != 200 {
			return false
		}
		sp, _ := done(got, "plant")
		so, _ := done(got, "office")
		return sp != "" && so != ""
	})
	var got vulnsView
	b.call("GET", "/api/vulns", nil, &got)
	if st, by := done(got, "plant"); st != "done" || by != nodeB {
		t.Errorf("plant: %s by %s, want done by siem-b (%s)", st, by, nodeB)
	}
	if st, by := done(got, "office"); st != "done" || by == nodeB {
		t.Errorf("office: %s by %s, want done by siem-a", st, by)
	}
	hosts := map[string]string{}
	for _, hst := range got.Hosts {
		hosts[hst.Address] = hst.TargetID
	}
	if hosts["10.20.0.10"] != "plant" || hosts["192.0.2.10"] != "office" {
		t.Errorf("hosts = %v", got.Hosts)
	}
	ra, _ := os.ReadFile(scannedA)
	rb, _ := os.ReadFile(scannedB)
	if strings.Contains(string(ra), "10.20.0.10") || !strings.Contains(string(rb), "10.20.0.10") || strings.Contains(string(rb), "192.0.2.10") {
		t.Errorf("siem-a scanned %q, siem-b scanned %q", ra, rb)
	}
	// Each server checks itself; the Scanners page lists both.
	waitUntil(t, 60*time.Second, "both servers checked themselves", func() bool {
		var sc vulnsView
		if a.call("GET", "/api/vulns/scanners", nil, &sc) != 200 || len(sc.Servers) != 2 {
			return false
		}
		for _, sv := range sc.Servers {
			if sv.Ready == nil || !*sv.Ready {
				return false
			}
			if sv.Name == "siem-b" && (len(sv.Networks) != 1 || sv.Networks[0].ID != "plant") {
				t.Fatalf("siem-b scans %v", sv.Networks)
			}
		}
		return true
	})
	// A scanner that is not one of the servers cannot be picked.
	a.call("GET", "/api/vulns", nil, &v)
	body["version"] = v.Version
	body["settings"].(map[string]any)["targets"] = []any{net("plant", "Plant floor", "10.20.0.10", "n_0000000000000000dead")}
	if code := a.call("PUT", "/api/vulns/settings", body, nil); code != 400 {
		t.Errorf("an unknown scanner saved: %d", code)
	}
}
