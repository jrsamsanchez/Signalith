// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// osvLog4j is Debian's record of Log4Shell, which CISA's catalog lists.
const osvLog4j = `{"id":"CVE-2021-44228","published":"2021-12-10T10:15:09Z","details":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
"affected":[{"package":{"name":"apache-log4j2","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.15.0-1"}]}]}]}`

type fakeInventory struct {
	mu    sync.Mutex
	hosts []*endpoint.HostPackages
	reads int
}

func (f *fakeInventory) HostPackages(ctx context.Context) ([]*endpoint.HostPackages, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.hosts, nil
}

func pkgHost(id, name, osName, osVersion string, at time.Time, pkgs ...endpoint.Package) *endpoint.HostPackages {
	return &endpoint.HostPackages{NodeID: id, Hostname: name, IPs: []string{"fe80::1", "192.0.2." + id[len(id)-1:]},
		PackageList: endpoint.PackageList{OS: osName, OSVersion: osVersion, At: at, Packages: pkgs}}
}

func TestPackageCheck(t *testing.T) {
	var hits sync.Map
	fail := atomic.Bool{}
	debian := osvZip(t, map[string]string{"CVE-2023-38408.json": osvDebianCVE, "DSA-5800-1.json": osvDebianDSA, "CVE-2021-44228.json": osvLog4j})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := hits.LoadOrStore(r.URL.Path, new(atomic.Int32))
		n.(*atomic.Int32).Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/osv/Debian:12/all.zip":
			w.Write(debian)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	count := func(path string) int32 {
		if n, ok := hits.Load(path); ok {
			return n.(*atomic.Int32).Load()
		}
		return 0
	}

	now := time.Now().UTC()
	clock := func() time.Time { return now }
	inv := &fakeInventory{hosts: []*endpoint.HostPackages{
		pkgHost("n1", "web1", "debian", "12.5", now.Add(-time.Hour),
			endpoint.Package{Name: "openssh-server", Version: "1:9.2p1-2+deb12u2", Source: "openssh", Type: "deb"},
			endpoint.Package{Name: "liblog4j2-java", Version: "2.14.1-1", Source: "apache-log4j2", Type: "deb"}),
		// Up to date.
		pkgHost("n2", "web2", "debian", "12.5", now.Add(-time.Hour),
			endpoint.Package{Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", Source: "openssh", Type: "deb"}),
		// A system with no advisories here, and a host gone quiet.
		pkgHost("n3", "amzn1", "amzn", "2023", now.Add(-time.Hour)),
		pkgHost("n4", "old1", "debian", "12.5", now.Add(-4*24*time.Hour),
			endpoint.Package{Name: "openssh-server", Version: "1:9.2p1-2", Source: "openssh", Type: "deb"}),
	}}
	ev := &events{}
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	p := NewPackageCheck(st, inv, srv.URL+"/osv/")
	p.Now, p.Events, p.Server, p.TempDir = clock, ev, "siem-a", t.TempDir()
	ctx := context.Background()
	x := builtInExploits()

	if err := p.Run(ctx, x); err != nil {
		t.Fatal(err)
	}
	if count("/osv/Debian:12/all.zip") != 1 {
		t.Errorf("downloads = %d", count("/osv/Debian:12/all.zip"))
	}
	hosts, err := st.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %+v", hosts)
	}
	h := hosts[0]
	if h.Hostname != "web1" || h.Address != "192.0.2.1" || h.TargetID != PackagesTarget || h.TargetName != PackagesTargetName || h.EndpointID != "n1" ||
		h.Counts.Critical != 2 || h.Counts.KEV != 1 || h.MaxCVSS != 10 || len(h.Services) != 2 {
		t.Fatalf("web1 = %+v", h)
	}
	if hosts[1].Hostname != "web2" || len(hosts[1].Services) != 0 {
		t.Errorf("web2 = %+v", hosts[1])
	}
	log4j := h.Services[0]
	if log4j.Product != "apache-log4j2" || log4j.Vulns[0].CVE != "CVE-2021-44228" || !log4j.Vulns[0].KEV || log4j.Vulns[0].Fixed != "2.15.0-1" {
		t.Errorf("log4j = %+v", log4j)
	}

	// Events like a scan's, one per CVE, marked as package matches.
	if len(ev.evs) != 3 {
		t.Fatalf("events = %d", len(ev.evs))
	}
	var kev map[string]any
	for _, e := range ev.evs {
		if e.Model != Model || e.Fields["category"] != CategoryVulnerability || e.Fields["vuln_confidence"] != ConfidencePackage ||
			e.Fields["vuln_source"] != SourcePackage || e.Fields["vendor_product"] != PackageVendorProduct || e.Fields["dest"] != "web1" ||
			e.Fields["dest_ip"] != "192.0.2.1" || e.Fields["endpoint_id"] != "n1" || e.Fields["vuln_distro"] != "Debian 12" || e.Fields["scan_network"] != PackagesTargetName {
			t.Errorf("event = %+v", e.Fields)
		}
		if _, ok := e.Fields["dest_port"]; ok {
			t.Errorf("a package event has a port: %+v", e.Fields)
		}
		if e.Fields["cve"] == "CVE-2021-44228" {
			kev = e.Fields
		}
	}
	if kev == nil || kev["known_exploited"] != "true" || kev["cvss"] != 10.0 || kev["product"] != "apache-log4j2" || kev["product_version"] != "2.14.1-1" ||
		kev["solution"] != "Upgrade apache-log4j2 to 2.15.0-1 or later" || kev["severity"] != "critical" {
		t.Errorf("log4j event = %+v", kev)
	}
	stat, err := p.Status(ctx)
	if err != nil || stat.Hosts != 2 || stat.Unsupported != 1 || stat.Feeds["Debian:12"].Count != 3 || stat.Feeds["Debian:12"].Error != "" {
		t.Errorf("status = %+v, %v", stat, err)
	}
	if !p.Active() {
		t.Error("not active with hosts checked")
	}

	// Within the hour nothing is read again.
	reads := inv.reads
	now = now.Add(30 * time.Minute)
	if err := p.Run(ctx, x); err != nil {
		t.Fatal(err)
	}
	if inv.reads != reads || len(ev.evs) != 3 {
		t.Errorf("ran again within the hour: %d reads, %d events", inv.reads-reads, len(ev.evs))
	}
	// An hour on, the hosts are checked again, but unchanged findings are
	// not written again within the day, and the advisories are not
	// downloaded again.
	now = now.Add(31 * time.Minute)
	if err := p.Run(ctx, x); err != nil {
		t.Fatal(err)
	}
	if inv.reads != reads+1 || len(ev.evs) != 3 || count("/osv/Debian:12/all.zip") != 1 {
		t.Errorf("hourly run: %d reads, %d events, %d downloads", inv.reads-reads, len(ev.evs), count("/osv/Debian:12/all.zip"))
	}
	// The host updates openssh: its findings change and are written.
	inv.mu.Lock()
	inv.hosts[0].Packages[0].Version = "1:9.2p1-2+deb12u3"
	inv.mu.Unlock()
	now = now.Add(time.Hour)
	if err := p.Run(ctx, x); err != nil {
		t.Fatal(err)
	}
	if len(ev.evs) != 4 {
		t.Errorf("events after the update = %d, want one more", len(ev.evs))
	}
	hosts, _ = st.Hosts(ctx)
	if hosts[0].Hostname != "web1" || len(hosts[0].Services) != 1 || hosts[0].Counts.Critical != 1 {
		t.Errorf("web1 after the update = %+v", hosts[0])
	}

	// A day on, with the advisories down, the last copy is used and the
	// error shows.
	fail.Store(true)
	now = now.Add(24 * time.Hour)
	if err := p.Run(ctx, x); err == nil {
		t.Error("no error while the advisories are down")
	}
	hosts, _ = st.Hosts(ctx)
	if len(hosts) != 2 || len(hosts[0].Services) != 1 {
		t.Errorf("hosts while down = %+v", hosts)
	}
	if stat, _ := p.Status(ctx); !strings.Contains(stat.Feeds["Debian:12"].Error, "502") {
		t.Errorf("status while down = %+v", stat)
	}
	ck := (&Checker{Packages: p}).packagesCheck(ctx, true)
	if ck.State != CheckWarn || !strings.Contains(ck.Detail, "2 hosts checked") || len(ck.Fix) == 0 {
		t.Errorf("check while down = %+v", ck)
	}

	// The hosts of a network removed from the scan settings go; these
	// stay.
	if err := st.DropHosts(ctx, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if hosts, _ = st.Hosts(ctx); len(hosts) != 2 {
		t.Errorf("DropHosts removed the package hosts: %d left", len(hosts))
	}

	// Off: nothing is downloaded and what was found goes.
	p.Set(OSVOff)
	if err := p.Run(ctx, x); err != nil {
		t.Fatal(err)
	}
	if hosts, _ = st.Hosts(ctx); len(hosts) != 0 {
		t.Errorf("hosts kept with the check off: %d", len(hosts))
	}
	if ck := (&Checker{Packages: p}).packagesCheck(ctx, true); ck.State != CheckInfo || !strings.Contains(ck.Detail, "off") {
		t.Errorf("check when off = %+v", ck)
	}
}

func TestPackageCheckFolderAndLimits(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Ubuntu_22.04_LTS"), 0o755); err != nil {
		t.Fatal(err)
	}
	z := osvZip(t, map[string]string{"UBUNTU-CVE-2023-38408.json": osvUbuntu})
	if err := os.WriteFile(filepath.Join(dir, "Ubuntu_22.04_LTS", "all.zip"), z, 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	inv := &fakeInventory{hosts: []*endpoint.HostPackages{pkgHost("n1", "u1", "ubuntu", "22.4", now,
		endpoint.Package{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.1", Source: "openssh", Type: "deb"})}}
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	p := NewPackageCheck(st, inv, "file://"+dir)
	ctx := context.Background()
	if err := p.Run(ctx, nil); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.Hosts(ctx)
	if len(hosts) != 1 || hosts[0].Counts.Medium != 1 || hosts[0].Services[0].Vulns[0].Ecosystem != "Ubuntu 22.04" {
		t.Fatalf("hosts = %+v", hosts)
	}

	// A download larger than the cap is refused.
	big := osvZip(t, map[string]string{"a.json": osvUbuntu, "b.json": strings.Repeat(" ", 4096) + osvUbuntu})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(big) }))
	defer srv.Close()
	old := maxOSVZip
	maxOSVZip = int64(len(big) - 1)
	defer func() { maxOSVZip = old }()
	e, _ := EcosystemFor("ubuntu", "22.4")
	if _, err := p.fetch(ctx, srv.URL, e); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized download = %v", err)
	}
	maxOSVZip = int64(len(big))
	if _, err := p.fetch(ctx, srv.URL, e); err != nil {
		t.Errorf("download at the cap = %v", err)
	}
}

func TestScannerRunsPackageCheck(t *testing.T) {
	var args []string
	s, ev := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Debian_12"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Debian_12", "all.zip"), osvZip(t, map[string]string{"a.json": osvLog4j}), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := &fakeInventory{hosts: []*endpoint.HostPackages{pkgHost("n1", "app1", "debian", "12", time.Now(),
		endpoint.Package{Name: "liblog4j2-java", Version: "2.14.1-1", Source: "apache-log4j2", Type: "deb"})}}
	s.Packages = NewPackageCheck(s.Store, inv, dir)
	s.Packages.Events = ev
	ctx := context.Background()
	// CVE lookups off: installed packages are not checked.
	if _, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{}, CVELookup: false}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if inv.reads != 0 {
		t.Error("checked with CVE lookups off")
	}
	set, _, _ := s.Store.Settings(ctx)
	set.CVELookup = true
	_, v, _ := s.Store.Settings(ctx)
	if _, err := s.Store.SaveSettings(ctx, set, v, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ev.evs) != 1 || ev.evs[0].Fields["cve"] != "CVE-2021-44228" {
		t.Fatalf("events = %+v", ev.evs)
	}
	// A server that does not run the background jobs never checks.
	s.Leader = func() bool { return false }
	inv.reads = 0
	s.Packages.lastRun = time.Time{}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if inv.reads != 0 {
		t.Error("checked on a server that does not run the jobs")
	}
}
