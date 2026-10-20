// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// Vulnerability scan results, as Signalith's own Nmap scans write them
// (internal/vulnscan): one Vulnerabilities event per open port, and one per
// CVE that applies to the software on it, all stamped with the scan's
// finish time and the scanner intake.
//
// The CVEs are real, with their real CVSS scores and CISA KEV status
// (with its due date and ransomware use), so the findings read like the
// ones a live scan raises. EPSS scores change every day: the ones here
// are round examples of the kind each CVE has, not today's. Unlike live events,
// the sample leaves out each CVE's NVD link (url), so the data names no
// real domain.

// scanServer is the Signalith server that runs the sample's scans.
const scanServer = "signalith-01"

// sampleVuln is one CVE a scan matched to a service.
type sampleVuln struct {
	cve      string
	cvss     float64
	kev      bool
	summary  string // first sentence of the NVD description
	severity string // from the CVSS score
	epss     float64
	epssPct  float64
	kevDue   string
}

// sampleService is one open port a scan found.
type sampleService struct {
	port    int
	app     string // the service as Nmap names it
	product string
	version string
	cpe     string
	vulns   []sampleVuln
}

var (
	cveApacheTraversal = sampleVuln{"CVE-2021-41773", 7.5, true, "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49", "high", 0.94, 0.999, "2021-11-17"}
	cveApacheRCE       = sampleVuln{"CVE-2021-42013", 9.8, true, "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient", "critical", 0.94, 0.999, "2021-11-17"}
	cveApacheSmuggling = sampleVuln{"CVE-2023-25690", 9.8, false, "Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack", "critical", 0.05, 0.89, ""}
	cveSSHAgent        = sampleVuln{"CVE-2023-38408", 9.8, false, "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system", "critical", 0.4, 0.97, ""}
	cveSCPInjection    = sampleVuln{"CVE-2020-15778", 7.8, false, "scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument", "high", 0.03, 0.86, ""}
)

const (
	cpeApache249 = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	cpeSSH82     = "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
)

// VulnTarget is the network the sample's scan results are kept under on
// the Vulnerabilities page (Data.VulnHosts).
const VulnTarget = vulnscan.SampleTarget

// vulnScanEvents writes one scan's results for hosts at t, and keeps them
// for the Vulnerabilities page too (vulnHost).
func (g *gen) vulnScanEvents(scanID, network string, hosts map[string][]sampleService, order []string, t time.Time) {
	for _, name := range order {
		h := g.org.host(name)
		g.vulnHosts = append(g.vulnHosts, vulnHost(scanID, network, h.Name, h.IP, hosts[name], t))
		for _, svc := range hosts[name] {
			const transport = "tcp"
			base := map[string]any{
				"host": scanServer, "sourcetype": "signalith:vulnscan", "vendor_product": "Signalith Nmap scan",
				"dest": h.Name, "dest_ip": h.IP, "dest_port": svc.port, "transport": transport,
				"scan_id": scanID, "scan_network": network, "app": svc.app,
			}
			what := svc.app
			if svc.product != "" {
				base["product"] = svc.product
				what = svc.product
				if svc.version != "" {
					base["product_version"] = svc.version
					what += " " + svc.version
				}
			}
			if svc.cpe != "" {
				base["cpe"] = svc.cpe
			}
			port := copyMap(base)
			port["category"] = "open_port"
			port["severity"] = "informational"
			port["signature"] = "Open port " + strconv.Itoa(svc.port) + "/" + transport + ": " + strings.TrimSpace(what)
			port["signature_id"] = transport + "/" + strconv.Itoa(svc.port)
			g.b.emit(ingest.Event{Time: t, Model: "Vulnerabilities", Fields: port, Origin: ingest.Origin{Intake: ingest.IntakeScanner}})
			for _, v := range svc.vulns {
				f := copyMap(base)
				f["category"] = "vulnerability"
				f["cve"] = v.cve
				f["signature_id"] = v.cve
				f["signature"] = v.cve + ": " + v.summary
				f["severity"] = v.severity
				f["cvss"] = v.cvss
				f["known_exploited"] = strconv.FormatBool(v.kev)
				if v.kev {
					// Both Apache CVEs are known to be used by ransomware gangs.
					f["known_ransomware"] = "true"
					f["kev_due"] = v.kevDue
				}
				f["epss"] = v.epss
				f["epss_percentile"] = v.epssPct
				g.b.emit(ingest.Event{Time: t, Model: "Vulnerabilities", Fields: f, Origin: ingest.Origin{Intake: ingest.IntakeScanner}})
			}
		}
	}
}

// vulnHost is a host the sample's scan found, as a real scan keeps it for
// the Vulnerabilities page.
func vulnHost(scanID, network, name, ip string, svcs []sampleService, t time.Time) *vulnscan.Host {
	h := &vulnscan.Host{ID: vulnscan.HostID(VulnTarget, ip), TargetID: VulnTarget, TargetName: network,
		Address: ip, Hostname: name, ScanID: scanID, FirstSeen: t, LastSeen: t, Services: []vulnscan.HostService{}}
	for _, svc := range svcs {
		hs := vulnscan.HostService{Service: vulnscan.Service{Port: svc.port, Transport: "tcp", Name: svc.app,
			Product: svc.product, Version: svc.version}}
		if svc.cpe != "" {
			hs.CPEs = []string{svc.cpe}
		}
		for _, v := range svc.vulns {
			vu := vulnscan.Vuln{CVE: v.cve, Description: v.summary, CVSS: v.cvss, CVSSVersion: "3.1", Severity: v.severity,
				KEV: v.kev, EPSS: v.epss, EPSSPercentile: v.epssPct, CPE: svc.cpe}
			if v.kev {
				vu.KEVDue, vu.Ransomware = v.kevDue, true
			}
			hs.Vulns = append(hs.Vulns, vu)
			switch vu.Severity {
			case "critical":
				h.Counts.Critical++
			case "high":
				h.Counts.High++
			case "medium":
				h.Counts.Medium++
			default:
				h.Counts.Low++
			}
			if vu.KEV {
				h.Counts.KEV++
			}
			if !vu.KEV && vu.EPSS >= vulnscan.LikelyEPSS {
				h.Counts.Likely++
			}
			h.MaxCVSS, h.MaxEPSS = max(h.MaxCVSS, vu.CVSS), max(h.MaxEPSS, vu.EPSS)
		}
		h.Services = append(h.Services, hs)
	}
	h.Counts.Hosts, h.Counts.Services = 1, len(h.Services)
	return h
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+8)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// vulnerabilityScan: the nightly scan of the server network finds an
// out-of-date Apache on the web server with two vulnerabilities attackers
// use (CISA KEV), a critical OpenSSH flaw on the application server, and
// Telnet left on next to SSH on the jump host. The domain controllers and
// the file server answer only on their usual Windows ports.
func (g *gen) vulnerabilityScan() {
	msrpc := sampleService{port: 135, app: "msrpc", product: "Microsoft Windows RPC"}
	smb := sampleService{port: 445, app: "microsoft-ds"}
	rdp := sampleService{port: 3389, app: "ms-wbt-server", product: "Microsoft Terminal Services"}
	dc := []sampleService{
		{port: 53, app: "domain", product: "Simple DNS Plus"},
		{port: 88, app: "kerberos-sec", product: "Microsoft Windows Kerberos"},
		msrpc,
		{port: 389, app: "ldap", product: "Microsoft Windows Active Directory LDAP"},
		smb, rdp,
	}
	hosts := map[string][]sampleService{
		"dc-01":   dc,
		"dc-02":   dc,
		"file-01": {msrpc, smb, rdp},
		"app-01": {
			{port: 22, app: "ssh", product: "OpenSSH", version: "8.2p1", cpe: cpeSSH82, vulns: []sampleVuln{cveSSHAgent, cveSCPInjection}},
			{port: 8080, app: "http", product: "Apache Tomcat"},
		},
		"web-01": {
			{port: 22, app: "ssh", product: "OpenSSH", version: "9.6p1"},
			{port: 443, app: "https", product: "Apache httpd", version: "2.4.49", cpe: cpeApache249,
				vulns: []sampleVuln{cveApacheTraversal, cveApacheRCE, cveApacheSmuggling}},
		},
		"db-01": {
			{port: 22, app: "ssh", product: "OpenSSH", version: "9.6p1"},
			{port: 5432, app: "postgresql", product: "PostgreSQL DB"},
		},
		"jump-01": {
			{port: 22, app: "ssh", product: "OpenSSH", version: "9.6p1"},
			{port: 23, app: "telnet", product: "Linux telnetd"},
		},
	}
	order := []string{"dc-01", "dc-02", "file-01", "app-01", "web-01", "db-01", "jump-01"}
	t := g.day(1, 2, 40)
	g.vulnScanEvents("scan-sample-servers", "Server network", hosts, order, t)
	g.story(Story{
		ID:    "vulnerability-scan",
		Title: "Nightly scan finds vulnerable servers",
		Summary: "Signalith's nightly vulnerability scan of the server network finds Apache httpd 2.4.49 on the web server web-01, with two vulnerabilities attackers are known to use " +
			"(CVE-2021-41773 and CVE-2021-42013, both in CISA's KEV catalog) and a critical request smuggling flaw (CVE-2023-25690). " +
			"web-01 is a high-priority server, so the known exploited ones are critical findings there. " +
			"OpenSSH 8.2p1 on app-01 has a critical ssh-agent flaw (CVE-2023-38408) that EPSS rates likely to be exploited, and the jump host jump-01 still answers on Telnet next to SSH.",
		Detections: []string{"vuln-known-exploited", "vuln-known-exploited-priority-asset", "vuln-likely-exploited", "vuln-critical", "vuln-cleartext-remote-login"},
	}, t.Add(time.Minute), "web-01", "app-01", "jump-01")
}
