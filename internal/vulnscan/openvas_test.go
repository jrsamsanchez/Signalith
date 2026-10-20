// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

const gmpReport = `<get_reports_response status="200" status_text="OK"><report id="r1"><report id="r1"><results>
<result id="a"><host>192.0.2.10<hostname>web-01.corp.example</hostname></host><port>443/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.117274"><name>Apache HTTP Server 2.4.49 Path Traversal</name><family>Web Servers</family>
<tags>cvss_base_vector=AV:N|summary=Apache 2.4.49 lets a path traversal read files.|solution_type=VendorFix</tags>
<solution type="VendorFix">Update to version 2.4.51 or later.</solution>
<refs><ref type="cve" id="CVE-2021-41773"/><ref type="url" id="https://httpd.apache.org"/></refs></nvt>
<severity>7.5</severity><qod><value>95</value></qod><description>Installed version: 2.4.49</description></result>
<result id="b"><host>192.0.2.10</host><port>general/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.10001"><name>Weak SSH host key</name><tags>summary=The host key is short.</tags><refs/></nvt>
<severity>5.0</severity><qod><value>80</value></qod></result>
<result id="c"><host>192.0.2.99</host><port>21/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.10002"><name>Anonymous FTP</name><tags>summary=Anyone can sign in.</tags><refs/></nvt>
<severity>6.4</severity><qod><value>99</value></qod></result>
<result id="d"><host>192.0.2.99</host><port>21/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.10003"><name>Unsure guess</name><refs/></nvt>
<severity>9.0</severity><qod><value>30</value></qod></result>
</results></report></report></get_reports_response>`

// fakeGVMD answers GMP commands like gvmd, and notes them.
type fakeGVMD struct {
	mu       sync.Mutex
	commands []string
	raw      map[string]string // the last of each command, as sent
	creds    int
	polls    int
	password string
	noFeed   atomic.Bool // the feed is still loading
	drop     atomic.Bool // the connection breaks at the next get_tasks
	stopping int         // delete_task fails this many times: the task is still stopping
}

func (f *fakeGVMD) dial(context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	go f.serve(server)
	return client, nil
}

func (f *fakeGVMD) serve(c net.Conn) {
	defer c.Close()
	dec := xml.NewDecoder(c)
	for {
		var cmd struct {
			XMLName  xml.Name
			Password string     `xml:"credentials>password"`
			Filter   string     `xml:"filter,attr"`
			Attrs    []xml.Attr `xml:",any,attr"`
			Inner    string     `xml:",innerxml"`
		}
		if err := dec.Decode(&cmd); err != nil {
			return
		}
		name := cmd.XMLName.Local
		f.mu.Lock()
		f.commands = append(f.commands, name)
		if f.raw == nil {
			f.raw = map[string]string{}
		}
		f.raw[name] = cmd.Inner + fmt.Sprint(cmd.Attrs)
		f.creds += map[bool]int{true: 1}[name == "create_credential"]
		n := f.creds
		f.mu.Unlock()
		var out string
		left := func(tag, kind string) string {
			c := "<comment>" + scanComment + "</comment>"
			return fmt.Sprintf(`<get_%ss_response status="200" status_text="OK">`+
				`<%s id="%s-old"><name>Signalith Office LAN old1%s</name>%s</%s>`+
				`<%s id="%s-live"><name>Signalith Office LAN live1%s</name>%s</%s>`+
				`<%s id="%s-mine"><name>Signalith by hand</name><comment>Someone's own</comment></%s></get_%ss_response>`,
				tag, tag, tag, kind, c, tag, tag, tag, kind, c, tag, tag, tag, tag, tag)
		}
		switch {
		case cmd.Filter != "" && name == "get_tasks":
			out = left("task", "")
		case cmd.Filter != "" && name == "get_targets":
			out = left("target", "")
		case cmd.Filter != "" && name == "get_credentials":
			out = left("credential", " ssh")
		case name == "get_tasks" && f.drop.CompareAndSwap(true, false):
			return
		case name == "delete_task" && f.takeStopping():
			out = `<delete_task_response status="400" status_text="Task is still stopping"/>`
		}
		if out != "" {
			if _, err := io.WriteString(c, out); err != nil {
				return
			}
			continue
		}
		switch name {
		case "authenticate":
			if cmd.Password != f.password {
				out = `<authenticate_response status="400" status_text="Authentication failed"/>`
			} else {
				out = `<authenticate_response status="200" status_text="OK"><role>User</role></authenticate_response>`
			}
		case "get_version":
			out = `<get_version_response status="200" status_text="OK"><version>22.5</version></get_version_response>`
		case "create_credential":
			out = fmt.Sprintf(`<create_credential_response status="201" status_text="OK, resource created" id="c%d"/>`, n)
		case "create_target":
			out = `<create_target_response status="201" status_text="OK, resource created" id="t1"/>`
		case "create_task":
			out = `<create_task_response status="201" status_text="OK, resource created" id="k1"/>`
		case "start_task":
			out = `<start_task_response status="202" status_text="OK, request submitted"><report_id>r1</report_id></start_task_response>`
		case "get_tasks":
			f.mu.Lock()
			f.polls++
			done := f.polls > 1
			f.mu.Unlock()
			if done {
				out = `<get_tasks_response status="200" status_text="OK"><task id="k1"><status>Done</status><progress>-1</progress></task></get_tasks_response>`
			} else {
				out = `<get_tasks_response status="200" status_text="OK"><task id="k1"><status>Running</status><progress>40</progress></task></get_tasks_response>`
			}
		case "get_reports":
			out = gmpReport
		case "get_configs":
			if f.noFeed.Load() {
				out = `<get_configs_response status="404" status_text="Failed to find config 'daba56c8-73ec-11df-a475-002264764cea'"/>`
			} else {
				out = `<get_configs_response status="200" status_text="OK"><config id="daba56c8-73ec-11df-a475-002264764cea"><nvt_count>95870<growing>1</growing></nvt_count></config></get_configs_response>`
			}
		default:
			out = "<" + name + `_response status="200" status_text="OK"/>`
		}
		if _, err := io.WriteString(c, out); err != nil {
			return
		}
	}
}

func (f *fakeGVMD) takeStopping() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopping > 0 {
		f.stopping--
		return true
	}
	return false
}

func (f *fakeGVMD) sent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.commands, ",")
}

func TestOpenVASScan(t *testing.T) {
	f := &fakeGVMD{password: "pw"}
	ov := &OpenVAS{Address: "/run/gvmd/gvmd.sock", Username: "signalith", Password: "pw", Poll: time.Millisecond, Dial: f.dial}
	ctx := context.Background()
	if v, err := ov.Version(ctx); err != nil || v != "22.5" {
		t.Fatalf("version %q %v", v, err)
	}
	var progress []float64
	found, err := ov.Scan(ctx, target("192.0.2.0/24"), "Signalith test", ScanLogins{}, func(p float64) { progress = append(progress, p) })
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("found = %+v", found)
	}
	web := found[0]
	if web.Port != 443 || web.Transport != "tcp" || web.Vuln.CVE != "CVE-2021-41773" || web.Vuln.Severity != "high" || web.Vuln.Source != SourceOpenVAS ||
		web.Vuln.Solution != "Update to version 2.4.51 or later." || web.Vuln.Description != "Apache 2.4.49 lets a path traversal read files." {
		t.Errorf("web = %+v", web)
	}
	if found[1].Port != 0 || found[1].Vuln.CVE != "" || found[1].Vuln.Key() != "1.3.6.1.4.1.25623.1.0.10001" {
		t.Errorf("host finding = %+v", found[1])
	}
	if len(progress) == 0 || progress[0] != 40 {
		t.Errorf("progress = %v", progress)
	}
	// The task and target are removed after.
	// The task and target are removed after, on a connection of their own.
	if s := f.sent(); !strings.HasSuffix(s, "get_reports,authenticate,stop_task,delete_task,delete_target") {
		t.Errorf("commands = %s", s)
	}
	// With logins: made before the target, named in it, removed after it.
	ssh := &Login{Kind: LoginSSH, Username: "scan", Auth: AuthKey, Port: 2222, Secret: "-----BEGIN KEY-----", Passphrase: "phrase"}
	smb := &Login{Kind: LoginSMB, Username: `CORP\scan`, Auth: AuthPassword, Secret: "win-pass"}
	f.commands = nil
	f.polls = 0
	if _, err := ov.Scan(ctx, target("192.0.2.0/24"), "Signalith test", ScanLogins{SSH: ssh, SMB: smb}, nil); err != nil {
		t.Fatal(err)
	}
	if s := f.sent(); !strings.HasPrefix(s, "authenticate,get_configs,create_credential,create_credential,create_target,") ||
		!strings.HasSuffix(s, "delete_target,delete_credential,delete_credential") {
		t.Errorf("commands with logins = %s", s)
	}
	f.mu.Lock()
	tgt, cred := f.raw["create_target"], f.raw["create_credential"]
	f.mu.Unlock()
	if !strings.Contains(tgt, `<ssh_credential id="c1"><port>2222</port></ssh_credential>`) || !strings.Contains(tgt, `<smb_credential id="c2">`) {
		t.Errorf("target = %s", tgt)
	}
	if !strings.Contains(cred, "<type>up</type><login>CORP\\scan</login><password>win-pass</password>") {
		t.Errorf("windows login = %s", cred)
	}
	if fmt.Sprint(ssh) != "ssh login scan" || strings.Contains(fmt.Sprintf("%v %+v", ssh, smb), "pass") {
		t.Errorf("a login prints its secret: %v %+v", ssh, smb)
	}

	// ESXi and SNMPv3: their own slots in the target, SHA and AES, and
	// UDP 161 added to the ports so the SNMP checks run.
	esxi := &Login{Kind: LoginESXi, Username: "scan", Auth: AuthPassword, Secret: "esx-pass"}
	snmp := &Login{Kind: LoginSNMP, Username: "scan", Auth: AuthSNMPv3, Secret: "auth-pass", Privacy: "priv-pass"}
	f.commands, f.polls, f.creds = nil, 0, 0
	if _, err := ov.Scan(ctx, target("192.0.2.0/24"), "Signalith test", ScanLogins{ESXi: esxi, SNMP: snmp}, nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	tgt, cred = f.raw["create_target"], f.raw["create_credential"]
	f.mu.Unlock()
	if !strings.Contains(tgt, `<esxi_credential id="c1">`) || !strings.Contains(tgt, `<snmp_credential id="c2">`) ||
		!strings.Contains(tgt, `<port_list id="730ef368-57e2-11e1-a90f-406186ea4fc5">`) {
		t.Errorf("target with ESXi and SNMP = %s", tgt)
	}
	if !strings.Contains(cred, "<type>snmp</type><login>scan</login><password>auth-pass</password><auth_algorithm>sha1</auth_algorithm>"+
		"<privacy><algorithm>aes</algorithm><password>priv-pass</password></privacy>") {
		t.Errorf("SNMP login = %s", cred)
	}
	// A community, on a network with its own ports.
	ports := target("192.0.2.0/24")
	ports.Ports = "22,443"
	f.commands, f.polls, f.creds = nil, 0, 0
	if _, err := ov.Scan(ctx, ports, "Signalith test", ScanLogins{SNMP: &Login{Kind: LoginSNMP, Auth: AuthCommunity, Secret: "Xq7-long-random"}}, nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	tgt, cred = f.raw["create_target"], f.raw["create_credential"]
	f.mu.Unlock()
	if !strings.Contains(tgt, "<port_range>T:22,443,U:161</port_range>") || strings.Contains(tgt, "port_list") {
		t.Errorf("target with a community = %s", tgt)
	}
	if !strings.Contains(cred, "<type>snmp</type><community>Xq7-long-random</community>") || strings.Contains(cred, "<login") {
		t.Errorf("community login = %s", cred)
	}

	// The connection breaks mid-scan, and the task takes a moment to stop:
	// the logins are still removed, on a new connection.
	f.commands, f.polls, f.stopping = nil, 0, 2
	f.drop.Store(true)
	if _, err := ov.Scan(ctx, target("192.0.2.0/24"), "Signalith test", ScanLogins{SSH: ssh}, nil); err == nil || !strings.Contains(err.Error(), "closed the connection") {
		t.Errorf("a broken connection: %v", err)
	}
	if s := f.sent(); !strings.HasSuffix(s, "get_tasks,authenticate,stop_task,delete_task,delete_task,delete_task,delete_target,delete_credential") {
		t.Errorf("commands after a broken connection = %s", s)
	}

	// Sweep removes what ended scans left behind, and nothing else.
	f.commands, f.raw = nil, nil
	n, err := ov.Sweep(ctx, func(id string) bool { return id == "live1" })
	if err != nil || n != 3 {
		t.Fatalf("sweep = %d %v", n, err)
	}
	if s := f.sent(); !strings.HasSuffix(s, "get_tasks,get_targets,get_credentials,stop_task,delete_task,delete_target,delete_credential") {
		t.Errorf("sweep commands = %s", s)
	}
	f.mu.Lock()
	raw := fmt.Sprint(f.raw)
	f.mu.Unlock()
	if !strings.Contains(raw, "credential-old") || strings.Contains(raw, "live") || strings.Contains(raw, "mine") {
		t.Errorf("swept a live scan's or someone's own: %s", raw)
	}

	ov.Password = "wrong"
	if _, err := ov.Version(ctx); err == nil || !strings.Contains(err.Error(), "refused the user name or password") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestScanWithOpenVAS(t *testing.T) {
	var args []string
	s, ev := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	f := &fakeGVMD{password: "pw"}
	s.OpenVAS = &OpenVAS{Address: "/run/gvmd/gvmd.sock", Username: "signalith", Password: "pw", Poll: time.Millisecond, Dial: f.dial}
	ctx := context.Background()
	tg := target("192.0.2.0/24")
	tg.OpenVAS = true
	set, _ := s.Store.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice")
	sc, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, sc.ID)
	// Nmap's 2 hosts and OpenVAS's third; one high, two medium.
	if got.State != StateDone || got.OpenVASError != "" || got.Counts.Hosts != 3 || got.Counts.High != 1 || got.Counts.Medium != 2 {
		t.Fatalf("scan = %+v", got)
	}
	hosts, _ := s.Store.Hosts(ctx)
	var web *Host
	for _, h := range hosts {
		if h.Address == "192.0.2.10" {
			web = h
		}
	}
	if web == nil || len(web.Services) != 3 || web.Services[0].Port != 0 || len(web.Services[2].Vulns) != 1 {
		t.Fatalf("web host = %+v", web)
	}
	var hostEvent, ftp map[string]any
	for _, e := range ev.evs {
		switch e.Fields["signature_id"] {
		case "1.3.6.1.4.1.25623.1.0.10001":
			hostEvent = e.Fields
		case "1.3.6.1.4.1.25623.1.0.10002":
			ftp = e.Fields
		}
	}
	if hostEvent == nil || hostEvent["dest_port"] != nil || hostEvent["cve"] != nil || hostEvent["vuln_source"] != SourceOpenVAS || hostEvent["signature"] != "Weak SSH host key" {
		t.Errorf("host event = %v", hostEvent)
	}
	if ftp == nil || ftp["dest_port"] != 21 || ftp["severity"] != "medium" {
		t.Errorf("ftp event = %v", ftp)
	}

	// Not set up on this scanner: Nmap's results, and a note why.
	s.OpenVAS = nil
	sc2, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.Store.Scan(ctx, sc2.ID)
	if got.State != StateDone || got.Counts.Hosts != 2 || !strings.Contains(got.OpenVASError, "not set up") {
		t.Errorf("scan without OpenVAS = %+v", got)
	}
}

func TestOpenVASCheck(t *testing.T) {
	ctx := context.Background()
	tg := target("192.0.2.0/24")
	tg.OpenVAS = true
	c := &Checker{}
	if ck := c.openVASCheck(ctx, nil); ck.State != CheckInfo || len(ck.Fix) != 4 {
		t.Errorf("not set up = %+v", ck)
	}
	if ck := c.openVASCheck(ctx, []Target{tg}); ck.State != CheckWarn {
		t.Errorf("wanted but not set up = %+v", ck)
	}
	f := &fakeGVMD{password: "pw"}
	c.OpenVAS = &OpenVAS{Address: "/run/gvmd/gvmd.sock", Username: "signalith", Password: "pw", Dial: f.dial}
	if ck := c.openVASCheck(ctx, []Target{tg}); ck.State != CheckOK || !strings.Contains(ck.Detail, "GMP 22.5, 95870 tests") {
		t.Errorf("set up = %+v", ck)
	}
	f.noFeed.Store(true)
	if ck := c.openVASCheck(ctx, []Target{tg}); ck.State != CheckWarn || !strings.Contains(ck.Detail, "still loading") {
		t.Errorf("feed loading = %+v", ck)
	}
	if _, err := c.OpenVAS.Scan(ctx, tg, "x", ScanLogins{}, nil); !errors.Is(err, ErrFeedLoading) {
		t.Errorf("scan while the feed loads: %v", err)
	}
	if strings.Contains(f.sent(), "create_target") {
		t.Errorf("made a target while the feed loads: %s", f.sent())
	}
	f.noFeed.Store(false)
	c.OpenVAS.Password = "nope"
	if ck := c.openVASCheck(ctx, nil); ck.State != CheckWarn || ck.Required {
		t.Errorf("wrong password = %+v", ck)
	}
}

// FuzzOpenVASReport reads any report gvmd might send without crashing,
// and keeps only results with an address.
func FuzzOpenVASReport(f *testing.F) {
	f.Add([]byte(gmpReport))
	f.Add([]byte(`<get_reports_response status="200"><report><report><results><result><host>x</host><port>99999/udp</port><severity>NaN</severity></result></results></report></report></get_reports_response>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var rep gmpReports
		if xml.Unmarshal(b, &rep) != nil {
			return
		}
		for _, fd := range findings(rep.Results) {
			if fd.Address == "" || fd.Vuln.Severity == "" {
				t.Fatalf("bad finding %+v", fd)
			}
		}
	})
}
