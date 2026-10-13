package sample

import (
	"fmt"
	"strings"
	"time"
)

// Antivirus events: Microsoft Defender through the Windows agent, ClamAV
// through the Linux agent, and an antivirus console's CEF through the
// syslog receiver. They run through the same parsers as live data and land
// in the Malware data model.
//
// Everything stays fictional and offline: no URLs in Defender messages, no
// update mirror names in freshclam lines, version numbers with a 4- or
// 5-digit group so none reads as an IPv4 address, and no test-file
// content anywhere, only the EICAR threat name.

// Defender message headers, as Windows renders them.
const (
	defHdrDetected = "Microsoft Defender Antivirus has detected malware or other potentially unwanted software."
	defHdrAction   = "Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software."
	defHdrFailed   = "Microsoft Defender Antivirus has encountered a non-critical error when taking action on malware or other potentially unwanted software."
	defHdrBlocked  = "Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator."
	defHdrCFA      = "Controlled Folder Access blocked an application from making changes to protected folders."
	defHdrUpdated  = "Microsoft Defender Antivirus security intelligence version updated."
	defHdrUpdFail  = "Microsoft Defender Antivirus has encountered an error trying to update security intelligence."
	defHdrConfig   = "Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware."
	defHdrTamper   = "Tamper protection blocked a change to Microsoft Defender Antivirus. If this is part of your organization's policy, no action is necessary. If this is not part of your organization's policy, contact your IT administrator."
)

// Sample Defender versions.
const (
	defEngine   = "1.1.24090.11"
	defPlatform = "4.18.24090.11"
)

// defenderMsg renders a Defender message: a header line, then one
// tab-indented "Label: value" line per pair.
func defenderMsg(header string, kv [][2]string) string {
	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	for _, p := range kv {
		fmt.Fprintf(&sb, " \t%s: %s\n", p[0], p[1])
	}
	return sb.String()
}

// threat is one malware find for a Defender threat event.
type threat struct {
	name, id, severity, category string
	path                         string // Defender resource, e.g. file:_C:\x.exe
	user                         string // DOMAIN\login
	process                      string // process that touched the file
	source                       string // detection source
}

// sigVersion is the Defender definitions version on a given day.
func sigVersion(day int) string { return fmt.Sprintf("1.419.%d.0", 2300+day) }

func (g *gen) threatPairs(th threat, t time.Time) [][2]string {
	src := th.source
	if src == "" {
		src = "Real-Time Protection"
	}
	proc := th.process
	if proc == "" {
		proc = "Unknown"
	}
	v := sigVersion(g.dayNum(t))
	return [][2]string{
		{"Name", th.name},
		{"ID", th.id},
		{"Severity", th.severity},
		{"Category", th.category},
		{"Path", th.path},
		{"Detection Origin", "Local machine"},
		{"Detection Type", "Concrete"},
		{"Detection Source", src},
		{"User", th.user},
		{"Process Name", proc},
		{"Security intelligence Version", "AV: " + v + ", AS: " + v + ", NIS: " + v},
		{"Engine Version", "AM: " + defEngine + ", NIS: " + defEngine},
	}
}

// defThreatFound writes a 1116: Defender found a threat.
func (g *gen) defThreatFound(h Host, th threat, t time.Time) {
	g.b.defender(h, "1116", t, defenderMsg(defHdrDetected, g.threatPairs(th, t)))
}

// defThreatAction writes a 1117: Defender acted on a threat (Quarantine,
// Remove, Clean, Allow).
func (g *gen) defThreatAction(h Host, th threat, action string, t time.Time) {
	kv := append(g.threatPairs(th, t), [2]string{"Action", action})
	g.b.defender(h, "1117", t, defenderMsg(defHdrAction, kv))
}

// defThreatFailed writes a 1118: Defender could not act on a threat.
func (g *gen) defThreatFailed(h Host, th threat, action, errText string, t time.Time) {
	kv := append(g.threatPairs(th, t),
		[2]string{"Action", action},
		[2]string{"Error Code", "0x80508023"},
		[2]string{"Error description", errText})
	g.b.defender(h, "1118", t, defenderMsg(defHdrFailed, kv))
}

// defASRBlock writes a 1121: an attack surface reduction rule blocked a
// process (proc) from starting or changing target.
func (g *gen) defASRBlock(h Host, guid, user, target, proc, cmdline string, t time.Time) {
	g.b.defender(h, "1121", t, defenderMsg(defHdrBlocked, [][2]string{
		{"ID", strings.ToUpper(guid)},
		{"Detection time", t.UTC().Format("2006-01-02T15:04:05.000Z")},
		{"User", user},
		{"Path", target},
		{"Process Name", proc},
		{"Target Commandline", cmdline},
		{"Security intelligence Version", sigVersion(g.dayNum(t))},
		{"Engine Version", defEngine},
		{"Product Version", defPlatform},
	}))
}

// defCFABlock writes a 1123: controlled folder access stopped proc from
// changing a protected file.
func (g *gen) defCFABlock(h Host, user, target, proc string, t time.Time) {
	g.b.defender(h, "1123", t, defenderMsg(defHdrCFA, [][2]string{
		{"Detection time", t.UTC().Format("2006-01-02T15:04:05.000Z")},
		{"User", user},
		{"Path", target},
		{"Process Name", proc},
		{"Security intelligence Version", sigVersion(g.dayNum(t))},
		{"Engine Version", defEngine},
		{"Product Version", defPlatform},
	}))
}

// defConfigChange writes a 5007: a Defender setting changed.
func (g *gen) defConfigChange(h Host, oldValue, newValue string, t time.Time) {
	g.b.defender(h, "5007", t, defenderMsg(defHdrConfig, [][2]string{
		{"Old value", oldValue},
		{"New value", newValue},
	}))
}

// defTamper writes a 5013: tamper protection blocked a change.
func (g *gen) defTamper(h Host, value string, t time.Time) {
	g.b.defender(h, "5013", t, defenderMsg(defHdrTamper, [][2]string{
		{"Feature Name", "Tamper Protection"},
		{"Value", value},
	}))
}

// defUpdated writes a 2000: new definitions installed.
func (g *gen) defUpdated(h Host, t time.Time) {
	day := g.dayNum(t)
	g.b.defender(h, "2000", t, defenderMsg(defHdrUpdated, [][2]string{
		{"Current security intelligence Version", sigVersion(day)},
		{"Previous security intelligence Version", sigVersion(day - 1)},
		{"Security intelligence Type", "AntiVirus"},
		{"Update Type", "Delta"},
		{"User", `NT AUTHORITY\SYSTEM`},
		{"Current Engine Version", defEngine},
		{"Previous Engine Version", defEngine},
	}))
}

// defUpdateFailed writes a 2001: a definitions update failed.
func (g *gen) defUpdateFailed(h Host, errText string, t time.Time) {
	day := g.dayNum(t)
	g.b.defender(h, "2001", t, defenderMsg(defHdrUpdFail, [][2]string{
		{"New security intelligence Version", sigVersion(day)},
		{"Previous security intelligence Version", sigVersion(day - 1)},
		{"Update Source", "Microsoft Update Server"},
		{"Security intelligence Type", "AntiVirus"},
		{"Update Type", "Delta"},
		{"User", `NT AUTHORITY\SYSTEM`},
		{"Current Engine Version", defEngine},
		{"Previous Engine Version", defEngine},
		{"Error code", "0x8024402c"},
		{"Error description", errText},
	}))
}

// clamLine writes a ClamAV daemon or freshclam line with its local-time
// prefix ("Tue Oct 13 13:12:40 2026 -> ").
func (g *gen) clamLine(h Host, file, text string, t time.Time) {
	g.b.clamav(h, file, t.UTC().Format("Mon Jan _2 15:04:05 2006")+" -> "+text, t)
}

const (
	clamdLog     = "/var/log/clamav/clamav.log"
	freshclamLog = "/var/log/clamav/freshclam.log"
)

// dayNum numbers the sample's days from its first (0) to its last (6), for
// definition versions that rise by one each day.
func (g *gen) dayNum(t time.Time) int {
	first := time.Date(g.start.Year(), g.start.Month(), g.start.Day(), 0, 0, 0, 0, time.UTC)
	return int(t.Sub(first) / (24 * time.Hour))
}

// antivirusBackground adds the daily routine of healthy antivirus: one
// definitions update per Windows host (Defender 2000) and one freshclam
// run per Linux host each day, at a fixed host-specific time. It takes no
// randomness, so the rest of the background is unchanged.
func (g *gen) antivirusBackground(days []window) {
	for _, day := range days {
		midnight := time.Date(day.start.Year(), day.start.Month(), day.start.Day(), 0, 0, 0, 0, time.UTC)
		for i, h := range g.org.windowsHosts() {
			t := midnight.Add(time.Duration(5+i%12)*time.Hour + time.Duration(7*i%60)*time.Minute)
			if t.Before(day.start) || t.After(day.end) {
				continue
			}
			g.defUpdated(h, t)
		}
		for i, h := range g.org.linuxHosts() {
			t := midnight.Add(time.Duration(3+i)*time.Hour + time.Duration(11*i%60)*time.Minute)
			if t.Before(day.start) || t.After(day.end) {
				continue
			}
			g.clamLine(h, freshclamLog, fmt.Sprintf("daily.cld updated (version: %d, sigs: 2070130, f-level: 90, builder: raynman)", 27400+g.dayNum(t)), t)
		}
	}
}

// winUserOn returns the DOMAIN\login of a host's usual user, never alice
// (whose findings belong to the phishing story's case).
func (g *gen) winUserOn(h Host) string {
	for _, u := range g.org.Users {
		if u.Login == "alice.nguyen" {
			continue
		}
		for _, hn := range u.Hosts {
			if hn == h.Name {
				return u.Winuser()
			}
		}
	}
	return g.org.userByLogin("olivia.okafor").Winuser()
}

// malwareOutbreak: a fake "payroll update" on the public file share is
// opened on four operations workstations. Defender quarantines it on three
// and fails to remove it on the fourth.
func (g *gen) malwareOutbreak() {
	t0 := g.day(3, 9, 40)
	hosts := []struct {
		name   string
		offset time.Duration
		failed bool
	}{
		{"ws-ops-01", 0, false},
		{"ws-ops-03", 4 * time.Minute, false},
		{"ws-ops-04", 9 * time.Minute, false},
		{"ws-ops-05", 13 * time.Minute, true},
	}
	entities := []string{}
	var last time.Time
	for _, x := range hosts {
		h := g.org.host(x.name)
		th := threat{
			name: "Trojan:Win32/Fakepay.A", id: "2147812345", severity: "High", category: "Trojan",
			path: `file:_\\file-01\public\Payroll_Update.exe`, user: g.winUserOn(h),
			process: `C:\Windows\explorer.exe`,
		}
		t := t0.Add(x.offset)
		g.defThreatFound(h, th, t)
		if x.failed {
			g.defThreatFailed(h, th, "Quarantine", "Access is denied.", t.Add(20*time.Second))
		} else {
			g.defThreatAction(h, th, "Quarantine", t.Add(20*time.Second))
		}
		entities = append(entities, x.name)
		last = t.Add(20 * time.Second)
	}
	g.story(Story{
		ID:    "malware-outbreak",
		Title: "Trojan spreads from a file share",
		Summary: `A fake payroll update (Trojan:Win32/Fakepay.A) on the public share \\file-01\public is opened on four operations workstations within 15 minutes: ws-ops-01, ws-ops-03, ws-ops-04 and ws-ops-05. ` +
			"Microsoft Defender quarantines it on the first three but cannot remove it on ws-ops-05. The same threat on several hosts points to the share it spreads from.",
		Detections: []string{"malware-detected", "malware-outbreak", "malware-not-removed"},
	}, last.Add(time.Minute), entities...)
}

// antivirusHousekeeping: the everyday antivirus problems a SOC also sees.
// Definitions stop updating on a Linux web server and a workstation, and
// IT tests Defender with the EICAR test file, a finding to close as benign.
func (g *gen) antivirusHousekeeping() {
	web := g.org.host("web-01")
	for _, h := range []int{6, 7} {
		g.clamLine(web, freshclamLog, "ERROR: Database update process failed: Connection failed (2)", g.day(5, h, 0))
	}
	ops := g.org.host("ws-ops-02")
	for _, h := range []int{8, 12} {
		g.defUpdateFailed(ops, "The client could not connect to the update source.", g.day(5, h, 15))
	}

	// ClamAV's nightly scan on app-01 finds a web shell in an upload
	// folder. clamd is only set to report, so the file stays on disk.
	app := g.org.host("app-01")
	g.clamLine(app, clamdLog, "/opt/app/uploads/avatar.php: Php.Webshell.Sample-1 FOUND", g.day(5, 2, 40))

	itws := g.org.host("ws-it-02")
	bob := g.org.userByLogin("bob.okafor")
	eicar := threat{
		name: "Virus:DOS/EICAR_Test_File", id: "2147519003", severity: "Severe", category: "Virus",
		path: `file:_C:\Users\bob.okafor\Downloads\eicar.com`, user: bob.Winuser(),
		process: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
	}
	te := g.day(5, 10, 30)
	g.defThreatFound(itws, eicar, te)
	g.defThreatAction(itws, eicar, "Remove", te.Add(15*time.Second))
	end := g.day(5, 12, 16)

	// A console-managed fleet too: Trend Micro Apex One quarantines a
	// bundled toolbar on an IT workstation (standard size only).
	if g.size != SizeSmall {
		h := g.org.host("ws-it-04")
		login := strings.TrimPrefix(g.winUserOn(h), NetBIOS+`\`)
		tt := g.day(5, 14, 5)
		g.b.cefAV("198.51.100.25", tt, "Trend Micro", "Apex Central", "2019", "AV:PUA_SampleToolbar", "PUA_SampleToolbar", "3", map[string]string{
			"act":              "Quarantined",
			"dhost":            h.Name,
			"dst":              h.IP,
			"duser":            NetBIOS + `\` + login,
			"filePath":         `C:\Users\` + login + `\Downloads\`,
			"fname":            "toolbar_setup.exe",
			"cs3Label":         "Virus_Malware_Name",
			"cs3":              "PUA_SampleToolbar",
			"cs6Label":         "TaskName",
			"cs6":              "Real-time Scan",
			"deviceExternalId": "7",
		})
		if tt.After(end) {
			end = tt
		}
	}

	g.story(Story{
		ID:    "antivirus-housekeeping",
		Title: "Antivirus upkeep",
		Summary: "Everyday antivirus problems: definitions stop updating on two hosts (ClamAV on web-01 cannot reach its update server, and Microsoft Defender on ws-ops-02 cannot reach the update source), so new malware would go unnoticed there. " +
			"ClamAV's nightly scan on app-01 finds a web shell in an upload folder, but ClamAV is only set to report, so the file stays on disk until someone removes it. " +
			"IT also tests Defender with the EICAR test file on ws-it-02, which raises a finding to close as benign.",
		Detections: []string{"av-definitions-failing", "malware-detected", "malware-left-clamav"},
	}, end.Add(time.Minute), "web-01", "ws-ops-02", "app-01", "ws-it-02", bob.Winuser())
}
