// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ruledraft

import (
	"regexp"
	"slices"
)

// cue is a sign in a description of a known attack behaviour, with the
// ATT&CK techniques and the severity that go with it.
type cue struct {
	re       *regexp.Regexp
	label    string
	mitre    []string
	severity string
}

func c(pattern, label, severity string, mitre ...string) cue {
	return cue{re: regexp.MustCompile(`\b(?:` + pattern + `)`), label: label, mitre: mitre, severity: severity}
}

// cues is checked against the lowercased description. Severity follows
// the built-in detections for the same behaviour.
var cues = []cue{
	c(`password spray`, "password spraying", "high", "T1110.003"),
	c(`brute[ -]?forc|(?:failed|failing|bad|wrong|unsuccessful) (?:log ?ins?|log ?ons?|logins?|logons?|sign[ -]?ins?|passwords?|auth)|(?:log ?ins?|log ?ons?|logins?|logons?|sign[ -]?ins?) (?:that )?fail`, "password guessing", "medium", "T1110"),
	c(`credential stuffing`, "credential stuffing", "high", "T1110.004"),
	c(`mimikatz|lsass|credential dump|dump(?:ing)? credentials|procdump`, "credential dumping", "critical", "T1003.001"),
	c(`dcsync`, "DCSync", "critical", "T1003.006"),
	c(`kerberoast`, "Kerberoasting", "high", "T1558.003"),
	c(`golden ticket`, "a golden ticket", "critical", "T1558.001"),
	c(`pass[ -]the[ -]hash`, "pass the hash", "high", "T1550.002"),
	c(`encoded (?:powershell|command)|powershell.{0,30}(?:-enc|encoded|base64)|base64.{0,30}powershell`, "an encoded PowerShell command", "high", "T1059.001", "T1027"),
	c(`powershell|pwsh`, "PowerShell", "medium", "T1059.001"),
	c(`cmd\.exe|command prompt|command shell`, "the Windows command shell", "medium", "T1059.003"),
	c(`bash|/bin/sh|reverse shell`, "a Unix shell", "medium", "T1059.004"),
	c(`(?:security|event|audit) logs? (?:was |were |being |is )?(?:cleared|deleted|wiped)|clear(?:ed|ing|s)? (?:the )?(?:security |event |audit )?logs?|wevtutil|1102\b`, "clearing logs", "high", "T1070.001"),
	c(`(?:domain |enterprise )?admins? group|administrators group|added to (?:a |an |the )?(?:privileged|admin)|privileged group`, "a change to an admin group", "high", "T1098"),
	c(`(?:new|created?|creating|add(?:ed)?) (?:local |domain )?(?:user )?accounts?|accounts? (?:was |were )?created|new users?|users? (?:was |were )?created`, "a new account", "medium", "T1136"),
	c(`(?:new|install(?:ed)?|created?) services?|services? (?:was |were )?(?:installed|created)|7045\b`, "a new service", "medium", "T1543.003"),
	c(`scheduled tasks?|schtasks|4698\b`, "a scheduled task", "medium", "T1053.005"),
	c(`cron(?:tab)?`, "a cron job", "medium", "T1053.003"),
	c(`shadow cop|vssadmin|wbadmin|bcdedit`, "deleting backups", "critical", "T1490"),
	c(`ransomware|encrypt(?:ed|ing|s)? (?:many |lots of |the )?files`, "ransomware", "critical", "T1486"),
	c(`run keys?|autorun|currentversion\\\\?run|startup folder`, "an autorun entry", "medium", "T1547.001"),
	c(`rdp|remote desktop`, "remote desktop", "medium", "T1021.001"),
	c(`psexec|admin shares?|\$admin|smb (?:exec|lateral)`, "remote execution over SMB", "high", "T1569.002", "T1021.002"),
	c(`wmic?\b|wmiprvse`, "WMI", "medium", "T1047"),
	c(`winrm|psremoting|enter-pssession`, "Windows remote management", "medium", "T1021.006"),
	c(`ssh`, "SSH", "medium", "T1021.004"),
	c(`lateral movement`, "lateral movement", "high", "T1021"),
	c(`rundll32`, "rundll32", "medium", "T1218.011"),
	c(`regsvr32`, "regsvr32", "medium", "T1218.010"),
	c(`mshta`, "mshta", "high", "T1218.005"),
	c(`certutil|bitsadmin|download(?:ing|s|ed)? (?:a |an )?(?:file|payload|executable|tool)|ingress tool`, "downloading a tool", "high", "T1105"),
	c(`(?:defender|antivirus|av|edr|real[ -]?time protection).{0,30}(?:disabl|turn(?:ed)? off|stopp|tamper)|(?:disabl|turn(?:ed|ing)? off|stopp|tamper)\w*.{0,30}(?:defender|antivirus|av|edr|real[ -]?time protection)`, "turning off security tools", "high", "T1562.001"),
	c(`exclusions?`, "an antivirus exclusion", "medium", "T1562.001"),
	c(`malware|virus|trojan|infect`, "malware", "high", "T1204"),
	c(`(?:office|word|winword|excel|outlook|macro).{0,40}(?:spawn|launch|start|run|child)`, "an Office document starting a program", "high", "T1566.001", "T1204.002"),
	c(`phish`, "phishing", "medium", "T1566"),
	c(`web ?shell`, "a web shell", "critical", "T1505.003"),
	c(`sql injection|sqli\b|exploit(?:ing|ed)? (?:a |the )?(?:public|web|internet)`, "exploiting a public application", "high", "T1190"),
	c(`port ?scan|scann(?:ing|ed|er)|nmap|many (?:ports|hosts)`, "network scanning", "low", "T1046"),
	c(`dns tunnel|long dns|dns exfil`, "DNS tunnelling", "high", "T1071.004"),
	c(`beacon|c2\b|command and control|callback`, "command and control", "high", "T1071"),
	c(`exfil|large (?:upload|outbound|transfer)|(?:uploading|sending) (?:a lot|lots|large)`, "data exfiltration", "high", "T1048"),
	c(`\btor\b|onion`, "Tor", "medium", "T1090.003"),
	c(`crypto ?min|coin ?min|xmrig|miner`, "cryptomining", "high", "T1496"),
	c(`sudo|privilege escalation|setuid|suid`, "privilege escalation", "medium", "T1548.003"),
	c(`/etc/shadow|/etc/passwd|shadow file`, "reading password files", "high", "T1003.008"),
	c(`mfa (?:fatigue|bomb|spam|push)|push (?:fatigue|bomb|spam)|(?:many|repeated) mfa`, "MFA fatigue", "high", "T1621"),
	c(`impossible travel|new (?:country|location)|unusual (?:country|location)|from (?:a |an )?(?:new|unusual|foreign) (?:country|location)`, "a sign-in from an unusual place", "medium", "T1078"),
	c(`(?:admin|administrator|root|privileged|service) accounts?.{0,30}(?:log|sign)|(?:log|sign)\w*.{0,30}(?:as|by|with) (?:an? )?(?:admin|administrator|root|privileged)`, "use of a privileged account", "medium", "T1078"),
	c(`whoami|net (?:user|group|localgroup)|nltest|discovery|recon`, "discovery commands", "low", "T1087", "T1033"),
	c(`clipboard|keylog|screen ?capture|screenshot`, "collecting input", "high", "T1056.001"),
	c(`mailbox|inbox rule|forwarding rule|mail forward`, "an email forwarding rule", "high", "T1114.003"),
	c(`(?:new|added) (?:app|application) (?:consent|credential|secret)|consent grant`, "an application consent or credential", "high", "T1098.001"),
	c(`s3 bucket.{0,30}public|public (?:s3 )?bucket`, "a public storage bucket", "high", "T1530"),
	c(`cloudtrail.{0,20}(?:stop|delet|disabl)|(?:stop|delet|disabl)\w*.{0,20}(?:cloudtrail|logging)`, "turning off cloud logging", "high", "T1562.008"),
}

// matched is a cue found in a description.
type matched struct {
	cue
	phrase string
	at     []int
}

// matchCues returns the cues found in a lowercased description. A more
// specific cue for the same technique (encoded PowerShell) hides a
// general one (PowerShell).
func matchCues(low string) []matched {
	var out []matched
	for _, c := range cues {
		loc := c.re.FindStringIndex(low)
		if loc == nil {
			continue
		}
		covered := false
		for _, m := range out {
			if loc[0] >= m.at[0] && loc[1] <= m.at[1] || allIn(c.mitre, m.mitre) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, matched{cue: c, phrase: low[loc[0]:loc[1]], at: loc})
		}
	}
	return out
}

func allIn(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
