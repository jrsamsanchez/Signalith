package ingest

import (
	"strconv"
	"strings"
)

// Microsoft Defender Antivirus writes to the Windows event log channel
// below; the Windows agent collects it. The rendered Message reads as
// "Label: value" lines, which name the threat, file, user and so on in
// every Windows version (older ones say "Signature" where newer ones say
// "Security intelligence"). The event data inserts are used only when
// there is no message to read.

// DefenderChannel is the Windows event log channel Defender writes to.
const DefenderChannel = "Microsoft-Windows-Windows Defender/Operational"

// DefenderProduct is the vendor_product of Defender events.
const DefenderProduct = "Microsoft Defender Antivirus"

// Limits on the part of a Defender message that is read.
const (
	defenderMaxMessage = 16 << 10
	defenderMaxLines   = 100
	defenderMaxLabel   = 48
)

// defenderLabels are the message labels read, in lower case with
// "signature" spelled "security intelligence". Others are ignored, so
// nothing in a message can name a field.
var defenderLabels = map[string]bool{
	"name": true, "id": true, "severity": true, "category": true, "path": true,
	"detection source": true, "user": true, "process name": true, "target commandline": true,
	"action": true, "action name": true, "error description": true,
	"security intelligence version": true, "current security intelligence version": true, "av security intelligence version": true,
	"engine version": true, "current engine version": true,
	"product version": true, "platform version": true, "current platform version": true,
	"old value": true, "new value": true, "value": true, "changed value": true, "feature name": true,
	"last av security intelligence age": true,
}

// defenderASR names attack surface reduction rules by GUID.
var defenderASR = map[string]string{
	"56a863a9-875e-4185-98a7-b882c64b5ce5": "Vulnerable signed driver",
	"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Credential theft from LSASS",
	"e6db77e5-3df2-4cf1-b95a-636979351e5b": "Persistence through WMI event subscription",
	"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader started a child process",
	"d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office app started a child process",
	"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Executable content from email",
	"01443614-cd74-433a-b99e-2ecdc07bfc25": "Rare or untrusted executable",
	"5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Obfuscated script",
	"d3e037e1-3eb8-44c8-a917-57927947596d": "Script launched downloaded executable content",
	"3b576869-a4ec-4529-8536-b80a7769e899": "Office app created executable content",
	"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office app injected code into another process",
	"26190899-1602-49e8-8b27-eb1d0a1ce869": "Office communication app started a child process",
	"d1e49aac-8f56-4280-b9ba-993a6d77406c": "Process creation from PsExec or WMI",
	"33ddedf1-c6e0-47cb-833e-de6133960387": "Reboot into Safe Mode",
	"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Untrusted program from USB",
	"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Copied or impersonated system tool",
	"a8f5898e-1dc8-49a9-9878-85004b8a61e6": "Webshell creation on a server",
	"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Office macro called Win32 APIs",
	"c1db55ab-c21a-4637-bb3f-a12568109d35": "Ransomware protection",
}

// The names of rules that are not attack surface reduction rules.
const (
	RuleControlledFolderAccess = "Controlled folder access"
	RuleNetworkProtection      = "Network protection"
	RuleASRUnknown             = "Attack surface reduction rule"
)

// defenderHealth gives the action and signature of health events whose
// meaning the event ID alone decides.
var defenderHealth = map[string][2]string{
	"2000": {"updated", "Antivirus definitions updated"},
	"2002": {"updated", "Antivirus engine updated"},
	"2001": {"update_failed", "Definitions update failed"},
	"2003": {"update_failed", "Engine update failed"},
	"2004": {"update_failed", "Definitions failed to load"},
	"2006": {"update_failed", "Platform update failed"},
	"3002": {"engine_failed", "Real-time protection failed"},
	"5008": {"engine_failed", "Antivirus engine failed"},
	"5000": {"enabled", "Real-time protection turned on"},
	"5001": {"disabled", "Real-time protection turned off"},
	"5009": {"enabled", "Malware scanning turned on"},
	"5010": {"disabled", "Malware scanning turned off"},
	"5011": {"enabled", "Virus scanning turned on"},
	"5012": {"disabled", "Virus scanning turned off"},
	"5004": {"modified", "Real-time protection setting changed"},
	"5013": {"tamper_blocked", "Tamper protection blocked a change"},
	"1150": {"status", "Antivirus is running"},
	"5101": {"outdated", "Antimalware platform expired"},
}

// defenderMessage reads the "Label: value" lines of a rendered message.
func defenderMessage(msg string) map[string]string {
	if len(msg) > defenderMaxMessage {
		msg = msg[:defenderMaxMessage]
	}
	out := map[string]string{}
	lines := 0
	for line := range strings.SplitSeq(msg, "\n") {
		if lines++; lines > defenderMaxLines {
			break
		}
		line = strings.Trim(line, " \t\r")
		label, value, ok := strings.Cut(line, ": ")
		if !ok {
			if !strings.HasSuffix(line, ":") {
				continue
			}
			label, value = line[:len(line)-1], ""
		}
		if len(label) > defenderMaxLabel {
			continue
		}
		label = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(label)), "signature", "security intelligence")
		if !defenderLabels[label] {
			continue
		}
		if _, seen := out[label]; !seen {
			out[label] = strings.TrimSpace(value)
		}
	}
	return out
}

// first returns the value of the first label present.
func first(kv map[string]string, labels ...string) string {
	for _, l := range labels {
		if v := kv[l]; v != "" {
			return v
		}
	}
	return ""
}

// versionPart returns the version after "AV: " or "AM: " in a list such as
// "AV: 1.419.2361.0, AS: 1.419.2361.0", or the value up to its first comma.
func versionPart(v, prefix string) string {
	if i := strings.Index(v, prefix); i >= 0 {
		v = v[i+len(prefix):]
	}
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}

// parseDefender maps a Defender event onto the Malware data model.
func parseDefender(eventID, msg string, in []string, ev *Event) {
	f := ev.Fields
	f["sourcetype"] = "WinEventLog:" + DefenderChannel
	f["vendor_product"] = DefenderProduct
	kv := defenderMessage(msg)

	typ, action, sig := "", "", ""
	switch eventID {
	case "1006", "1116", "1015", "1007", "1117", "1008", "1118", "1119", "1009":
		typ = MalwareThreat
	case "1121", "1122", "1123", "1124", "1127", "1128", "1125", "1126":
		typ = MalwareRule
	case "5007":
		typ = MalwareHealth
	case "1151":
		typ, action, sig = MalwareHealth, "status", "Antivirus health report"
	default:
		h, ok := defenderHealth[eventID]
		if !ok {
			return // stays Other, with the base fields and the message
		}
		typ, action, sig = MalwareHealth, h[0], h[1]
	}
	ev.Model = MalwareModel

	// Labels every kind of event can carry.
	SetValue(f, "user", kv["user"])
	SetValue(f, "detection_source", kv["detection source"])
	SetProcessPath(f, kv["process name"])
	SetValue(f, "process", kv["target commandline"])
	SetValue(f, "reason", kv["error description"])
	if v := first(kv, "security intelligence version", "current security intelligence version", "av security intelligence version"); v != "" {
		SetValue(f, "signature_version", versionPart(v, "AV: "))
	}
	if v := first(kv, "engine version", "current engine version"); v != "" {
		SetValue(f, "engine_version", versionPart(v, "AM: "))
	}
	SetValue(f, "product_version", first(kv, "product version", "platform version", "current platform version"))

	switch typ {
	case MalwareThreat:
		name := kv["name"]
		SetValue(f, "threat_id", kv["id"])
		SetValue(f, "vendor_severity", kv["severity"])
		SetValue(f, "vendor_category", kv["category"])
		SetValue(f, "vendor_action", first(kv, "action", "action name"))
		path := kv["path"]
		if name == "" && (eventID == "1116" || eventID == "1117" || eventID == "1118" || eventID == "1119") {
			name, path = defenderInserts(in, f, path)
		}
		defenderResource(f, path)
		sig = CapValue(name)
		if sig == "" {
			sig = UnknownThreat
		}
		switch eventID {
		case "1006", "1116", "1015":
			action = "detected"
		case "1007", "1117":
			action = MalwareAction(str(f, "vendor_action"))
		case "1008", "1118", "1119":
			action = "failed"
		case "1009":
			action = "restored"
		}
		vcat := str(f, "vendor_category")
		cat := MalwareCategory(sig, vcat)
		if eventID == "1015" {
			// Behavior monitoring: the category is behavior unless the
			// threat's name says what it is.
			if cat = MalwareCategory(sig, ""); cat == "other" {
				cat = "behavior"
			}
		}
		f["category"] = cat
		if s := MalwareSeverity(str(f, "vendor_severity")); s != "" {
			f["severity"] = s
		}
	case MalwareRule:
		path := kv["path"]
		switch eventID {
		case "1121", "1122":
			id := strings.ToLower(CapValue(kv["id"]))
			SetValue(f, "rule_id", id)
			sig = defenderASR[id]
			if sig == "" {
				sig = RuleASRUnknown
			}
			SetFilePath(f, path)
		case "1123", "1124", "1127", "1128":
			sig = RuleControlledFolderAccess
			SetFilePath(f, path)
		case "1125", "1126":
			sig = RuleNetworkProtection
			SetValue(f, "url", path)
		}
		action = "audited"
		switch eventID {
		case "1121", "1123", "1127", "1126":
			action = "blocked"
		}
		f["rule"] = sig
	case MalwareHealth:
		switch eventID {
		case "5007":
			// The registry values as they were and are, which rules
			// search for the setting changed.
			SetValue(f, "old_value", kv["old value"])
			SetValue(f, "new_value", kv["new value"])
			action, sig = defenderConfigChange(f, kv["old value"], kv["new value"])
		case "5013":
			SetValue(f, "setting", first(kv, "value", "changed value"))
		case "5004":
			SetValue(f, "setting", kv["feature name"])
		case "1151":
			if v := kv["last av security intelligence age"]; v != "" {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
					f["signature_age_days"] = n
					if n >= 7 {
						action, sig = "outdated", "Antivirus definitions out of date"
					}
				}
			}
		}
	}
	f["type"] = typ
	f["action"] = action
	f["signature"] = sig
}

// defenderInserts reads a threat event's data inserts, which Defender
// writes in a fixed order, when its message names no threat. It returns
// the threat name and resource path.
func defenderInserts(in []string, f map[string]any, path string) (string, string) {
	if len(in) < 42 || !allDigitsStr(at(in, 6)) || !strings.Contains(at(in, 7), ":") {
		return "", path
	}
	SetValue(f, "threat_id", at(in, 6))
	SetValue(f, "vendor_severity", at(in, 9))
	SetValue(f, "vendor_category", at(in, 11))
	SetValue(f, "detection_source", at(in, 17))
	SetProcessPath(f, at(in, 18))
	SetValue(f, "user", at(in, 19))
	SetValue(f, "vendor_action", at(in, 30))
	SetValue(f, "reason", at(in, 33))
	// "AV: 1.381.2134.0, AS: ..., NIS: ..." and "AM: 1.1.20000.2, NIS: ...",
	// read as the message path reads them.
	SetValue(f, "signature_version", versionPart(at(in, 40), "AV: "))
	SetValue(f, "engine_version", versionPart(at(in, 41), "AM: "))
	return at(in, 7), at(in, 21)
}

func allDigitsStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// defenderResource reads the first resource of a threat's Path, such as
// "file:_C:\Users\a\x.exe" or "webfile:_C:\x.exe|https://example.com/x|pid:12,ProcessStart:1".
func defenderResource(f map[string]any, path string) {
	path, _, _ = strings.Cut(path, "; ")
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	kind, rest, ok := strings.Cut(path, ":_")
	if !ok || strings.ContainsAny(kind, `\/ `) {
		SetFilePath(f, path)
		return
	}
	switch strings.ToLower(kind) {
	case "file", "containerfile":
		SetFilePath(f, rest)
	case "webfile":
		parts := strings.SplitN(rest, "|", 3)
		SetFilePath(f, parts[0])
		if len(parts) > 1 {
			SetValue(f, "url", parts[1])
		}
		if len(parts) > 2 {
			setPID(f, parts[2])
		}
	case "process", "behavior":
		setPID(f, rest)
	case "amsi":
		SetProcessPath(f, rest)
	case "regkey":
		SetValue(f, "setting", rest)
	default:
		SetFilePath(f, path)
	}
}

// setPID reads the number after "pid:" into process_id.
func setPID(f map[string]any, s string) {
	i := strings.Index(strings.ToLower(s), "pid:")
	if i < 0 {
		return
	}
	s = s[i+4:]
	n := 0
	for n < len(s) && n < 12 && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if v, err := strconv.ParseInt(s[:n], 10, 64); err == nil {
		f["process_id"] = v
	}
}

// Registry values whose being set to 1 turns protection off.
var defenderDisable = []string{
	`\DisableRealtimeMonitoring = 0x1`, `\DisableBehaviorMonitoring = 0x1`, `\DisableIOAVProtection = 0x1`,
	`\DisableOnAccessProtection = 0x1`, `\DisableScriptScanning = 0x1`, `\DisableAntiSpyware = 0x1`, `\DisableAntiVirus = 0x1`,
}

// defenderConfigChange reads event 5007 (configuration changed) and
// returns its action and signature.
func defenderConfigChange(f map[string]any, oldValue, newValue string) (string, string) {
	if newValue != "" {
		SetValue(f, "setting", newValue)
	} else {
		SetValue(f, "setting", oldValue)
	}
	if ex, typ, ok := defenderExclusion(newValue); ok {
		SetValue(f, "exclusion", ex)
		SetValue(f, "exclusion_type", typ)
		return "exclusion_added", "Antivirus exclusion added"
	}
	if ex, typ, ok := defenderExclusion(oldValue); ok {
		SetValue(f, "exclusion", ex)
		SetValue(f, "exclusion_type", typ)
		return "exclusion_removed", "Antivirus exclusion removed"
	}
	for _, d := range defenderDisable {
		if strings.Contains(newValue, d) {
			return "disabled", "Antivirus protection turned off by a setting"
		}
	}
	// Tamper protection: 5 is on, 4 (or 0) is off.
	if _, v, ok := strings.Cut(newValue, `\Features\TamperProtection = `); ok {
		if v = strings.ToLower(strings.TrimSpace(v)); v == "0x4" || v == "0x0" {
			return "disabled", "Tamper protection turned off"
		}
	}
	return "modified", "Antivirus setting changed"
}

// defenderExclusion reads an exclusion from a registry value such as
// HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0.
func defenderExclusion(v string) (exclusion, typ string, ok bool) {
	i := strings.Index(v, `\Exclusions\`)
	if i < 0 {
		return "", "", false
	}
	rest := v[i+len(`\Exclusions\`):]
	seg, after, found := strings.Cut(rest, `\`)
	if !found {
		// A switch such as Exclusions_Paths = 0x1 (Group Policy turning
		// its exclusion list on or off), not an exclusion.
		return "", "", false
	}
	switch strings.ToLower(seg) {
	case "paths", "temporarypaths":
		typ = "path"
	case "extensions":
		typ = "extension"
	case "processes":
		typ = "process"
	case "ipaddresses":
		typ = "ip"
	default:
		return "", "", false
	}
	if j := strings.Index(after, " = "); j >= 0 {
		after = after[:j]
	}
	if after = strings.TrimSpace(after); after == "" {
		return "", "", false
	}
	return after, typ, true
}
