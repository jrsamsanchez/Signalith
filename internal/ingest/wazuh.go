package ingest

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Wazuh alerts arrive from a Wazuh manager, which is the only thing Wazuh
// agents talk to: Fluent Bit on the manager tails alerts.json (one JSON
// alert per line) and sends each line under the tag "wazuh", or the
// manager's syslog output sends each alert as JSON to the syslog receiver.
// Both end in ParseWazuhAlert, which maps an alert onto the data model that
// fits it best and keeps the rest in wazuh_* fields and the raw JSON.

// WazuhTag is the Fluent Bit tag the generated Wazuh config sends with.
const WazuhTag = "wazuh"

// WazuhSourcetype is the sourcetype of every Wazuh alert.
const WazuhSourcetype = "wazuh:alerts"

// maxWazuhList caps the entries kept from one list in an alert (rule
// groups, ATT&CK IDs), and maxWazuhPrefix how much text may come before
// the JSON in a syslog message.
const (
	maxWazuhList   = 32
	maxWazuhPrefix = 256
)

// isWazuhTag reports whether a Fluent Bit tag is the Wazuh one.
func isWazuhTag(tag string) bool {
	return tag == WazuhTag || strings.HasPrefix(tag, WazuhTag+".")
}

// IsWazuhAlert reports whether a decoded JSON object is a Wazuh alert: it
// has "rule" and "agent" objects.
func IsWazuhAlert(r map[string]any) bool {
	_, rule := r["rule"].(map[string]any)
	_, agent := r["agent"].(map[string]any)
	return rule && agent
}

// parseWazuhRecord maps a record sent under the Wazuh tag: either an
// alert Fluent Bit already decoded, or the alert line in "log".
func parseWazuhRecord(r map[string]any) Event {
	if IsWazuhAlert(r) {
		return ParseWazuhAlert(r, "")
	}
	line := str(r, "log", "message")
	if a, ok := decodeWazuh(line); ok {
		return ParseWazuhAlert(a, strings.TrimSpace(line))
	}
	ev := parseGeneric(r)
	ev.Fields["sourcetype"] = WazuhSourcetype
	ev.Fields["vendor_product"] = "Wazuh"
	if line != "" {
		ev.Fields["message"] = line
	}
	return ev
}

// ParseWazuhText finds a Wazuh JSON alert in a syslog message's text,
// which may start with a short tag such as "ossec: ", and maps it. It
// reports false when the text is not a whole Wazuh alert.
func ParseWazuhText(text string) (Event, bool) {
	i := strings.IndexByte(text, '{')
	if i < 0 || i > maxWazuhPrefix {
		return Event{}, false
	}
	body := strings.TrimSpace(text[i:])
	if !strings.HasSuffix(body, "}") || !strings.Contains(body, `"rule"`) || !strings.Contains(body, `"agent"`) {
		return Event{}, false
	}
	a, ok := decodeWazuh(body)
	if !ok {
		return Event{}, false
	}
	return ParseWazuhAlert(a, body), true
}

// decodeWazuh decodes one JSON alert, within the size and nesting limits
// of any other record, and reports whether it is a Wazuh alert.
func decodeWazuh(s string) (map[string]any, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || len(s) > MaxRecordBytes || depth([]byte(s)) > MaxDepth {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var a map[string]any
	if err := dec.Decode(&a); err != nil || dec.More() {
		return nil, false
	}
	return a, IsWazuhAlert(a)
}

// ParseWazuhAlert maps a decoded Wazuh alert. raw is its JSON text; when
// empty the alert is encoded again for the raw event.
func ParseWazuhAlert(a map[string]any, raw string) Event {
	if raw == "" {
		b, _ := json.Marshal(a)
		raw = string(b)
	}
	groups := wlist(wget(a, "rule", "groups"))
	agent := wstr(wget(a, "agent", "name"))

	var ev Event
	switch {
	case wget(a, "syscheck") != nil:
		ev = wazuhSyscheck(a, groups)
	case wstr(wget(a, "data", "sca", "type")) == "check":
		ev = wazuhSCA(a)
	default:
		var ok bool
		if ev, ok = wazuhMalware(a, groups); ok {
			break
		}
		if ev, ok = wazuhWindows(a); !ok {
			if action := wazuhAuthAction(groups); action != "" {
				ev = wazuhAuth(a, action)
			} else {
				ev = wazuhAlert(a, groups)
			}
		}
	}
	f := ev.Fields
	level, hasLevel := wint(wget(a, "rule", "level"))
	f["signature_id"] = wstr(wget(a, "rule", "id"))
	// A Malware event's signature is the threat's name; the rule's
	// description is kept in description.
	if ev.Model == MalwareModel {
		f["description"] = wstr(wget(a, "rule", "description"))
	} else {
		f["signature"] = wstr(wget(a, "rule", "description"))
	}
	// Antivirus alerts keep the product that found the threat (ClamAV
	// through Wazuh's integration); everything else is Wazuh's.
	if ev.Model != MalwareModel || f["vendor_product"] == nil {
		f["vendor_product"] = "Wazuh"
	}
	f["sourcetype"] = WazuhSourcetype
	f["host"] = agent
	if ev.Model != "Network_Traffic" {
		f["dest"] = agent // a connection's dest is where it went
	}
	f["message"] = raw
	if hasLevel {
		f["wazuh_rule_level"] = level
	}
	if len(groups) > 0 {
		f["wazuh_rule_groups"] = groups
	}
	if ids := wlist(wget(a, "rule", "mitre", "id")); len(ids) > 0 {
		f["mitre"] = ids
	}
	if tactics := wlist(wget(a, "rule", "mitre", "tactic")); len(tactics) > 0 {
		f["mitre_tactic"] = tactics
	}
	f["wazuh_agent_id"] = wstr(wget(a, "agent", "id"))
	f["wazuh_agent_name"] = agent
	f["wazuh_agent_ip"] = wstr(wget(a, "agent", "ip"))
	f["wazuh_manager"] = wstr(wget(a, "manager", "name"))
	f["wazuh_decoder"] = wstr(wget(a, "decoder", "name"))
	f["wazuh_location"] = wstr(wget(a, "location"))
	if t, ok := wazuhTime(wstr(a["timestamp"])); ok {
		ev.Time = t
	}
	return ev
}

// wazuhSeverity names a Wazuh rule level (0 to 15).
func wazuhSeverity(level int64) string {
	switch {
	case level <= 3:
		return "informational"
	case level <= 6:
		return "low"
	case level <= 9:
		return "medium"
	case level <= 12:
		return "high"
	}
	return "critical"
}

// wazuhAlert is the Alerts event for an alert no other model fits.
func wazuhAlert(a map[string]any, groups []string) Event {
	f := map[string]any{
		"app":         "wazuh",
		"id":          wstr(a["id"]),
		"description": wstr(wget(a, "rule", "description")),
		"type":        strings.Join(groups, ", "),
		"src":         wstr(wget(a, "data", "srcip")),
		"user":        wazuhUser(a),
	}
	if level, ok := wint(wget(a, "rule", "level")); ok {
		f["severity"] = wazuhSeverity(level)
		f["severity_id"] = level
	}
	return Event{Model: "Alerts", Fields: f}
}

// wazuhMalware maps the antivirus alerts a Wazuh manager raises onto
// Malware, so they are found with every other antivirus's: its ClamAV
// integration (the clamd or freshclam line in full_log), VirusTotal
// matches, and rootcheck's trojaned files. Each needs a threat name or a
// file; other rootcheck findings stay Alerts.
func wazuhMalware(a map[string]any, groups []string) (Event, bool) {
	has := func(g string) bool {
		for _, x := range groups {
			if x == g {
				return true
			}
		}
		return false
	}
	f := map[string]any{}
	decoder := wstr(wget(a, "decoder", "name"))
	switch {
	case has("clamd") || has("freshclam") || strings.HasPrefix(decoder, "clamd") || strings.HasPrefix(decoder, "freshclam"):
		line := wstr(wget(a, "full_log"))
		program := "clamd"
		if strings.HasPrefix(decoder, "freshclam") || !strings.HasPrefix(decoder, "clamd") && strings.Contains(line, "freshclam") {
			program = "freshclam"
		}
		// full_log is the syslog line; the ClamAV message follows the
		// program's "clamd[pid]: " tag.
		if i := strings.Index(line, program); i >= 0 {
			if j := strings.Index(line[i:], ": "); j >= 0 {
				line = line[i+j+2:]
			}
		}
		if !parseClamAVLine(program, line, f) {
			return Event{}, false
		}
	case wstr(wget(a, "data", "virustotal", "malicious")) == "1":
		vt := wget(a, "data", "virustotal")
		f["type"] = MalwareThreat
		f["action"] = "detected"
		f["detection_source"] = "VirusTotal"
		SetFilePath(f, wstr(wget(vt, "source", "file")))
		if h := wstr(wget(vt, "source", "sha1")); isHex(h) {
			f["file_sha1"] = strings.ToLower(h)
		}
		if h := wstr(wget(vt, "source", "md5")); isHex(h) {
			f["file_md5"] = strings.ToLower(h)
		}
		f["signature"] = "VirusTotal: " + wstr(wget(vt, "positives")) + " of " + wstr(wget(vt, "total")) + " engines"
		f["category"] = "other"
		SetValue(f, "url", wstr(wget(vt, "permalink")))
	case has("rootcheck") && strings.Contains(strings.ToLower(wstr(wget(a, "data", "title"))+" "+wstr(wget(a, "full_log"))), "trojan"):
		f["type"] = MalwareThreat
		f["action"] = "detected"
		f["detection_source"] = "Wazuh rootcheck"
		f["category"] = "trojan"
		file := wstr(wget(a, "data", "file"))
		if file == "" {
			// "Trojaned version of file '/bin/ls' detected."
			if _, rest, ok := strings.Cut(wstr(wget(a, "full_log")), "file '"); ok {
				file, _, _ = strings.Cut(rest, "'")
			}
		}
		SetFilePath(f, file)
		sig := CapValue(wstr(wget(a, "data", "title")))
		if sig == "" {
			sig = "Trojaned file"
		}
		f["signature"] = sig
	default:
		return Event{}, false
	}
	if _, ok := f["file_path"]; !ok && f["type"] == MalwareThreat && f["signature"] == UnknownThreat {
		return Event{}, false // neither a threat name nor a file
	}
	if f["type"] == MalwareThreat {
		if level, ok := wint(wget(a, "rule", "level")); ok {
			sev := wazuhSeverity(level)
			if sev == "informational" {
				sev = "low"
			}
			f["severity"] = sev
		}
	}
	if f["vendor_product"] == nil {
		f["vendor_product"] = "Wazuh"
	}
	if p, _ := f["file_path"].(string); p == "" {
		delete(f, "file_path")
	}
	return Event{Model: MalwareModel, Fields: f}, true
}

// wazuhAuthAction returns success or failure for an alert whose rule
// groups mark it as an authentication, or "".
func wazuhAuthAction(groups []string) string {
	for _, g := range groups {
		switch g {
		case "authentication_success":
			return "success"
		case "authentication_failed", "authentication_failures", "invalid_login":
			return "failure"
		}
	}
	return ""
}

// wazuhUser is the account an alert is about.
func wazuhUser(a map[string]any) string {
	for _, p := range [][]string{
		{"data", "dstuser"}, {"data", "srcuser"}, {"data", "win", "eventdata", "targetUserName"}, {"data", "win", "eventdata", "subjectUserName"},
	} {
		if u := wstr(wget(a, p...)); u != "" {
			return u
		}
	}
	return ""
}

// wazuhAuth is the Authentication event for a logon alert: sshd, PAM,
// sudo, su, Windows and others Wazuh's rules group as authentication.
func wazuhAuth(a map[string]any, action string) Event {
	app := wstr(wget(a, "decoder", "parent"))
	if app == "" {
		app = wstr(wget(a, "decoder", "name"))
	}
	if app == "" {
		app = wstr(wget(a, "predecoder", "program_name"))
	}
	src := wstr(wget(a, "data", "srcip"))
	if src == "" {
		src = wstr(wget(a, "data", "win", "eventdata", "ipAddress"))
	}
	port := wstr(wget(a, "data", "srcport"))
	if port == "" {
		port = wstr(wget(a, "data", "win", "eventdata", "ipPort"))
	}
	f := map[string]any{
		"action":      action,
		"app":         app,
		"user":        wazuhUser(a),
		"user_domain": wstr(wget(a, "data", "win", "eventdata", "targetDomainName")),
		"src":         src,
		"src_port":    atoi(port),
	}
	// sudo and su: srcuser asked to act as dstuser.
	if su, du := wstr(wget(a, "data", "srcuser")), wstr(wget(a, "data", "dstuser")); su != "" && du != "" && su != du {
		f["src_user"] = su
	}
	return Event{Model: "Authentication", Fields: f}
}

// wazuhSyscheck is the Filesystem event (or Registry, for Windows
// registry monitoring) for a file integrity monitoring alert.
func wazuhSyscheck(a map[string]any, groups []string) Event {
	sc := func(k ...string) string { return wstr(wget(a, append([]string{"syscheck"}, k...)...)) }
	path := sc("path")
	action := sc("event")
	if action == "added" {
		action = "created"
	}
	user := sc("audit", "user", "name")
	if user == "" {
		user = sc("uname_after")
	}
	f := map[string]any{"action": action, "user": user}
	if proc := sc("audit", "process", "name"); proc != "" {
		f["process_path"] = proc
		f["process_name"] = baseName(proc)
	}
	if pid, ok := wint(wget(a, "syscheck", "audit", "process", "id")); ok {
		f["process_id"] = pid
	}
	if slices.Contains(groups, "syscheck_registry") || strings.HasPrefix(strings.ToUpper(path), "HKEY_") {
		value := sc("value_name")
		f["registry_key_name"] = baseName(path)
		f["registry_value_name"] = value
		f["registry_path"] = path
		if value != "" {
			f["registry_path"] = path + `\` + value
		}
		return Event{Model: "Registry", Fields: f}
	}
	f["file_path"] = path
	f["file_name"] = baseName(path)
	f["file_hash"] = strings.ToLower(sc("sha256_after"))
	if size, ok := wint(wget(a, "syscheck", "size_after")); ok {
		f["file_size"] = size
	}
	return Event{Model: "Filesystem", Fields: f}
}

// wazuhSCA is the Configuration_Check event for a Security Configuration
// Assessment check result.
func wazuhSCA(a map[string]any) Event {
	chk := func(k string) string { return wstr(wget(a, "data", "sca", "check", k)) }
	result := chk("result")
	if result == "" {
		result = chk("status") // older managers report "Not applicable" here
	}
	switch strings.ToLower(result) {
	case "passed":
		result = "pass"
	case "failed":
		result = "fail"
	case "not applicable":
		result = "n/a"
	}
	f := map[string]any{
		"check_id":  chk("id"),
		"check":     chk("title"),
		"result":    result,
		"detail":    chk("reason"),
		"benchmark": wstr(wget(a, "data", "sca", "policy")),
	}
	if comp, ok := wget(a, "data", "sca", "check", "compliance").(map[string]any); ok {
		var refs []string
		for k, v := range comp {
			if s := strings.Join(wlist(v), ","); s != "" {
				refs = append(refs, k+": "+s)
			}
		}
		slices.Sort(refs)
		if len(refs) > maxWazuhList {
			refs = refs[:maxWazuhList]
		}
		f["reference"] = strings.Join(refs, "; ")
	}
	return Event{Model: "Configuration_Check", Fields: f}
}

// windowsInsertNames lists, for the Security events parseWindowsSecurity
// reads, the event data names in schema order: the order Fluent Bit's
// StringInserts has them in. Wazuh sends the same data by name (with the
// first letter in lower case).
var windowsInsertNames = map[string][]string{
	"4624": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
		"LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort",
		"ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount",
		"TargetLinkedLogonId", "ElevatedToken"},
	"4625": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
		"WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"4688": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName",
		"TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
		"ParentProcessName", "MandatoryLabel"},
	"4663": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "AccessList", "AccessMask", "ProcessId", "ProcessName"},
	"4648": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "LogonGuid", "TargetUserName",
		"TargetDomainName", "TargetLogonGuid", "TargetServerName", "TargetInfo", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"5156": {"ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol",
		"FilterRTID", "LayerName", "LayerRTID"},
	"5157": {"ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol",
		"FilterRTID", "LayerName", "LayerRTID"},
	"4656": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "TransactionId", "AccessList", "AccessReason", "AccessMask", "PrivilegeList",
		"RestrictedSidCount", "ProcessId", "ProcessName"},
	"4657": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectName", "ObjectValueName",
		"HandleId", "OperationType", "OldValueType", "OldValue", "NewValueType", "NewValue", "ProcessId", "ProcessName"},
	"4661": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "TransactionId", "AccessList", "AccessMask", "PrivilegeList", "Properties",
		"RestrictedSidCount", "ProcessId", "ProcessName"},
	"4662": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "OperationType", "HandleId", "AccessList", "AccessMask", "Properties"},
	"4768": {"TargetUserName", "TargetDomainName", "TargetSid", "ServiceName", "ServiceSid", "TicketOptions", "Status",
		"TicketEncryptionType", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"},
	"4769": {"TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "TicketOptions", "TicketEncryptionType",
		"IpAddress", "IpPort", "Status"},
	"4698": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"},
	"5136": {"OpCorrelationID", "AppCorrelationID", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
		"DSName", "DSType", "ObjectDN", "ObjectGUID", "ObjectClass", "AttributeLDAPDisplayName", "AttributeSyntaxOID",
		"AttributeValue", "OperationType"},
	"5145": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectType", "IpAddress", "IpPort",
		"ShareName", "ShareLocalPath", "RelativeTargetName", "AccessMask", "AccessList"},
	"4719": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CategoryId", "SubcategoryId",
		"SubcategoryGuid", "AuditPolicyChanges"},
	"4706": {"DomainName", "DomainSid", "TdoType", "TdoDirection", "TdoAttributes", "SidFilteringEnabled", "SubjectUserSid",
		"SubjectUserName", "SubjectDomainName", "SubjectLogonId"},
	"4794": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "Workstation"},
	"4697": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ServiceName", "ServiceFileName",
		"ServiceType", "ServiceStartType", "ServiceAccount", "ClientProcessStartKey", "ClientProcessId", "ParentProcessId"},
	"4720": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId", "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory",
		"HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
		"PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
		"UserParameters", "SidHistory"},
	"4738": {"Dummy", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName",
		"HomeDirectory", "HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet",
		"AccountExpires", "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue",
		"UserAccountControl", "UserParameters", "SidHistory"},
	"4726": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId"},
	"4728": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4732": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4756": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
}

// wazuhWindows maps a Windows event channel alert with the Windows parser,
// by building the record Fluent Bit's winevtlog input would have sent. It
// reports false when the parser has no model for the event.
func wazuhWindows(a map[string]any) (Event, bool) {
	sys, _ := wget(a, "data", "win", "system").(map[string]any)
	if sys == nil {
		return Event{}, false
	}
	data, _ := wget(a, "data", "win", "eventdata").(map[string]any)
	byName := make(map[string]string, len(data))
	keys := make([]string, 0, len(data))
	for k, v := range data {
		byName[strings.ToLower(k)] = wstr(v)
		keys = append(keys, k)
	}
	channel := wstr(sys["channel"])
	eventID := wstr(sys["eventID"])
	r := map[string]any{
		"Channel":      channel,
		"EventID":      eventID,
		"Computer":     wstr(sys["computer"]),
		"TimeCreated":  wstr(sys["systemTime"]),
		"Message":      strings.Trim(wstr(sys["message"]), `"`),
		"ProviderName": wstr(sys["providerName"]),
	}
	names, ok := windowsInsertNames[eventID]
	if channel == SystemChannel {
		names, ok = serviceInstallSchema, eventID == "7045"
	} else if channel != "Security" {
		ok = false
	}
	if ok {
		ins := make([]any, len(names))
		for i, n := range names {
			ins[i] = byName[strings.ToLower(n)]
		}
		r["StringInserts"] = ins
	}
	if strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational") {
		// The Sysmon parser reads "Name: value" lines; Wazuh has the
		// same values by name.
		slices.Sort(keys)
		var b strings.Builder
		for _, k := range keys {
			v := strings.NewReplacer("\r", " ", "\n", " ").Replace(byName[strings.ToLower(k)])
			b.WriteString(upperFirst(k) + ": " + v + "\n")
		}
		r["Message"] = b.String()
	}
	ev := parseWindows(r)
	if ev.Model == "Other" {
		return Event{}, false
	}
	ev.Fields["wazuh_win_event_id"] = eventID
	if ev.Model == "Authentication" {
		ev.Fields["app"] = "win:local"
	}
	return ev, true
}

func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// wazuhTime reads an alert's timestamp, such as
// 2026-10-13T08:15:02.123+0000.
func wazuhTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range []string{"2006-01-02T15:04:05Z0700", time.RFC3339Nano} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return parseTime(s)
}

// wget walks nested objects; it returns nil when a step is missing or not
// an object.
func wget(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// wstr returns a string, number or boolean as text, and "" for anything
// else (objects, lists, null).
func wstr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// wint reads a whole number sent as a number or a string.
func wint(v any) (int64, bool) {
	s := strings.TrimSpace(wstr(v))
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > -1e15 && f < 1e15 && f == float64(int64(f)) {
		return int64(f), true
	}
	return 0, false
}

// wlist reads a list of strings (or one string) and keeps at most
// maxWazuhList non-empty entries.
func wlist(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s := wstr(e); s != "" && len(out) < maxWazuhList {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range x {
			if s != "" && len(out) < maxWazuhList {
				out = append(out, s)
			}
		}
	default:
		if s := wstr(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}
