package ingest

import (
	"html"
	"slices"
	"strconv"
	"strings"
)

// Fluent Bit's winevtlog input emits records with these keys: Channel,
// Computer, EventID, ProviderName, TimeCreated, Message and StringInserts
// (the event's data values, in schema order).

func isWindowsRecord(tag string, r map[string]any) bool {
	return strings.HasPrefix(tag, "win") || (has(r, "EventID") && (has(r, "Channel") || has(r, "Computer")))
}

func inserts(r map[string]any) []string {
	raw, _ := r["StringInserts"].([]any)
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = str(map[string]any{"v": v}, "v")
	}
	return out
}

func at(xs []string, i int) string {
	if i < len(xs) {
		return xs[i]
	}
	return ""
}

var windowsLogonTypes = map[string]string{
	"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
	"8": "network cleartext", "9": "new credentials", "10": "remote interactive", "11": "cached interactive",
}

// Windows 4625 status codes that explain a failed logon.
var windowsFailureReasons = map[string]string{
	"0xc0000064": "unknown user",
	"0xc000006a": "bad password",
	"0xc0000234": "account locked out",
	"0xc0000072": "account disabled",
	"0xc000006f": "outside allowed hours",
	"0xc0000070": "workstation restriction",
	"0xc0000193": "account expired",
	"0xc0000071": "password expired",
	"0xc0000224": "password must change",
}

func parseWindows(r map[string]any) Event { return parseWindowsWith(r, nil) }

// parseWindowsWith is parseWindows with a Sysmon event's named values
// already known (the OpenTelemetry Collector sends them); they win over
// what the rendered message says.
func parseWindowsWith(r map[string]any, named map[string]string) Event {
	channel := str(r, "Channel")
	eventID := str(r, "EventID")
	computer := str(r, "Computer", "ComputerName")
	computer = truncateUTF8(computer, maxHostLen)
	f := map[string]any{
		"host":           computer,
		"dest":           computer,
		"sourcetype":     "WinEventLog:" + channel,
		"vendor_product": "Microsoft Windows",
		"signature_id":   eventID,
		"message":        str(r, "Message"),
	}
	if f["message"] == "" {
		delete(f, "message")
	}
	ev := Event{Model: "Other", Fields: f}
	if t, ok := parseTime(str(r, "TimeCreated", "TimeGenerated")); ok {
		ev.Time = t
	}
	in := inserts(r)

	switch {
	case channel == "Security":
		parseWindowsSecurity(eventID, in, &ev)
	case channel == SystemChannel:
		parseWindowsSystem(eventID, str(r, "ProviderName"), in, &ev)
	case strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational"):
		kv := keyValues(str(r, "Message"))
		for k, v := range named {
			kv[k] = v
		}
		parseSysmon(eventID, kv, &ev)
	case strings.EqualFold(channel, DefenderChannel):
		parseDefender(eventID, str(r, "Message"), in, &ev)
	case strings.EqualFold(channel, PowerShellChannel) && eventID == "4104":
		parseScriptBlock(in, &ev)
	}
	return ev
}

// PowerShellChannel is where PowerShell logs script blocks (4104) once
// script block logging is turned on.
const PowerShellChannel = "Microsoft-Windows-PowerShell/Operational"

// parseScriptBlock reads a PowerShell script block event (4104). A long
// script comes as several events, one part each, sharing a block ID.
func parseScriptBlock(in []string, ev *Event) {
	ev.Model = "Script"
	f := ev.Fields
	f["vendor_product"] = "Microsoft PowerShell"
	f["signature"] = "Script block logged"
	f["script_block_text"] = at(in, 2)
	f["script_block_id"] = strings.Trim(at(in, 3), "{}")
	f["script_path"] = at(in, 4)
	f["script_part"] = atoi(at(in, 0))
	f["script_parts"] = atoi(at(in, 1))
}

func parseWindowsSecurity(eventID string, in []string, ev *Event) {
	f := ev.Fields
	switch eventID {
	case "4624", "4625":
		ev.Model = "Authentication"
		f["app"] = "win:local"
		f["user"] = at(in, 5)
		f["user_domain"] = at(in, 6)
		f["user_sid"] = at(in, 4)
		if eventID == "4624" {
			f["action"] = "success"
			f["signature"] = "An account was successfully logged on"
			f["logon_type"] = atoi(at(in, 8))
			f["src"] = at(in, 18)
			f["src_port"] = atoi(at(in, 19))
			f["src_host"] = at(in, 11)
			f["authentication_method"] = strings.TrimSpace(at(in, 10))
			f["logon_process"] = strings.TrimSpace(at(in, 9))
			f["process_path"] = at(in, 17)
			f["process_name"] = baseName(at(in, 17))
		} else {
			f["action"] = "failure"
			f["signature"] = "An account failed to log on"
			f["logon_type"] = atoi(at(in, 10))
			f["src"] = at(in, 19)
			f["src_port"] = atoi(at(in, 20))
			f["src_host"] = at(in, 13)
			f["authentication_method"] = strings.TrimSpace(at(in, 12))
			f["logon_process"] = strings.TrimSpace(at(in, 11))
			f["process_path"] = at(in, 18)
			f["process_name"] = baseName(at(in, 18))
			sub := strings.ToLower(at(in, 9))
			if reason, ok := windowsFailureReasons[sub]; ok {
				f["reason"] = reason
			} else if reason, ok := windowsFailureReasons[strings.ToLower(at(in, 7))]; ok {
				f["reason"] = reason
			}
		}
		if lt, ok := f["logon_type"].(int64); ok {
			if name, ok := windowsLogonTypes[strconv.FormatInt(lt, 10)]; ok {
				f["logon_type_name"] = name
			}
		}
	case "4688":
		ev.Model = "Endpoint"
		f["action"] = "allowed"
		f["signature"] = "A new process has been created"
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["process_id"] = atoi(at(in, 4))
		f["parent_process_id"] = atoi(at(in, 7))
		f["logon_id"] = at(in, 3)
		f["process_path"] = at(in, 5)
		f["process_name"] = baseName(at(in, 5))
		f["process"] = at(in, 8)
		if p := at(in, 13); p != "" {
			f["parent_process_path"] = p
			f["parent_process_name"] = baseName(p)
		}
		if f["process"] == "" {
			f["process"] = at(in, 5)
		}
	case "4698":
		// The task's definition is its XML, as the Task Scheduler stores
		// it: what it runs, when, and whether it is hidden.
		ev.Model = "Change"
		f["action"] = "created"
		f["object_category"] = "scheduled_task"
		f["signature"] = "A scheduled task was created"
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object"] = at(in, 4)
		f["task_name"] = at(in, 4)
		f["task_content"] = at(in, 5)
		f["task_command"] = taskElement(at(in, 5), "Command")
		f["task_arguments"] = taskElement(at(in, 5), "Arguments")
	case "4697":
		// A service installed, as the Security log records it (with
		// Audit Security System Extension on): the same as System 7045,
		// with who installed it, and the type and start type as numbers.
		ev.Model = "Change"
		f["action"] = "created"
		f["object_category"] = "service"
		f["signature"] = "A service was installed in the system"
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object"] = at(in, 4)
		f["service_name"] = at(in, 4)
		f["service_path"] = at(in, 5)
		f["service_type"] = at(in, 6)
		f["service_start_type"] = at(in, 7)
		f["service_account"] = at(in, 8)
	case "4663":
		// An access to an object whose audit rule (SACL) asks for it: a
		// file goes to Filesystem and a registry key to Registry.
		f["signature"] = "An attempt was made to access an object"
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object_type"] = at(in, 5)
		name := at(in, 6)
		f["object_path"] = name
		f["object_name"] = baseName(name)
		f["access_list"] = strings.Join(strings.Fields(at(in, 8)), " ")
		f["access_mask"] = at(in, 9)
		f["process_id"] = atoi(at(in, 10))
		f["process_path"] = at(in, 11)
		f["process_name"] = baseName(at(in, 11))
		f["action"] = objectAccessAction(f["access_list"].(string))
		switch at(in, 5) {
		case "File":
			ev.Model = "Filesystem"
			f["file_path"] = name
			f["file_name"] = baseName(name)
		case "Key":
			ev.Model = "Registry"
			f["registry_path"] = name
			f["registry_key_name"] = baseName(name)
		}
	case "4720", "4726":
		ev.Model = "Change"
		f["object"] = at(in, 0)
		f["object_category"] = "user"
		f["user"] = at(in, 4)
		f["action"] = map[string]string{"4720": "created", "4726": "deleted"}[eventID]
		f["signature"] = map[string]string{
			"4720": "A user account was created",
			"4726": "A user account was deleted",
		}[eventID]
	case "4728", "4732", "4756":
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "group"
		f["signature"] = "A member was added to a security-enabled group"
		f["member"] = at(in, 0)
		f["object"] = at(in, 2)
		f["user"] = at(in, 6)
	}
}

// SystemChannel is the Windows System log, where the Service Control
// Manager records services being installed.
const SystemChannel = "System"

// ServiceControlManager is the provider of the System log's service
// events.
const ServiceControlManager = "Service Control Manager"

// parseWindowsSystem reads the System log events the parser knows: a
// service installed (7045). Event IDs belong to their provider, so only
// the Service Control Manager's 7045 is one; a record without a provider
// is taken as its.
func parseWindowsSystem(eventID, provider string, in []string, ev *Event) {
	f := ev.Fields
	if provider != "" {
		f["provider"] = provider
	}
	if eventID != "7045" || (provider != "" && !strings.EqualFold(provider, ServiceControlManager)) {
		return
	}
	f["provider"] = ServiceControlManager
	ev.Model = "Change"
	f["action"] = "created"
	f["object_category"] = "service"
	f["signature"] = "A service was installed in the system"
	f["object"] = at(in, 0)
	f["service_name"] = at(in, 0)
	f["service_path"] = at(in, 1)
	f["service_type"] = at(in, 2)
	f["service_start_type"] = at(in, 3)
	f["service_account"] = at(in, 4)
}

// objectAccessAction is what an object access did, from its access list
// (%%1537 DELETE, %%4417 WriteData, %%4418 AppendData, %%4420
// WriteExtendedAttributes, %%4424 WriteAttributes); anything else reads.
func objectAccessAction(list string) string {
	codes := strings.Fields(list)
	switch {
	case slices.Contains(codes, "%%1537"):
		return "deleted"
	case slices.ContainsFunc(codes, func(c string) bool {
		return c == "%%4417" || c == "%%4418" || c == "%%4420" || c == "%%4424"
	}):
		return "modified"
	}
	return "read"
}

// taskElement is the text of a scheduled task's first element named tag
// (what its first action runs), or "".
func taskElement(task, tag string) string {
	_, rest, ok := strings.Cut(task, "<"+tag+">")
	if !ok {
		return ""
	}
	v, _, ok := strings.Cut(rest, "</"+tag+">")
	if !ok {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(v))
}

func parseSysmon(eventID string, kv map[string]string, ev *Event) {
	f := ev.Fields
	f["vendor_product"] = "Microsoft Sysmon"
	switch eventID {
	case "1":
		ev.Model = "Endpoint"
		f["action"] = "allowed"
		f["signature"] = "Process Create"
		f["user"] = kv["User"]
		f["process"] = kv["CommandLine"]
		f["process_path"] = kv["Image"]
		f["process_name"] = baseName(kv["Image"])
		f["process_id"] = atoi(kv["ProcessId"])
		f["process_hash"] = kv["Hashes"]
		splitHashes(kv["Hashes"], f)
		f["parent_process"] = kv["ParentCommandLine"]
		f["parent_process_path"] = kv["ParentImage"]
		f["parent_process_name"] = baseName(kv["ParentImage"])
		f["parent_process_id"] = atoi(kv["ParentProcessId"])
		f["parent_user"] = kv["ParentUser"]
		// The PE header fields Sigma rules match on: a renamed binary keeps
		// its OriginalFileName.
		f["original_file_name"] = kv["OriginalFileName"]
		f["process_description"] = kv["Description"]
		f["process_product"] = kv["Product"]
		f["process_company"] = kv["Company"]
		f["process_file_version"] = kv["FileVersion"]
		f["process_integrity_level"] = kv["IntegrityLevel"]
		f["process_current_directory"] = kv["CurrentDirectory"]
		f["process_guid"] = kv["ProcessGuid"]
		f["parent_process_guid"] = kv["ParentProcessGuid"]
		f["logon_id"] = kv["LogonId"]
	case "3":
		ev.Model = "Network_Traffic"
		f["action"] = "allowed"
		f["signature"] = "Network connection detected"
		f["user"] = kv["User"]
		f["transport"] = strings.ToLower(kv["Protocol"])
		f["src"] = kv["SourceIp"]
		f["src_port"] = atoi(kv["SourcePort"])
		f["dest"] = kv["DestinationIp"]
		f["dest_host"] = kv["DestinationHostname"]
		f["dest_port"] = atoi(kv["DestinationPort"])
		f["process_name"] = baseName(kv["Image"])
		f["process_path"] = kv["Image"]
		f["process_guid"] = kv["ProcessGuid"]
		f["src_host"] = kv["SourceHostname"]
		switch strings.ToLower(kv["Initiated"]) {
		case "true":
			f["direction"] = "outbound"
		case "false":
			f["direction"] = "inbound"
		}
	case "6", "7":
		// Driver load (6) and image (DLL) load (7).
		ev.Model = "Image_Load"
		f["signature"] = kv["Signature"]
		f["signed"] = strings.ToLower(kv["Signed"])
		f["signature_status"] = kv["SignatureStatus"]
		f["loaded_file_path"] = kv["ImageLoaded"]
		f["loaded_file_name"] = baseName(kv["ImageLoaded"])
		if eventID == "7" {
			sysmonProcess(kv, f)
		}
	case "8", "10":
		// Remote thread created (8) and process accessed (10): the source
		// process acts on the target.
		ev.Model = "Endpoint"
		f["signature"] = "Process accessed"
		if eventID == "8" {
			f["signature"] = "Remote thread created"
		}
		f["user"] = kv["SourceUser"]
		f["process_path"] = kv["SourceImage"]
		f["process_name"] = baseName(kv["SourceImage"])
		f["process_id"] = atoi(kv["SourceProcessId"])
		f["process_guid"] = firstOf(kv["SourceProcessGuid"], kv["SourceProcessGUID"])
		f["target_process_path"] = kv["TargetImage"]
		f["target_process_name"] = baseName(kv["TargetImage"])
		f["target_process_id"] = atoi(kv["TargetProcessId"])
		f["target_process_guid"] = firstOf(kv["TargetProcessGuid"], kv["TargetProcessGUID"])
		f["granted_access"] = kv["GrantedAccess"]
		f["call_trace"] = kv["CallTrace"]
		f["start_address"] = kv["StartAddress"]
		f["start_module"] = kv["StartModule"]
		f["start_function"] = kv["StartFunction"]
	case "11", "23", "26":
		// File created (11), deleted and archived (23), deleted (26).
		ev.Model = "Filesystem"
		f["action"] = "created"
		if eventID != "11" {
			f["action"] = "deleted"
		}
		f["file_path"] = kv["TargetFilename"]
		f["file_name"] = baseName(kv["TargetFilename"])
		sysmonProcess(kv, f)
		if h := sysmonHash(kv["Hashes"], "SHA256"); h != "" {
			f["file_hash"] = h
		}
	case "12", "13", "14":
		// Registry key or value created or deleted (12), value set (13),
		// key or value renamed (14).
		ev.Model = "Registry"
		f["action"] = registryActions[kv["EventType"]]
		path := kv["TargetObject"]
		f["registry_path"] = path
		if eventID == "12" && strings.HasSuffix(kv["EventType"], "Key") || eventID == "14" && kv["EventType"] == "RenameKey" {
			f["registry_key_name"] = baseName(path)
		} else {
			f["registry_value_name"] = baseName(path)
			f["registry_key_name"] = baseName(parentPath(path))
		}
		f["registry_value_data"] = kv["Details"]
		f["registry_new_path"] = kv["NewName"]
		sysmonProcess(kv, f)
	case "22":
		ev.Model = "Network_Resolution"
		f["query"] = kv["QueryName"]
		f["answer"] = kv["QueryResults"]
		f["reply_code"] = dnsStatus(kv["QueryStatus"])
		sysmonProcess(kv, f)
	}
}

// sysmonProcess sets the acting process of a Sysmon event that names it
// as Image.
func sysmonProcess(kv map[string]string, f map[string]any) {
	f["user"] = kv["User"]
	f["process_path"] = kv["Image"]
	f["process_name"] = baseName(kv["Image"])
	f["process_id"] = atoi(kv["ProcessId"])
	f["process_guid"] = kv["ProcessGuid"]
}

// registryActions maps Sysmon's registry EventType onto the Registry
// data model's action.
var registryActions = map[string]string{
	"CreateKey": "created", "DeleteKey": "deleted", "DeleteValue": "deleted",
	"SetValue": "modified", "RenameKey": "renamed",
}

// dnsStatus names Sysmon's QueryStatus, a Windows error code (0 for
// success, 9003 for a name that does not exist), as the reply codes DNS
// servers log; other codes stay numbers.
func dnsStatus(code string) string {
	switch code {
	case "0":
		return "NoError"
	case "9003", "123":
		return "NXDomain"
	case "9002":
		return "ServFail"
	case "9004":
		return "NotImp"
	case "9005":
		return "Refused"
	}
	return code
}

// parentPath drops the last \-separated part of a path.
func parentPath(p string) string {
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[:i]
	}
	return ""
}

func firstOf(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// sysmonHash returns one hash, lower case, from a Sysmon Hashes list.
func sysmonHash(v, kind string) string {
	for _, part := range strings.Split(v, ",") {
		k, h, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(k, kind) {
			return strings.ToLower(h)
		}
	}
	return ""
}

// splitHashes copies each hash of a Sysmon "SHA256=..,MD5=.." list into
// process_md5, process_sha1 and process_sha256 in lower case, so threat
// intel and searches can match one hash exactly.
func splitHashes(v string, f map[string]any) {
	for _, part := range strings.Split(v, ",") {
		k, h, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || h == "" {
			continue
		}
		switch strings.ToUpper(k) {
		case "MD5":
			f["process_md5"] = strings.ToLower(h)
		case "SHA1":
			f["process_sha1"] = strings.ToLower(h)
		case "SHA256":
			f["process_sha256"] = strings.ToLower(h)
		}
	}
}

// multiLine are the Sysmon fields whose values can run over several
// lines: a command line can hold a whole script.
var multiLine = map[string]bool{"CommandLine": true, "ParentCommandLine": true, "Details": true}

// keyValues parses "Key: Value" lines from a rendered event message. The
// first value of a key is kept. A line that is not a "Key: Value" line
// continues a multi-line value (a command line with line breaks in it,
// blank lines included) up to the next key line.
func keyValues(msg string) map[string]string {
	out := map[string]string{}
	cont := "" // the multi-line key being continued
	for _, raw := range strings.Split(msg, "\n") {
		line := strings.TrimSpace(raw)
		k, v, ok := strings.Cut(line, ":")
		isKey := ok && k != "" && !strings.ContainsAny(k, " \t") && (v == "" || v[0] == ' ' || v[0] == '\t')
		if !isKey {
			if cont != "" {
				out[cont] += "\n" + strings.TrimRight(raw, "\r")
			}
			continue
		}
		cont = ""
		if _, exists := out[k]; !exists {
			out[k] = strings.TrimSpace(v)
			if multiLine[k] {
				cont = k
			}
		}
	}
	return out
}
