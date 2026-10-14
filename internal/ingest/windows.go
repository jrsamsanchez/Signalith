package ingest

import (
	"html"
	"slices"
	"strconv"
	"strings"
	"unicode"
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
		// The provider that wrote it: the Event Log service writes the
		// log cleared (1102), the auditing system the rest.
		if p := str(r, "ProviderName"); p != "" {
			f["provider"] = p
		}
		parseWindowsSecurity(eventID, in, &ev)
	case channel == SystemChannel:
		parseWindowsSystem(eventID, str(r, "ProviderName"), in, &ev)
		if b := str(r, "Binary"); b != "" && ev.Model == "Other" {
			// The event's binary data, which the OpenTelemetry
			// Collector sends: for a service event, the service's name
			// in UTF-16 hex.
			f["system_binary"] = strings.ToLower(b)
		}
	case strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational"):
		kv := keyValues(str(r, "Message"))
		for k, v := range named {
			kv[k] = v
		}
		// The provider that wrote it (Microsoft-Windows-Sysmon), which
		// rules use to tell Sysmon's events from other sources'.
		if p := str(r, "ProviderName"); p != "" {
			f["provider"] = p
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
			// The account that asked for the logon, and the details newer
			// Windows versions add: the impersonation level and elevation
			// as message codes (%%1833 is Impersonation, %%1842 Yes), and
			// for a new credentials logon (type 9, runas /netonly) the
			// account used on the network.
			f["src_user_sid"] = at(in, 0)
			f["src_user"] = at(in, 1)
			f["src_user_domain"] = at(in, 2)
			f["key_length"] = atoi(at(in, 15))
			f["impersonation_level"] = at(in, 20)
			f["restricted_admin_mode"] = at(in, 21)
			f["target_outbound_user"] = at(in, 22)
			f["target_outbound_domain"] = at(in, 23)
			f["virtual_account"] = at(in, 24)
			f["elevated_token"] = at(in, 26)
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
	case "4648":
		// A logon with explicit credentials (runas, or a program passing
		// another account's password): the account that acted is
		// src_user, the one it used user, on the server it named.
		ev.Model = "Authentication"
		f["app"] = "win:local"
		f["signature"] = "A logon was attempted using explicit credentials"
		f["user_sid"] = at(in, 0)
		f["src_user"] = at(in, 1)
		f["src_user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["user"] = at(in, 5)
		f["user_domain"] = at(in, 6)
		f["dest"] = at(in, 8)
		f["target_info"] = at(in, 9)
		f["process_id"] = atoi(at(in, 10))
		f["process_path"] = at(in, 11)
		f["process_name"] = baseName(at(in, 11))
		f["src"] = at(in, 12)
		f["src_port"] = atoi(at(in, 13))
	case "5156", "5157":
		// A connection the Windows Filtering Platform allowed (5156) or
		// blocked (5157), with Audit Filtering Platform Connection on.
		// The program is a device path (\device\harddiskvolume2\...).
		ev.Model = "Network_Traffic"
		f["action"] = map[string]string{"5156": "allowed", "5157": "blocked"}[eventID]
		f["signature"] = map[string]string{
			"5156": "The Windows Filtering Platform has permitted a connection",
			"5157": "The Windows Filtering Platform has blocked a connection",
		}[eventID]
		f["process_id"] = atoi(at(in, 0))
		f["process_path"] = at(in, 1)
		f["process_name"] = baseName(at(in, 1))
		// %%14592 is inbound, %%14593 outbound.
		f["direction"] = map[string]string{"%%14592": "inbound", "%%14593": "outbound"}[at(in, 2)]
		f["src"] = at(in, 3)
		f["src_port"] = atoi(at(in, 4))
		f["dest"] = at(in, 5)
		f["dest_port"] = atoi(at(in, 6))
		f["transport"] = map[string]string{"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp"}[at(in, 7)]
		f["filter_rtid"] = at(in, 8)
		f["layer_name"] = at(in, 9)
		f["layer_rtid"] = at(in, 10)
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
		// Newer Windows versions add the process that asked the Service
		// Control Manager and its parent.
		if len(in) > 10 {
			f["client_process_id"] = atoi(at(in, 10))
			f["parent_process_id"] = atoi(at(in, 11))
		}
	case "4656", "4661", "4663":
		// A handle to an object asked for (4656, or 4661 for a directory or
		// SAM object) or an access to it (4663), when its audit rule (SACL)
		// asks for it: a file goes to Filesystem and a registry key to
		// Registry. The three share the subject and object, then differ.
		f["signature"] = map[string]string{
			"4656": "A handle to an object was requested",
			"4661": "A handle to an object was requested",
			"4663": "An attempt was made to access an object",
		}[eventID]
		f["user_sid"] = at(in, 0)
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object_server"] = at(in, 4)
		f["object_type"] = at(in, 5)
		name := at(in, 6)
		f["object_path"] = name
		f["object_name"] = baseName(name)
		list, mask, pid, proc := at(in, 8), at(in, 9), at(in, 10), at(in, 11)
		switch eventID {
		case "4656":
			list, mask, pid, proc = at(in, 9), at(in, 11), at(in, 14), at(in, 15)
		case "4661":
			list, mask, pid, proc = at(in, 9), at(in, 10), at(in, 14), at(in, 15)
			f["object_properties"] = strings.Join(strings.Fields(at(in, 12)), " ")
		}
		f["access_list"] = strings.Join(strings.Fields(list), " ")
		f["access_mask"] = mask
		f["process_id"] = atoi(pid)
		f["process_path"] = proc
		f["process_name"] = baseName(proc)
		f["access_names"] = accessNames(f["access_list"].(string))
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
	case "4657":
		// A registry value changed, when the key's audit rule asks for it:
		// the key, the value's name and its old and new data.
		ev.Model = "Registry"
		f["signature"] = "A registry value was modified"
		f["user_sid"] = at(in, 0)
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		key, value := at(in, 4), at(in, 5)
		f["object_path"] = key
		f["registry_path"] = key + `\` + value
		f["registry_key_name"] = baseName(key)
		f["registry_value_name"] = value
		// %%1904 is a value created, %%1905 changed and %%1906 deleted.
		f["registry_operation"] = at(in, 7)
		f["action"] = map[string]string{"%%1904": "created", "%%1906": "deleted"}[at(in, 7)]
		if f["action"] == "" {
			f["action"] = "modified"
		}
		f["registry_value_type"] = at(in, 10)
		f["registry_old_value_data"] = at(in, 9)
		f["registry_value_data"] = at(in, 11)
		f["process_id"] = atoi(at(in, 12))
		f["process_path"] = at(in, 13)
		f["process_name"] = baseName(at(in, 13))
	case "4662":
		// An operation on an object a directory service or WMI audits
		// (with Audit Directory Service Access on): reading a property,
		// say, or a control access right such as replicating changes.
		// Directory objects and classes are %{GUID}s, kept as recorded.
		ev.Model = "Change"
		f["signature"] = "An operation was performed on an object"
		f["user_sid"] = at(in, 0)
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object_server"] = at(in, 4)
		f["object_category"] = "object"
		if at(in, 4) == "DS" {
			f["object_category"] = "directory_object"
		}
		f["object_type"] = at(in, 5)
		f["object"] = at(in, 6)
		f["access_list"] = strings.Join(strings.Fields(at(in, 9)), " ")
		f["access_mask"] = at(in, 10)
		f["access_names"] = accessNames(f["access_list"].(string))
		f["object_properties"] = strings.Join(strings.Fields(at(in, 11)), " ")
		f["action"] = objectAccessAction(f["access_list"].(string))
	case "4768", "4769":
		// A Kerberos ticket asked of a domain controller: a ticket-granting
		// ticket (4768, a logon to the domain) or a service ticket (4769).
		// Status 0x0 is granted, anything else a failure code. An IPv4
		// client is recorded as ::ffff:a.b.c.d, stored as a.b.c.d.
		ev.Model = "Authentication"
		f["app"] = "win:kerberos"
		f["authentication_method"] = "Kerberos"
		f["user"] = at(in, 0)
		f["user_domain"] = at(in, 1)
		var status string
		if eventID == "4768" {
			f["signature"] = "A Kerberos authentication ticket (TGT) was requested"
			f["user_sid"] = at(in, 2)
			f["kerberos_service"] = at(in, 3)
			f["kerberos_service_sid"] = at(in, 4)
			f["ticket_options"] = at(in, 5)
			status = at(in, 6)
			f["ticket_encryption_type"] = at(in, 7)
			f["pre_auth_type"] = at(in, 8)
			f["src"] = strings.TrimPrefix(at(in, 9), "::ffff:")
			f["src_port"] = atoi(at(in, 10))
			f["cert_issuer"] = at(in, 11)
			f["cert_serial"] = at(in, 12)
			f["cert_thumbprint"] = at(in, 13)
		} else {
			f["signature"] = "A Kerberos service ticket was requested"
			f["kerberos_service"] = at(in, 2)
			f["kerberos_service_sid"] = at(in, 3)
			f["ticket_options"] = at(in, 4)
			f["ticket_encryption_type"] = at(in, 5)
			f["src"] = strings.TrimPrefix(at(in, 6), "::ffff:")
			f["src_port"] = atoi(at(in, 7))
			status = at(in, 8)
		}
		f["kerberos_status"] = status
		f["action"] = "failure"
		if status == "0x0" {
			f["action"] = "success"
		}
	case "5145":
		// A file or named pipe on a network share, checked for the access
		// a client asked for (with Audit Detailed File Share on). The
		// path is relative to the share.
		ev.Model = "Filesystem"
		f["signature"] = "A network share object was checked to see whether client can be granted desired access"
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["object_type"] = at(in, 4)
		f["src"] = at(in, 5)
		f["src_port"] = atoi(at(in, 6))
		f["share_name"] = at(in, 7)
		f["share_path"] = at(in, 8)
		f["share_target"] = at(in, 9)
		f["file_path"] = at(in, 9)
		f["file_name"] = baseName(at(in, 9))
		f["access_mask"] = at(in, 10)
		f["access_list"] = strings.Join(strings.Fields(at(in, 11)), " ")
		f["access_names"] = accessNames(f["access_list"].(string))
		f["action"] = objectAccessAction(f["access_list"].(string))
	case "5136":
		// A directory service object changed (with Audit Directory
		// Service Changes on): one attribute value added or deleted.
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "directory_object"
		f["signature"] = "A directory service object was modified"
		f["user"] = at(in, 3)
		f["user_domain"] = at(in, 4)
		f["logon_id"] = at(in, 5)
		f["object"] = at(in, 8)
		f["ad_object_guid"] = strings.Trim(at(in, 9), "{}")
		f["ad_object_class"] = at(in, 10)
		f["ad_attribute"] = at(in, 11)
		f["ad_value"] = at(in, 13)
		// %%14674 is a value added, %%14675 a value deleted.
		f["ad_operation"] = at(in, 14)
	case "4720", "4726", "4738":
		// A user account created, deleted or changed: the account, then
		// who did it, then (4720 and 4738) its attributes, "-" when a
		// change left one as it was. 4738 starts with an unused value.
		ev.Model = "Change"
		f["object_category"] = "user"
		f["action"] = map[string]string{"4720": "created", "4726": "deleted", "4738": "modified"}[eventID]
		f["signature"] = map[string]string{
			"4720": "A user account was created",
			"4726": "A user account was deleted",
			"4738": "A user account was changed",
		}[eventID]
		if eventID == "4738" {
			in = in[min(1, len(in)):]
		}
		f["object"] = at(in, 0)
		f["object_domain"] = at(in, 1)
		f["object_sid"] = at(in, 2)
		f["user_sid"] = at(in, 3)
		f["user"] = at(in, 4)
		f["user_domain"] = at(in, 5)
		f["logon_id"] = at(in, 6)
		if eventID != "4726" {
			f["sam_account_name"] = at(in, 8)
			f["display_name"] = at(in, 9)
			f["user_principal_name"] = at(in, 10)
			f["primary_group_id"] = at(in, 18)
			f["allowed_to_delegate_to"] = at(in, 19)
			f["old_uac_value"] = at(in, 20)
			f["new_uac_value"] = at(in, 21)
			f["user_account_control"] = strings.Join(strings.Fields(at(in, 22)), " ")
			f["sid_history"] = at(in, 24)
		}
	case "4728", "4732", "4756":
		// A member added to a global (4728), local (4732) or universal
		// (4756) security group.
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "group"
		f["signature"] = "A member was added to a security-enabled group"
		f["member"] = at(in, 0)
		f["member_sid"] = at(in, 1)
		f["object"] = at(in, 2)
		f["object_domain"] = at(in, 3)
		f["object_sid"] = at(in, 4)
		f["user_sid"] = at(in, 5)
		f["user"] = at(in, 6)
		f["user_domain"] = at(in, 7)
		f["logon_id"] = at(in, 8)
	case "4719":
		// The audit policy changed: which subcategory and what was
		// turned on or off (%%8448 success removed, %%8450 failure
		// removed, %%8449 success added, %%8451 failure added).
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "audit_policy"
		f["signature"] = "System audit policy was changed"
		f["user_sid"] = at(in, 0)
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["audit_category"] = at(in, 4)
		f["audit_subcategory"] = at(in, 5)
		f["object"] = at(in, 6)
		f["audit_subcategory_guid"] = at(in, 6)
		f["audit_policy_changes"] = strings.Join(strings.Fields(at(in, 7)), " ")
	case "4706":
		// A trust to a domain was created.
		ev.Model = "Change"
		f["action"] = "created"
		f["object_category"] = "domain_trust"
		f["signature"] = "A new trust was created to a domain"
		f["object"] = at(in, 0)
		f["object_sid"] = at(in, 1)
		f["trust_type"] = at(in, 2)
		f["trust_direction"] = at(in, 3)
		f["trust_attributes"] = at(in, 4)
		f["user_sid"] = at(in, 6)
		f["user"] = at(in, 7)
		f["user_domain"] = at(in, 8)
		f["logon_id"] = at(in, 9)
	case "4794":
		// A domain controller's Directory Services Restore Mode
		// administrator password was set.
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "user"
		f["object"] = "DSRM Administrator"
		f["signature"] = "An attempt was made to set the Directory Services Restore Mode administrator password"
		f["user_sid"] = at(in, 0)
		f["user"] = at(in, 1)
		f["user_domain"] = at(in, 2)
		f["logon_id"] = at(in, 3)
		f["src_host"] = at(in, 4)
	default:
		parseWindowsSecurityNamed(eventID, securityNamed(eventID, in), ev)
	}
}

// securityNamed is a Security event's data by name, from its values in
// schema order (windowsSchema).
func securityNamed(eventID string, in []string) map[string]string {
	names := windowsSchema[eventID]
	d := make(map[string]string, len(names))
	for i, n := range names {
		d[n] = at(in, i)
	}
	return d
}

// subject sets the account that acted (the event's Subject*).
func subject(d map[string]string, f map[string]any) {
	f["user_sid"] = d["SubjectUserSid"]
	f["user"] = d["SubjectUserName"]
	f["user_domain"] = d["SubjectDomainName"]
	f["logon_id"] = d["SubjectLogonId"]
}

// parseWindowsSecurityNamed reads the Security events parsed by their
// data names.
func parseWindowsSecurityNamed(eventID string, d map[string]string, ev *Event) {
	f := ev.Fields
	switch eventID {
	case "4776":
		// A domain controller (or the local SAM) checked an account's
		// password for NTLM: Status 0x0 is success, else why it failed.
		ev.Model = "Authentication"
		f["app"] = "win:local"
		f["signature"] = "The computer attempted to validate the credentials for an account"
		f["authentication_method"] = d["PackageName"]
		f["user"] = d["TargetUserName"]
		f["src_host"] = d["Workstation"]
		f["ntlm_status"] = d["Status"]
		f["action"] = "failure"
		if d["Status"] == "0x0" {
			f["action"] = "success"
		} else if reason, ok := windowsFailureReasons[strings.ToLower(d["Status"])]; ok {
			f["reason"] = reason
		}
	case "4771":
		// Kerberos pre-authentication failed: a wrong password (Status
		// 0x18) or another Kerberos error.
		ev.Model = "Authentication"
		f["app"] = "win:local"
		f["action"] = "failure"
		f["signature"] = "Kerberos pre-authentication failed"
		f["user"] = d["TargetUserName"]
		f["user_sid"] = d["TargetSid"]
		f["kerberos_service"] = d["ServiceName"]
		f["ticket_options"] = d["TicketOptions"]
		f["kerberos_status"] = d["Status"]
		f["pre_auth_type"] = d["PreAuthType"]
		f["src"] = strings.TrimPrefix(d["IpAddress"], "::ffff:")
		f["src_port"] = atoi(d["IpPort"])
		f["cert_issuer"] = d["CertIssuerName"]
		f["cert_serial"] = d["CertSerialNumber"]
		f["cert_thumbprint"] = d["CertThumbprint"]
	case "4741", "4742":
		// A computer account created or changed, with the attributes of
		// a user account and its DNS name and service principal names.
		ev.Model = "Change"
		f["object_category"] = "computer"
		f["action"] = map[string]string{"4741": "created", "4742": "modified"}[eventID]
		f["signature"] = map[string]string{
			"4741": "A computer account was created",
			"4742": "A computer account was changed",
		}[eventID]
		subject(d, f)
		f["object"] = d["TargetUserName"]
		f["object_domain"] = d["TargetDomainName"]
		f["object_sid"] = d["TargetSid"]
		f["sam_account_name"] = d["SamAccountName"]
		f["display_name"] = d["DisplayName"]
		f["user_principal_name"] = d["UserPrincipalName"]
		f["primary_group_id"] = d["PrimaryGroupId"]
		f["allowed_to_delegate_to"] = d["AllowedToDelegateTo"]
		f["old_uac_value"] = d["OldUacValue"]
		f["new_uac_value"] = d["NewUacValue"]
		f["user_account_control"] = strings.Join(strings.Fields(d["UserAccountControl"]), " ")
		f["sid_history"] = d["SidHistory"]
		f["dns_host_name"] = d["DnsHostName"]
		f["service_principal_names"] = strings.Join(strings.Fields(d["ServicePrincipalNames"]), " ")
	case "4781":
		// An account renamed: object is its new name.
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "user"
		f["signature"] = "The name of an account was changed"
		subject(d, f)
		f["object"] = d["NewTargetUserName"]
		f["old_object"] = d["OldTargetUserName"]
		f["object_domain"] = d["TargetDomainName"]
		f["object_sid"] = d["TargetSid"]
	case "4727", "4730", "4737":
		// A security-enabled global group created, deleted or changed.
		ev.Model = "Change"
		f["object_category"] = "group"
		f["action"] = map[string]string{"4727": "created", "4730": "deleted", "4737": "modified"}[eventID]
		f["signature"] = map[string]string{
			"4727": "A security-enabled global group was created",
			"4730": "A security-enabled global group was deleted",
			"4737": "A security-enabled global group was changed",
		}[eventID]
		subject(d, f)
		f["object"] = d["TargetUserName"]
		f["object_domain"] = d["TargetDomainName"]
		f["object_sid"] = d["TargetSid"]
		f["sam_account_name"] = d["SamAccountName"]
		f["sid_history"] = d["SidHistory"]
	case "4729":
		// A member removed from a security-enabled global group.
		ev.Model = "Change"
		f["action"] = "modified"
		f["object_category"] = "group"
		f["signature"] = "A member was removed from a security-enabled global group"
		subject(d, f)
		f["member"] = d["MemberName"]
		f["member_sid"] = d["MemberSid"]
		f["object"] = d["TargetUserName"]
		f["object_domain"] = d["TargetDomainName"]
		f["object_sid"] = d["TargetSid"]
	case "4798", "4799":
		// A user's local groups (4798) or a local group's members (4799)
		// listed, by the process that asked.
		ev.Model = "Change"
		f["action"] = "read"
		f["object_category"] = map[string]string{"4798": "user", "4799": "group"}[eventID]
		f["signature"] = map[string]string{
			"4798": "A user's local group membership was enumerated",
			"4799": "A security-enabled local group membership was enumerated",
		}[eventID]
		subject(d, f)
		f["object"] = d["TargetUserName"]
		f["object_domain"] = d["TargetDomainName"]
		f["object_sid"] = d["TargetSid"]
		f["process_id"] = atoi(d["CallerProcessId"])
		f["process_path"] = d["CallerProcessName"]
		f["process_name"] = baseName(d["CallerProcessName"])
	case "4886", "4887":
		// A certificate requested from Certificate Services (4886) and
		// issued (4887): who asked, and the request's attributes, such as
		// its template and any subject alternative name.
		ev.Model = "Change"
		f["object_category"] = "certificate"
		f["action"] = map[string]string{"4886": "requested", "4887": "created"}[eventID]
		f["signature"] = map[string]string{
			"4886": "Certificate Services received a certificate request",
			"4887": "Certificate Services approved a certificate request and issued a certificate",
		}[eventID]
		f["object"] = d["RequestId"]
		f["cert_request_id"] = d["RequestId"]
		f["cert_requester"] = d["Requester"]
		f["cert_attributes"] = d["Attributes"]
		f["cert_disposition"] = d["Disposition"]
		f["cert_subject_key_id"] = d["SubjectKeyIdentifier"]
		f["cert_subject"] = d["Subject"]
	case "1102":
		// The Security log cleared.
		ev.Model = "Change"
		f["action"] = "deleted"
		f["object_category"] = "audit_log"
		f["object"] = "Security"
		f["signature"] = "The audit log was cleared"
		subject(d, f)
	case "4699", "4701", "4702":
		// A scheduled task deleted, disabled or updated: its definition
		// (the new one for an update).
		ev.Model = "Change"
		f["object_category"] = "scheduled_task"
		f["action"] = map[string]string{"4699": "deleted", "4701": "modified", "4702": "modified"}[eventID]
		f["signature"] = map[string]string{
			"4699": "A scheduled task was deleted",
			"4701": "A scheduled task was disabled",
			"4702": "A scheduled task was updated",
		}[eventID]
		subject(d, f)
		content := firstOf(d["TaskContent"], d["TaskContentNew"])
		f["object"] = d["TaskName"]
		f["task_name"] = d["TaskName"]
		f["task_content"] = content
		f["task_command"] = taskElement(content, "Command")
		f["task_arguments"] = taskElement(content, "Arguments")
	case "5140":
		// A network share accessed (with Audit File Share on): once per
		// session, for the share as a whole.
		ev.Model = "Filesystem"
		f["signature"] = "A network share object was accessed"
		subject(d, f)
		f["object_type"] = d["ObjectType"]
		f["src"] = strings.TrimPrefix(d["IpAddress"], "::ffff:")
		f["src_port"] = atoi(d["IpPort"])
		f["share_name"] = d["ShareName"]
		f["share_path"] = d["ShareLocalPath"]
		f["access_mask"] = d["AccessMask"]
		f["access_list"] = strings.Join(strings.Fields(d["AccessList"]), " ")
		f["access_names"] = accessNames(f["access_list"].(string))
		f["action"] = objectAccessAction(f["access_list"].(string))
	}
}

// SystemChannel is the Windows System log, where the Service Control
// Manager records services being installed.
const SystemChannel = "System"

// ServiceControlManager is the provider of the System log's service
// events.
const ServiceControlManager = "Service Control Manager"

// parseWindowsSystem reads the System log events the parser knows: a
// service installed (7045), and the data of the other events
// systemEvents lists. Event IDs belong to their provider, so only the
// Service Control Manager's 7045 is one; a record without a provider is
// taken as its.
func parseWindowsSystem(eventID, provider string, in []string, ev *Event) {
	f := ev.Fields
	if provider != "" {
		f["provider"] = provider
	}
	if eventID != "7045" || (provider != "" && !strings.EqualFold(provider, ServiceControlManager)) {
		parseSystemEvent(eventID, provider, in, ev)
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

// systemEvent is a System log event the parser reads the data of: what
// it is, and the names of its data values in schema order.
type systemEvent struct {
	signature string
	data      []string
}

// systemEvents are the System log events, other than a service installed
// (7045), whose data the parser keeps, by provider (lower case) and
// event ID. Each data value is stored as SystemDataField names it.
var systemEvents = map[string]systemEvent{
	"service control manager|7023": {"A service terminated with an error", []string{"param1", "param2"}},
	"service control manager|7034": {"A service terminated unexpectedly", []string{"param1", "param2"}},
	"service control manager|7036": {"A service changed state", []string{"param1", "param2"}},
	"service control manager|7040": {"A service's start type changed", []string{"param1", "param2", "param3", "param4"}},
	"microsoft-windows-eventlog|104": {"An event log was cleared",
		[]string{"SubjectUserName", "SubjectDomainName", "Channel", "BackupPath"}},
	"microsoft-windows-kernel-general|16": {"A registry hive's access history was cleared",
		[]string{"HiveNameLength", "HiveName", "KeysUpdated", "DirtyPages"}},
	"application popup|26":                   {"An application popup was shown", []string{"Caption", "Message"}},
	"microsoft-windows-distributedcom|10001": {"A DCOM server could not start", []string{"param1", "param2", "param3"}},
}

// systemEventFor is the System log event of a provider ("" for the
// Service Control Manager) and event ID, if the parser reads its data.
func systemEventFor(provider, eventID string) (systemEvent, bool) {
	if provider == "" {
		provider = ServiceControlManager
	}
	e, ok := systemEvents[strings.ToLower(provider)+"|"+eventID]
	return e, ok
}

// SystemDataField is the stored field of a System log event's data value
// (param1 is system_param1, HiveName system_hive_name), for the values
// of the events the parser reads and their binary data (Binary).
func SystemDataField(name string) (string, bool) {
	f := systemField(name)
	return f, systemDataFields[f]
}

// systemField is system_ and a data value's name in snake case.
func systemField(name string) string {
	var b strings.Builder
	b.WriteString("system_")
	for i, r := range name {
		if unicode.IsUpper(r) && i > 0 && !unicode.IsUpper(rune(name[i-1])) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// systemDataFields are the fields SystemDataField names.
var systemDataFields = func() map[string]bool {
	out := map[string]bool{"system_binary": true}
	for _, e := range systemEvents {
		for _, n := range e.data {
			out[systemField(n)] = true
		}
	}
	return out
}()

// parseSystemEvent keeps the data of a System log event systemEvents
// lists, by name; the event stays in Other, found by its provider and ID.
func parseSystemEvent(eventID, provider string, in []string, ev *Event) {
	e, ok := systemEventFor(provider, eventID)
	if !ok {
		return
	}
	f := ev.Fields
	f["signature"] = e.signature
	for i, n := range e.data {
		if v := at(in, i); v != "" {
			f[systemField(n)] = v
		}
	}
	if eventID == "104" {
		// The account that cleared the log.
		f["user"] = at(in, 0)
		f["user_domain"] = at(in, 1)
	}
}

// accessRightNames are the names Windows shows for the access codes of
// an object access's access list.
var accessRightNames = map[string]string{
	"%%7680": "CreateChild", "%%7681": "DeleteChild", "%%7682": "ListContents", "%%7683": "WriteSelf",
	"%%7684": "ReadProperty", "%%7685": "WriteProperty", "%%7686": "DeleteTree", "%%7687": "ListObject",
	"%%7688": "ControlAccess",
	"%%1537": "DELETE", "%%1538": "READ_CONTROL", "%%1539": "WRITE_DAC", "%%1540": "WRITE_OWNER",
	"%%1541": "SYNCHRONIZE", "%%1542": "ACCESS_SYS_SEC",
	"%%4416": "ReadData", "%%4417": "WriteData", "%%4418": "AppendData", "%%4419": "ReadEA",
	"%%4420": "WriteEA", "%%4421": "Execute", "%%4422": "DeleteChild", "%%4423": "ReadAttributes",
	"%%4424": "WriteAttributes",
}

// accessNames is an access list followed by the names of its codes
// (%%4417 WriteData), so a search finds an access by its code, as the
// event records it, or by its name, as Windows shows it.
func accessNames(list string) string {
	out := strings.Fields(list)
	for _, c := range strings.Fields(list) {
		if n, ok := accessRightNames[c]; ok {
			out = append(out, n)
		}
	}
	return strings.Join(out, " ")
}

// objectAccessAction is what an object access did, from its access list
// (%%1537 DELETE and %%7686 DeleteTree; %%1539 WRITE_DAC, %%1540
// WRITE_OWNER, %%4417 WriteData, %%4418 AppendData, %%4420
// WriteExtendedAttributes, %%4424 WriteAttributes and %%7685
// WriteProperty); anything else reads.
func objectAccessAction(list string) string {
	codes := strings.Fields(list)
	switch {
	case slices.Contains(codes, "%%1537") || slices.Contains(codes, "%%7686"):
		return "deleted"
	case slices.ContainsFunc(codes, func(c string) bool {
		switch c {
		case "%%1539", "%%1540", "%%4417", "%%4418", "%%4420", "%%4424", "%%7685":
			return true
		}
		return false
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
		f["dest_port_name"] = kv["DestinationPortName"]
		f["process_name"] = baseName(kv["Image"])
		f["process_path"] = kv["Image"]
		f["process_guid"] = kv["ProcessGuid"]
		f["src_host"] = kv["SourceHostname"]
		f["src_is_ipv6"] = strings.ToLower(kv["SourceIsIpv6"])
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
		// The loaded file's hashes as Sysmon lists them (SHA256=...,
		// IMPHASH=...), and for a DLL its version information.
		f["loaded_file_hash"] = kv["Hashes"]
		if eventID == "7" {
			sysmonProcess(kv, f)
			f["loaded_original_file_name"] = kv["OriginalFileName"]
			f["loaded_file_description"] = kv["Description"]
			f["loaded_file_product"] = kv["Product"]
			f["loaded_file_company"] = kv["Company"]
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
	case "15":
		// An alternate data stream written (FileCreateStreamHash), such as
		// the Zone.Identifier a browser adds to a download: the stream's
		// path (file:stream), its SHA-256, every hash Sysmon logs
		// (SHA256=...,IMPHASH=...) and, for small text streams, its
		// contents.
		ev.Model = "Filesystem"
		f["action"] = "created"
		f["signature"] = "File stream created"
		f["file_path"] = kv["TargetFilename"]
		f["file_name"] = baseName(kv["TargetFilename"])
		sysmonProcess(kv, f)
		if h := sysmonHash(firstOf(kv["Hash"], kv["Hashes"]), "SHA256"); h != "" {
			f["file_hash"] = h
		}
		f["file_hashes"] = firstOf(kv["Hash"], kv["Hashes"])
		f["file_contents"] = kv["Contents"]
	case "5":
		ev.Model = "Endpoint"
		f["action"] = "stopped"
		f["signature"] = "Process terminated"
		sysmonProcess(kv, f)
	case "9":
		// A process reading a drive directly (\Device\HarddiskVolume2),
		// bypassing the file system.
		ev.Model = "Endpoint"
		f["signature"] = "RawAccessRead detected"
		f["device"] = kv["Device"]
		sysmonProcess(kv, f)
	case "17", "18":
		// A named pipe created (17) or connected to (18), by the process
		// that did it.
		ev.Model = "Endpoint"
		f["signature"] = "Pipe Created"
		if eventID == "18" {
			f["signature"] = "Pipe Connected"
		}
		f["pipe_name"] = kv["PipeName"]
		f["pipe_event_type"] = kv["EventType"]
		sysmonProcess(kv, f)
	case "12", "13", "14":
		// Registry key or value created or deleted (12), value set (13),
		// key or value renamed (14).
		ev.Model = "Registry"
		f["action"] = registryActions[kv["EventType"]]
		f["registry_event_type"] = kv["EventType"]
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
