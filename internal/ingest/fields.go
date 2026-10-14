package ingest

import (
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// Every field name an event brings becomes a field in its daily index's
// mapping, and OpenSearch caps how many one index can have (the template
// sets index.mapping.total_fields.limit). The parsers emit a fixed set of
// names, but generic JSON records, syslog structured data and CEF
// extensions carry names the sender chooses. Without limits, one sender
// inventing names could fill a day's mapping, after which OpenSearch
// rejects every event that brings a field not yet mapped, including
// legitimate ones. So names other than the known ones below are checked
// and budgeted; the ones that do not pass are dropped from the event and
// counted, and their values stay in the raw message.
const (
	// maxFieldNameLen is the longest sender-chosen field name kept.
	maxFieldNameLen = 128
	// maxFieldDepth is how many dot-separated parts a name may have;
	// OpenSearch maps each part as an object field.
	maxFieldDepth = 5
	// maxFieldsPerEvent caps the fields of one event. Known fields are
	// always kept.
	maxFieldsPerEvent = 200
	// maxNewNamesPerIndex caps the field names (counting each dotted
	// prefix, as OpenSearch does) that events may add to one daily index
	// beyond the known fields, for all servers together: each server that
	// stored events in the last 10 minutes gets an equal share, and at
	// least minNamesPerServer (see Pipeline.Servers). With the known
	// fields it stays well under the template's limit of 2000, which
	// leaves room for names added before a restart.
	maxNewNamesPerIndex = 1000
	// minNamesPerServer is the smallest share of maxNewNamesPerIndex one
	// server gets, however many share it. Past a handful of servers the
	// shares add up to more than the budget, and the mapping guard
	// (mappingStop) keeps the index under OpenSearch's limit.
	minNamesPerServer = 100
)

// namesBudget is one server's share of maxNewNamesPerIndex when servers
// store events.
func namesBudget(servers int) int {
	return max(minNamesPerServer, maxNewNamesPerIndex/max(servers, 1))
}

// knownFields maps the field names Signalith itself produces to their
// OpenSearch types. The index template maps every one of them up front, so
// a sender cannot give one a different type first, and an event made only
// of known fields can always be stored however full the mapping is.
var knownFields = func() map[string]string {
	const kw, long, double = "keyword", "long", "double"
	m := map[string]string{
		"@timestamp":     "date",
		"message":        "text",
		"datamodel":      kw,
		"device_time":    kw,
		"dropped_fields": long,

		// The marker on every event and risk event the "Load sample data"
		// feature writes (datamodel.SampleField). It is mapped up front so it
		// survives the known-fields-only retry and never uses a day's
		// new-name budget; handleFields leaves it out of the fields rail.
		datamodel.SampleField: kw,

		// Where each event came from (origin.go): mapped up front so they
		// survive the known-fields-only retry.
		IntakeField: kw, TokenField: kw, TokenIDField: kw, SenderField: kw,

		// Windows and Linux parsers.
		"src_host": kw, "logon_type_name": kw, "member": kw,
		// Sysmon process fields that Sigma rules match on.
		"original_file_name": kw, "process_description": kw, "process_product": kw,
		"process_company": kw, "process_file_version": kw, "process_integrity_level": kw,
		"process_current_directory": kw, "process_guid": kw, "parent_process_guid": kw,
		"parent_process_id": long, "parent_user": kw, "logon_id": kw,
		// Sysmon fields not yet in a data model: the call stack of a process
		// access, where a remote thread starts, and a registry rename's new
		// name.
		"call_trace": kw, "start_address": kw, "start_module": kw, "start_function": kw,
		"registry_new_path": kw, "registry_event_type": kw,
		"loaded_file_hash": kw, "loaded_original_file_name": kw, "loaded_file_description": kw,
		"loaded_file_product": kw, "loaded_file_company": kw,
		// PowerShell script blocks: which part of a long script an event is,
		// and its text. Script blocks run to 20,000 characters, past what a
		// keyword indexes, and rules match words inside them, so the text is
		// a wildcard field (see IndexTemplate).
		"script_part": long, "script_parts": long, "script_block_text": "wildcard",
		// A scheduled task (Security 4698): its name and its definition,
		// XML that rules search for words inside, as for script blocks.
		"task_name": kw, "task_content": "wildcard", "task_command": kw, "task_arguments": kw,
		// An object access (Security 4663): what kind of object, its path
		// and name whatever the kind, and the access asked for.
		"object_type": kw, "object_path": kw, "object_name": kw, "access_list": kw, "access_mask": kw,
		// A service installed (System 7045): its name, the command it runs
		// (a path, or a whole command line), its type, start type and
		// account, and the log's provider.
		"service_name": kw, "service_path": kw, "service_type": kw, "service_start_type": kw, "service_account": kw,
		"provider": kw,
		// Whether a Sysmon network connection's source is an IPv6 address,
		// and the service name of its destination port (smtp, ftp).
		"src_is_ipv6": kw, "dest_port_name": kw,
		// A Sysmon named pipe event (17, 18): the pipe and whether it was
		// created or connected to. An alternate data stream's (Sysmon 15)
		// hashes as Sysmon lists them, and its contents, text that rules
		// search for words inside.
		"pipe_name": kw, "pipe_event_type": kw, "file_hashes": kw, "file_contents": "wildcard",
		// A logon's (Security 4624 and 4625) logon process and account SID,
		// and for a 4624 the SID of the account that asked for it, its key
		// length, impersonation level, elevation and outbound account.
		"logon_process": kw, "user_sid": kw, "src_user_sid": kw, "key_length": long, "impersonation_level": kw,
		"restricted_admin_mode": kw, "target_outbound_user": kw, "target_outbound_domain": kw, "virtual_account": kw,
		"elevated_token": kw,
		// The process that asked for a service install (Security 4697).
		"client_process_id": long,
		// An object access's access list with the names of its codes
		// added (WriteData for %%4417), a network share access (Security 5145) and a directory
		// object change (Security 5136), whose values (security
		// descriptors) rules search words inside.
		"access_names": kw, "share_name": kw, "share_path": kw, "share_target": kw,
		"ad_object_guid": kw, "ad_object_class": kw, "ad_attribute": kw, "ad_value": "wildcard", "ad_operation": kw,
		// A handle asked for or an operation on an object (Security 4656,
		// 4661 and 4662): the server that owns it and its properties; a
		// registry value changed (4657); a Kerberos ticket asked for
		// (4768 and 4769); a logon with explicit credentials (4648); a
		// connection the filtering platform allowed or blocked (5156, 5157).
		"object_server": kw, "object_properties": kw, "src_user_domain": kw, "target_info": kw,
		"filter_rtid": kw, "layer_name": kw, "layer_rtid": kw,
		// User accounts and groups changed (Security 4720, 4726, 4728,
		// 4732, 4738, 4756), the audit policy changed (4719) and a domain
		// trust created (4706).
		"object_domain": kw, "object_sid": kw, "member_sid": kw, "sam_account_name": kw, "display_name": kw,
		"user_principal_name": kw, "primary_group_id": kw, "allowed_to_delegate_to": kw, "old_uac_value": kw,
		"new_uac_value": kw, "user_account_control": kw, "sid_history": kw, "audit_category": kw,
		"audit_subcategory": kw, "audit_subcategory_guid": kw, "audit_policy_changes": kw, "trust_type": kw,
		"trust_direction": kw, "trust_attributes": kw,
		"registry_operation": kw, "registry_value_type": kw, "registry_old_value_data": kw,
		"kerberos_service": kw, "kerberos_service_sid": kw, "kerberos_status": kw, "ticket_options": kw,
		"ticket_encryption_type": kw, "pre_auth_type": kw, "cert_issuer": kw, "cert_serial": kw, "cert_thumbprint": kw,
		// NTLM credential checks (4776), computer accounts (4741, 4742), an
		// account renamed (4781), certificates requested and issued
		// (4886, 4887) and Sysmon's raw disk reads (9).
		"ntlm_status": kw, "dns_host_name": kw, "service_principal_names": "wildcard", "old_object": kw,
		"cert_request_id": kw, "cert_requester": kw, "cert_attributes": "wildcard", "cert_disposition": kw,
		"cert_subject_key_id": kw, "cert_subject": kw, "device": kw,
		// The data of the System log events the parser reads besides
		// services installed (systemEvents), by name (SystemDataField).
		"system_param1": kw, "system_param2": kw, "system_param3": kw, "system_param4": kw, "system_binary": kw,
		"system_subject_user_name": kw, "system_subject_domain_name": kw, "system_channel": kw,
		"system_backup_path": kw, "system_hive_name_length": kw, "system_hive_name": kw, "system_keys_updated": kw,
		"system_dirty_pages": kw, "system_caption": kw, "system_message": "wildcard",
		// An Application log event's data values, one per line.
		"event_data": "wildcard",
		// The data of Windows Firewall, BITS, AppX deployment and WMI
		// events, by name (ChannelDataField): firewall rules and settings
		// changed, transfer jobs, app packages installed and WMI
		// subscriptions.
		"firewall_action": kw, "firewall_active": kw, "firewall_application_path": kw, "firewall_direction": kw,
		"firewall_edge_traversal": kw, "firewall_embedded_context": kw, "firewall_error_code": kw, "firewall_flags": kw,
		"firewall_local_addresses": kw, "firewall_local_only_mapped": kw, "firewall_local_ports": kw,
		"firewall_loose_source_mapped": kw, "firewall_modifying_application": kw, "firewall_modifying_user": kw,
		"firewall_origin": kw, "firewall_policy_app_id": kw, "firewall_profiles": kw, "firewall_protocol": kw,
		"firewall_remote_addresses": kw, "firewall_remote_machine_authorization_list": kw, "firewall_remote_ports": kw,
		"firewall_remote_user_authorization_list": kw, "firewall_rule_id": kw, "firewall_rule_name": kw,
		"firewall_rule_status": kw, "firewall_schema_version": kw, "firewall_security_options": kw,
		"firewall_service_name": kw, "firewall_setting_type": kw, "firewall_setting_value": kw,
		"firewall_setting_value_display": kw, "firewall_setting_value_size": kw, "firewall_setting_value_string": kw,
		"firewall_store_type":           kw,
		"bits_client_process_start_key": kw, "bits_file_count": kw, "bits_job_id": kw, "bits_job_owner": kw,
		"bits_job_title": kw, "bits_local_name": kw, "bits_process_id": kw, "bits_process_path": kw,
		"bits_remote_name": kw, "bits_user": kw,
		"appx_calling_process": kw, "appx_deployment_operation": kw, "appx_deployment_options": kw,
		"appx_detailed_message_info": kw, "appx_error_code": kw, "appx_error_file_info": kw, "appx_external_location": kw,
		"appx_flags": kw, "appx_flags_high": kw, "appx_has_full_trust": kw, "appx_has_win32alacarte": kw,
		"appx_is_centennial": kw, "appx_is_in_place_update": kw, "appx_is_in_related_set": kw, "appx_is_optional": kw,
		"appx_is_package_encrypted": kw, "appx_is_package_using_bdc": kw, "appx_is_streaming_package": kw,
		"appx_main_package_family_name": kw, "appx_mount_point": kw, "appx_package_display_name": kw,
		"appx_package_flags": kw, "appx_package_flags2": kw, "appx_package_full_name": kw, "appx_package_source_uri": kw,
		"appx_package_type": kw, "appx_path": kw, "appx_policy_reason": kw, "appx_rollback_detailed_message_info": kw,
		"appx_rollback_error_file_info": kw, "appx_storage_id": kw, "appx_system_volume": kw, "appx_target_platform": kw,
		"wmi_client_machine": kw, "wmi_client_process_id": kw, "wmi_component": kw, "wmi_consumer": kw, "wmi_ess": kw,
		"wmi_id": kw, "wmi_namespace": kw, "wmi_namespace_name": kw, "wmi_operation": kw, "wmi_possible_cause": kw,
		"wmi_processid": kw, "wmi_provider_name": kw, "wmi_query": kw, "wmi_queryid": kw, "wmi_result_code": kw,
		"wmi_user": kw,
		// Linux audit records (auditd.go): each field as auditd names it,
		// the names of an ENRICHED record's numbers (auditd_uid_name), and
		// a program's arguments one by one and joined, which rules search
		// for words inside, as they do its command line (proctitle).
		"auditd_type": kw, "auditd_id": kw, "auditd_argc": kw, "auditd_execve_command": "wildcard", "auditd_proctitle": "wildcard",
		"auditd_syscall": kw, "auditd_syscall_name": kw, "auditd_arch": kw, "auditd_arch_name": kw, "auditd_success": kw,
		"auditd_exit": kw, "auditd_exe": kw, "auditd_comm": kw, "auditd_key": kw, "auditd_name": kw, "auditd_nametype": kw,
		"auditd_cwd": kw, "auditd_unit": kw, "auditd_op": kw, "auditd_res": kw, "auditd_acct": kw, "auditd_pid": kw,
		"auditd_ppid": kw, "auditd_uid": kw, "auditd_euid": kw, "auditd_auid": kw, "auditd_gid": kw, "auditd_uid_name": kw,
		"auditd_euid_name": kw, "auditd_auid_name": kw, "auditd_gid_name": kw, "auditd_tty": kw, "auditd_ses": kw,
		"auditd_hostname": kw, "auditd_addr": kw, "auditd_terminal": kw, "auditd_data": "wildcard", "auditd_items": kw,
		"auditd_mode": kw, "auditd_ouid": kw, "auditd_ouid_name": kw, "auditd_subj": kw,
		"auditd_a0": kw, "auditd_a1": kw, "auditd_a2": kw, "auditd_a3": kw, "auditd_a4": kw, "auditd_a5": kw, "auditd_a6": kw, "auditd_a7": kw, "auditd_a8": kw, "auditd_a9": kw, "auditd_a10": kw, "auditd_a11": kw, "auditd_a12": kw, "auditd_a13": kw, "auditd_a14": kw, "auditd_a15": kw, "auditd_a16": kw, "auditd_a17": kw, "auditd_a18": kw, "auditd_a19": kw, "auditd_a20": kw, "auditd_a21": kw, "auditd_a22": kw, "auditd_a23": kw, "auditd_a24": kw, "auditd_a25": kw, "auditd_a26": kw, "auditd_a27": kw, "auditd_a28": kw, "auditd_a29": kw, "auditd_a30": kw, "auditd_a31": kw,
		// An sshd line whose client address cannot be told from text the
		// client sent (see ambiguousSSH).
		"src_ambiguous": kw,

		// Syslog receiver, including the CIM names CEF keys map to.
		"facility": kw, "severity": kw, "severity_id": long, "msgid": kw, "sequence": long,
		"dvc": kw, "dvc_host": kw, "direction": kw, "vendor_action": kw, "dest_user": kw,
		"bytes_in": long, "bytes_out": long, "src_mac": kw, "dest_mac": kw,
		"src_nt_domain": kw, "dest_nt_domain": kw, "src_translated_ip": kw, "dest_translated_ip": kw,
		"src_translated_port": long, "dest_translated_port": long, "src_interface": kw, "dest_interface": kw,
		"url": kw, "http_method": kw, "http_user_agent": kw, "file_name": kw, "file_path": kw,
		"file_hash": kw, "file_size": long, "category": kw,
		"cef_version": kw, "cef_vendor": kw, "cef_product": kw, "cef_device_version": kw,
		"leef_version": kw, "leef_vendor": kw, "leef_product": kw, "leef_device_version": kw,

		// OpenTelemetry log records (OTLP).
		"service": kw, "trace_id": kw, "span_id": kw, "otel_scope": kw,

		// osquery (internal/endpoint).
		"endpoint_id": kw, "file_old_path": kw, "user_id": kw, "inventory_type": kw,

		// Wazuh alerts (wazuh.go).
		"benchmark": kw, "wazuh_rule_level": long, "wazuh_rule_groups": kw, "wazuh_agent_id": kw,
		"wazuh_agent_name": kw, "wazuh_agent_ip": kw, "wazuh_manager": kw, "wazuh_decoder": kw,
		"wazuh_location": kw, "wazuh_win_event_id": kw,

		// Risk events.
		"group_key": kw, "risk_score": double, "risk_base_score": double,

		// Vulnerability scans: a CVSS score has a decimal (9.8), which a
		// long would cut to 9 in sorts, charts and stats.
		"cvss": double,
	}
	add := func(fs []datamodel.Field) {
		for _, f := range fs {
			if strings.HasPrefix(f.Name, "_") {
				continue // _time and _raw are @timestamp and message
			}
			if _, ok := m[f.Name]; ok {
				continue
			}
			switch f.Type {
			case "number":
				m[f.Name] = long
			case "text":
				m[f.Name] = "text"
			default:
				m[f.Name] = kw
			}
		}
	}
	add(datamodel.Common)
	for _, model := range datamodel.Models {
		add(model.Fields)
	}
	return m
}()

// SampleField is the keyword field that marks a document as sample data
// (see the sample package). Its value is the load's ID.
const SampleField = datamodel.SampleField

// KnownField reports whether Signalith's own parsers produce a field name,
// so the index template maps it and events always keep it.
func KnownField(name string) bool {
	_, ok := knownFields[name]
	return ok
}

// validFieldName reports whether a sender-chosen name can become a field:
// at most maxFieldNameLen bytes of letters, digits and _ - @ : /, parts
// separated by single dots, at most maxFieldDepth parts, and not starting
// with _ (OpenSearch reserves those names) or another symbol.
func validFieldName(name string) bool {
	if name == "" || len(name) > maxFieldNameLen || !utf8.ValidString(name) {
		return false
	}
	depth := 1
	partStart := true
	for _, r := range name {
		switch {
		case r == '.':
			if partStart {
				return false // leading dot or two in a row
			}
			depth++
			partStart = true
			continue
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '@':
		case r == '_' || r == '-' || r == ':' || r == '/':
			if partStart {
				return false
			}
		default:
			return false
		}
		partStart = false
	}
	return !partStart && depth <= maxFieldDepth
}

// fieldBudget keeps the names each daily index has been given on this
// server, for its share of maxNewNamesPerIndex. It is per server run; the template's field limit
// leaves room for what earlier runs added, and write retries an event with
// only its known fields if OpenSearch still turns it away.
type fieldBudget struct {
	mu      sync.Mutex
	indices map[string]*indexNames // by index name
}

type indexNames struct {
	day string
	// paths holds each name and dotted prefix added: true for an object
	// (a prefix of a longer name), false for a value.
	paths map[string]bool
}

// limit is limitTo with the whole budget, as on a server alone.
func (b *fieldBudget) limit(index, day, oldest string, f map[string]any) int {
	return b.limitTo(index, day, oldest, f, maxNewNamesPerIndex, false)
}

// hasUnknown reports whether an event has a field Signalith does not
// produce itself.
func hasUnknown(f map[string]any) bool {
	for k := range f {
		if !KnownField(k) {
			return true
		}
	}
	return false
}

// limitTo drops the fields of an event (going to index, on day) that are
// invalid, over the per-event cap, clash with a known field or with how
// the index already maps the name, or do not fit the index's budget of
// budget names (this server's share). With full, the index's mapping is
// near OpenSearch's limit (mappingStop), and no new name is granted;
// names granted before still pass. It returns how many it dropped. oldest
// is the first day an event can still be written to; budgets of earlier
// days are forgotten.
func (b *fieldBudget) limitTo(index, day, oldest string, f map[string]any, budget int, full bool) int {
	var unknown []string
	for k := range f {
		if !KnownField(k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return 0
	}
	// Sorted, so which names an event keeps does not depend on map order,
	// and "a" is seen before "a.b".
	slices.Sort(unknown)
	dropped := 0
	drop := func(k string) {
		delete(f, k)
		dropped++
	}
	if len(f) > maxFieldsPerEvent {
		keep := max(maxFieldsPerEvent-(len(f)-len(unknown)), 0)
		for _, k := range unknown[keep:] {
			drop(k)
		}
		unknown = unknown[:keep]
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	ix := b.indices[index]
	if ix == nil {
		if b.indices == nil {
			b.indices = map[string]*indexNames{}
		}
		for k, old := range b.indices {
			if old.day < oldest {
				delete(b.indices, k)
			}
		}
		ix = &indexNames{day: day, paths: map[string]bool{}}
		b.indices[index] = ix
	}
	for _, k := range unknown {
		if !validFieldName(k) {
			drop(k)
			continue
		}
		if isObject, seen := ix.paths[k]; seen {
			if isObject {
				drop(k) // "a" when the index already has "a.b"
			}
			continue
		}
		parts := strings.Split(k, ".")
		if KnownField(parts[0]) && len(parts) > 1 {
			drop(k) // "user.name" would turn the known field user into an object
			continue
		}
		added, clash := 1, false
		for i := 1; i < len(parts); i++ {
			isObject, seen := ix.paths[strings.Join(parts[:i], ".")]
			if !seen {
				added++
			} else if !isObject {
				clash = true // "a.b" when the index already has a value "a"
				break
			}
		}
		if clash || full || len(ix.paths)+added > budget {
			drop(k)
			continue
		}
		for i := 1; i < len(parts); i++ {
			ix.paths[strings.Join(parts[:i], ".")] = true
		}
		ix.paths[k] = false
	}
	return dropped
}

// onlyKnown removes every field Signalith does not produce itself and
// returns how many it removed.
func onlyKnown(f map[string]any) int {
	n := 0
	for k := range f {
		if !KnownField(k) {
			delete(f, k)
			n++
		}
	}
	return n
}

// dayOf is the index day of a time.
func dayOf(t time.Time) string { return t.UTC().Format("2006.01.02") }
