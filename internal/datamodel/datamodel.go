// Package datamodel defines Signalith's common field model. Field names
// follow Splunk's CIM so ES analysts recognize them, and every parser maps
// its source onto one of these models.
package datamodel

import (
	"sort"
	"strings"
)

// SampleField marks every event, risk event and finding the "Load sample
// data" feature writes; its value is the load's ID. The name is one no
// sender uses, so a real event is never mistaken for sample data: the live
// detection scheduler leaves marked documents out, the sample backfill
// reads only its own, and Remove deletes exactly those.
const SampleField = "signalith_sample"

// Field describes one normalized field.
type Field struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string, number, ip, time, text
	Description string   `json:"description"`
	Examples    []string `json:"examples,omitempty"`
}

// Model is a data model: a family of events with the same fields.
type Model struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Fields      []Field `json:"fields"`
}

// Common fields exist on every event regardless of model.
var Common = []Field{
	{Name: "_time", Type: "time", Description: "When the event happened"},
	{Name: "host", Type: "string", Description: "Host that reported the event"},
	{Name: "sourcetype", Type: "string", Description: "Source format, for example WinEventLog:Security or linux:auth"},
	{Name: "datamodel", Type: "string", Description: "Data model the event was mapped to"},
	{Name: "vendor_product", Type: "string", Description: "Product that produced the event"},
	{Name: "signature_id", Type: "string", Description: "Vendor event code, such as a Windows event ID"},
	{Name: "signature", Type: "string", Description: "Human-readable event name"},
	{Name: "_raw", Type: "text", Description: "The original event text"},
}

// Models lists every built-in data model.
var Models = []Model{
	{
		Name:        "Authentication",
		Description: "Logons, logoffs and privilege elevation (Windows logons, SSH, sudo, su)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "Outcome", Examples: []string{"success", "failure"}},
			{Name: "app", Type: "string", Description: "Application that authenticated the user", Examples: []string{"win:local", "sshd", "sudo"}},
			{Name: "user", Type: "string", Description: "Account being authenticated"},
			{Name: "src_user", Type: "string", Description: "Account that requested the authentication, for sudo and su"},
			{Name: "user_domain", Type: "string", Description: "Domain of the user"},
			{Name: "src", Type: "ip", Description: "Where the attempt came from"},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "string", Description: "System the user authenticated to"},
			{Name: "authentication_method", Type: "string", Description: "Method used", Examples: []string{"password", "publickey"}},
			{Name: "logon_type", Type: "number", Description: "Windows logon type (2 interactive, 3 network, 10 remote desktop)"},
			{Name: "reason", Type: "string", Description: "Why a failure happened"},
			{Name: "process", Type: "string", Description: "Command run through sudo"},
		},
	},
	{
		Name:        "Endpoint",
		Description: "Process launches on hosts (Windows 4688, Sysmon)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What happened", Examples: []string{"allowed"}},
			{Name: "user", Type: "string", Description: "Account that started the process"},
			{Name: "dest", Type: "string", Description: "Host where the process ran"},
			{Name: "process", Type: "string", Description: "Full command line"},
			{Name: "process_name", Type: "string", Description: "Executable file name", Examples: []string{"powershell.exe"}},
			{Name: "process_path", Type: "string", Description: "Executable path"},
			{Name: "process_id", Type: "number", Description: "Process ID"},
			{Name: "parent_process", Type: "string", Description: "Parent command line"},
			{Name: "parent_process_name", Type: "string", Description: "Parent executable file name"},
			{Name: "parent_process_path", Type: "string", Description: "Parent executable path"},
			{Name: "process_hash", Type: "string", Description: "Hashes of the executable, as Sysmon lists them"},
			{Name: "process_md5", Type: "string", Description: "MD5 hash of the executable, lower case"},
			{Name: "process_sha1", Type: "string", Description: "SHA-1 hash of the executable, lower case"},
			{Name: "process_sha256", Type: "string", Description: "SHA-256 hash of the executable, lower case"},
			{Name: "process_guid", Type: "string", Description: "Sysmon's unique ID for the process"},
			{Name: "process_integrity_level", Type: "string", Description: "Windows integrity level of the process", Examples: []string{"Medium", "High", "System"}},
			{Name: "process_current_directory", Type: "string", Description: "Working folder the process started in"},
			{Name: "process_description", Type: "string", Description: "File description from the executable's version information"},
			{Name: "process_product", Type: "string", Description: "Product name from the executable's version information"},
			{Name: "process_company", Type: "string", Description: "Company name from the executable's version information"},
			{Name: "process_file_version", Type: "string", Description: "File version from the executable's version information"},
			{Name: "original_file_name", Type: "string", Description: "File name the executable was built with, which stays the same when it is renamed"},
			{Name: "parent_process_id", Type: "number", Description: "Parent process ID"},
			{Name: "parent_process_guid", Type: "string", Description: "Sysmon's unique ID for the parent process"},
			{Name: "parent_user", Type: "string", Description: "Account that started the parent process"},
			{Name: "logon_id", Type: "string", Description: "Windows logon session the process runs in"},
			{Name: "target_process", Type: "string", Description: "Command line of the process that was opened or injected into (process access, remote thread)"},
			{Name: "target_process_name", Type: "string", Description: "File name of the target process"},
			{Name: "target_process_path", Type: "string", Description: "Path of the target process"},
			{Name: "target_process_id", Type: "number", Description: "ID of the target process"},
			{Name: "target_process_guid", Type: "string", Description: "Sysmon's unique ID for the target process"},
			{Name: "granted_access", Type: "string", Description: "Access rights granted to the target process, as a hex mask", Examples: []string{"0x1010"}},
		},
	},
	{
		Name:        "Network_Traffic",
		Description: "Network connections (Sysmon event 3, firewalls)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "Outcome", Examples: []string{"allowed", "blocked"}},
			{Name: "src", Type: "ip", Description: "Source address"},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "ip", Description: "Destination address"},
			{Name: "dest_host", Type: "string", Description: "Destination host name"},
			{Name: "dest_port", Type: "number", Description: "Destination port"},
			{Name: "transport", Type: "string", Description: "Protocol", Examples: []string{"tcp", "udp"}},
			{Name: "user", Type: "string", Description: "Account that owns the connection"},
			{Name: "process_name", Type: "string", Description: "Process that made the connection"},
			{Name: "bytes", Type: "number", Description: "Total bytes"},
		},
	},
	{
		Name:        "Change",
		Description: "Account and configuration changes (user created, deleted, added to a group)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What changed", Examples: []string{"created", "deleted", "modified"}},
			{Name: "object", Type: "string", Description: "What was changed, such as the account name"},
			{Name: "object_category", Type: "string", Description: "Kind of object", Examples: []string{"user", "group"}},
			{Name: "user", Type: "string", Description: "Account that made the change"},
			{Name: "dest", Type: "string", Description: "System where the change happened"},
		},
	},
	{
		Name:        "Malware",
		Description: "Antivirus and endpoint protection: malware found and what was done about it, protection rule blocks, and the health of the antivirus itself.",
		Fields: []Field{
			{Name: "type", Type: "string", Description: "Kind of event: threat (malware found), rule (a protection rule acted) or health (the antivirus itself changed or has a problem)", Examples: []string{"threat", "rule", "health"}},
			{Name: "action", Type: "string", Description: "What happened, such as quarantined, failed, disabled or exclusion_added", Examples: []string{"quarantined", "failed", "disabled"}},
			{Name: "vendor_action", Type: "string", Description: "The action as the product wrote it", Examples: []string{"Quarantine", "Left alone"}},
			{Name: "threat_id", Type: "string", Description: "The product's ID for the threat", Examples: []string{"2147729891"}},
			{Name: "category", Type: "string", Description: "Kind of threat: virus, worm, trojan, ransomware, backdoor, spyware, adware, pua, exploit, hacktool, behavior, test or other", Examples: []string{"trojan", "ransomware"}},
			{Name: "vendor_category", Type: "string", Description: "The threat category as the product wrote it", Examples: []string{"Trojan", "Tool"}},
			{Name: "severity", Type: "string", Description: "How serious the product rates it: low, medium, high or critical", Examples: []string{"high"}},
			{Name: "vendor_severity", Type: "string", Description: "The severity as the product wrote it", Examples: []string{"Severe"}},
			{Name: "dest", Type: "string", Description: "Host the event is about", Examples: []string{"ws-fin-07"}},
			{Name: "dest_ip", Type: "ip", Description: "Address of that host, when the product sends one", Examples: []string{"192.0.2.27"}},
			{Name: "user", Type: "string", Description: "Account involved, such as the user who opened the file", Examples: []string{`CORP\alice.nguyen`}},
			{Name: "src", Type: "ip", Description: "Address the threat came from, when the product says", Examples: []string{"203.0.113.45"}},
			{Name: "src_host", Type: "string", Description: "Host the threat came from, when the product says", Examples: []string{"file-01"}},
			{Name: "url", Type: "string", Description: "Web address the threat came from or was blocked at"},
			{Name: "file_name", Type: "string", Description: "File name of the threat", Examples: []string{"invoice.exe"}},
			{Name: "file_path", Type: "string", Description: "Full path of the threat", Examples: []string{`C:\Users\alice.nguyen\Downloads\invoice.exe`}},
			{Name: "file_hash", Type: "string", Description: "File hash as the product sent it"},
			{Name: "file_md5", Type: "string", Description: "MD5 of the file (lower case)"},
			{Name: "file_sha1", Type: "string", Description: "SHA-1 of the file (lower case)"},
			{Name: "file_sha256", Type: "string", Description: "SHA-256 of the file (lower case)"},
			{Name: "file_size", Type: "number", Description: "File size in bytes", Examples: []string{"68"}},
			{Name: "process", Type: "string", Description: "Command line of the process involved"},
			{Name: "process_name", Type: "string", Description: "Executable file name of the process involved", Examples: []string{"winword.exe"}},
			{Name: "process_path", Type: "string", Description: "Executable path of the process involved"},
			{Name: "process_id", Type: "number", Description: "Process ID", Examples: []string{"4120"}},
			{Name: "rule", Type: "string", Description: "Protection rule that acted", Examples: []string{"Office app started a child process"}},
			{Name: "rule_id", Type: "string", Description: "ID of that rule (for attack surface reduction, its GUID)", Examples: []string{"d4f940ab-401b-4efc-aadc-ad5f3c50688a"}},
			{Name: "setting", Type: "string", Description: "Setting that changed, as the product wrote it", Examples: []string{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0`}},
			{Name: "exclusion", Type: "string", Description: "What an added or removed exclusion lets through", Examples: []string{`C:\ProgramData\SyncSvc`}},
			{Name: "exclusion_type", Type: "string", Description: "Kind of exclusion: path, extension, process or ip", Examples: []string{"path"}},
			{Name: "signature_version", Type: "string", Description: "Version of the antivirus definitions", Examples: []string{"1.419.2361.0"}},
			{Name: "engine_version", Type: "string", Description: "Version of the scan engine", Examples: []string{"1.1.24090.11"}},
			{Name: "product_version", Type: "string", Description: "Version of the antivirus product", Examples: []string{"4.18.24090.11"}},
			{Name: "signature_age_days", Type: "number", Description: "Age of the definitions in days, when the product reports it", Examples: []string{"9"}},
			{Name: "reason", Type: "string", Description: "Error or reason text from the product", Examples: []string{"The process cannot access the file"}},
			{Name: "detection_source", Type: "string", Description: "Which scan or feature found it", Examples: []string{"Real-Time Protection"}},
		},
	},
	{
		Name:        "Filesystem",
		Description: "Files created, changed or deleted on hosts (Sysmon 11, 23 and 26, osquery file integrity monitoring)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What happened to the file", Examples: []string{"created", "modified", "deleted"}},
			{Name: "file_path", Type: "string", Description: "Full path of the file"},
			{Name: "file_name", Type: "string", Description: "File name without its folder"},
			{Name: "file_hash", Type: "string", Description: "SHA-256 of the file, lower case, when the source reports it"},
			{Name: "file_size", Type: "number", Description: "Size of the file in bytes"},
			{Name: "process_name", Type: "string", Description: "Process that changed the file, when the source knows"},
			{Name: "process_path", Type: "string", Description: "Path of that process"},
			{Name: "process_id", Type: "number", Description: "ID of that process"},
			{Name: "user", Type: "string", Description: "Account that changed the file, when the source knows"},
			{Name: "dest", Type: "string", Description: "Host the file is on"},
		},
	},
	{
		Name:        "Registry",
		Description: "Windows registry keys and values created, changed or deleted (Sysmon 12, 13 and 14)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What happened", Examples: []string{"created", "modified", "deleted", "renamed"}},
			{Name: "registry_path", Type: "string", Description: "Full path of the key or value"},
			{Name: "registry_key_name", Type: "string", Description: "Name of the key"},
			{Name: "registry_value_name", Type: "string", Description: "Name of the value"},
			{Name: "registry_value_data", Type: "string", Description: "Data written to the value"},
			{Name: "process_name", Type: "string", Description: "Process that made the change"},
			{Name: "process_path", Type: "string", Description: "Path of that process"},
			{Name: "process_guid", Type: "string", Description: "Sysmon's unique ID for that process"},
			{Name: "user", Type: "string", Description: "Account that made the change"},
			{Name: "dest", Type: "string", Description: "Host the registry is on"},
		},
	},
	{
		Name:        "Network_Resolution",
		Description: "DNS lookups made on hosts (Sysmon 22)",
		Fields: []Field{
			{Name: "query", Type: "string", Description: "Name that was looked up", Examples: []string{"example.com"}},
			{Name: "answer", Type: "string", Description: "What the lookup returned"},
			{Name: "reply_code", Type: "string", Description: "Result of the lookup", Examples: []string{"NoError", "NXDomain"}},
			{Name: "process_name", Type: "string", Description: "Process that made the lookup"},
			{Name: "process_path", Type: "string", Description: "Path of that process"},
			{Name: "dest", Type: "string", Description: "Host the lookup was made on"},
		},
	},
	{
		Name:        "Image_Load",
		Description: "DLLs and drivers loaded on Windows hosts (Sysmon 6 and 7)",
		Fields: []Field{
			{Name: "loaded_file_path", Type: "string", Description: "Path of the loaded DLL or driver"},
			{Name: "loaded_file_name", Type: "string", Description: "File name of the loaded DLL or driver"},
			{Name: "signed", Type: "string", Description: "Whether the file is signed", Examples: []string{"true", "false"}},
			{Name: "signature", Type: "string", Description: "Who signed the file"},
			{Name: "signature_status", Type: "string", Description: "Whether the signature is valid", Examples: []string{"Valid", "Expired"}},
			{Name: "process_name", Type: "string", Description: "Process that loaded the file"},
			{Name: "process_path", Type: "string", Description: "Path of that process"},
			{Name: "process_id", Type: "number", Description: "ID of that process"},
			{Name: "process_guid", Type: "string", Description: "Sysmon's unique ID for that process"},
			{Name: "user", Type: "string", Description: "Account the process runs as"},
			{Name: "dest", Type: "string", Description: "Host the file was loaded on"},
		},
	},
	{
		Name:        "Script",
		Description: "PowerShell script blocks run on Windows hosts (event 4104)",
		Fields: []Field{
			{Name: "script_block_text", Type: "text", Description: "The script text that ran"},
			{Name: "script_path", Type: "string", Description: "File the script came from, when it came from one"},
			{Name: "script_block_id", Type: "string", Description: "ID that ties together the parts of a long script"},
			{Name: "user", Type: "string", Description: "Account that ran the script"},
			{Name: "dest", Type: "string", Description: "Host the script ran on"},
		},
	},
	{
		Name:        "Inventory",
		Description: "What is on each host: operating system, installed software, accounts, listening ports, services and startup items (osquery)",
		Fields: []Field{
			{Name: "inventory_type", Type: "string", Description: "Kind of item", Examples: []string{"os", "software", "user", "port", "service", "startup"}},
			{Name: "action", Type: "string", Description: "Whether the item appeared or went away since the host last reported", Examples: []string{"added", "removed"}},
			{Name: "dest", Type: "string", Description: "Host the item is on"},
			{Name: "os", Type: "string", Description: "Operating system name", Examples: []string{"Ubuntu", "Microsoft Windows 11 Pro"}},
			{Name: "os_version", Type: "string", Description: "Operating system version"},
			{Name: "name", Type: "string", Description: "Software, account, service or startup item name"},
			{Name: "version", Type: "string", Description: "Software version"},
			{Name: "vendor", Type: "string", Description: "Software publisher"},
			{Name: "package_type", Type: "string", Description: "Where the software came from", Examples: []string{"deb", "rpm", "windows", "macos"}},
			{Name: "user", Type: "string", Description: "Account name, for accounts"},
			{Name: "dest_port", Type: "number", Description: "Listening port, for ports"},
			{Name: "transport", Type: "string", Description: "Protocol of a listening port", Examples: []string{"tcp", "udp"}},
			{Name: "process_name", Type: "string", Description: "Program listening on a port"},
			{Name: "status", Type: "string", Description: "State of a service", Examples: []string{"RUNNING", "STOPPED"}},
			{Name: "path", Type: "string", Description: "Install folder, program path or startup item path"},
		},
	},
	{
		Name:        "Configuration_Check",
		Description: "Results of configuration checks run on hosts, based on the SCAP Security Guide (osquery)",
		Fields: []Field{
			{Name: "dest", Type: "string", Description: "Host the check ran on"},
			{Name: "check_id", Type: "string", Description: "Signalith's ID for the check"},
			{Name: "check", Type: "string", Description: "What the check looks for"},
			{Name: "result", Type: "string", Description: "Outcome", Examples: []string{"pass", "fail", "error"}},
			{Name: "severity", Type: "string", Description: "How much a failure matters", Examples: []string{"low", "medium", "high"}},
			{Name: "rule_id", Type: "string", Description: "The SCAP Security Guide rule the check is based on, when there is one"},
			{Name: "reference", Type: "string", Description: "Control references, such as NIST SP 800-53 IDs"},
			{Name: "detail", Type: "string", Description: "What the host reported, when the check failed"},
			{Name: "benchmark", Type: "string", Description: "The guide or policy the check comes from", Examples: []string{"SCAP Security Guide"}},
			{Name: "os", Type: "string", Description: "Platform the check is for", Examples: []string{"linux", "windows", "darwin"}},
		},
	},
	{
		Name:        "Alerts",
		Description: "Alerts raised by other security tools, such as Wazuh",
		Fields: []Field{
			{Name: "app", Type: "string", Description: "Tool that raised the alert", Examples: []string{"wazuh"}},
			{Name: "id", Type: "string", Description: "The tool's ID for this alert"},
			{Name: "description", Type: "string", Description: "What the alert says"},
			{Name: "severity", Type: "string", Description: "Severity", Examples: []string{"informational", "low", "medium", "high", "critical"}},
			{Name: "severity_id", Type: "number", Description: "The tool's own severity number, such as a Wazuh rule level from 0 to 15"},
			{Name: "type", Type: "string", Description: "Alert category from the tool, such as Wazuh rule groups"},
			{Name: "dest", Type: "string", Description: "Host the alert is about"},
			{Name: "src", Type: "ip", Description: "Source address, when the alert has one"},
			{Name: "user", Type: "string", Description: "Account the alert is about, when it has one"},
			{Name: "mitre", Type: "string", Description: "ATT&CK techniques the tool tagged the alert with"},
		},
	},
	{
		Name:        "Risk",
		Description: "Risk that detections attributed to users and systems; not included in searches unless you ask for datamodel=Risk",
		Fields: []Field{
			{Name: "risk_object", Type: "string", Description: "User or system the risk is attributed to"},
			{Name: "risk_object_type", Type: "string", Description: "Kind of risk object", Examples: []string{"user", "system", "other"}},
			{Name: "risk_score", Type: "number", Description: "Score after the asset or identity priority multiplier"},
			{Name: "risk_base_score", Type: "number", Description: "Score the detection assigned before the multiplier"},
			{Name: "risk_priority", Type: "string", Description: "Priority of the risk object from the asset or identity list"},
			{Name: "risk_message", Type: "string", Description: "What happened, from the detection title"},
			{Name: "detection_id", Type: "string", Description: "Detection that added the risk"},
			{Name: "mitre", Type: "string", Description: "ATT&CK techniques of the detection"},
			{Name: "mitre_tactic", Type: "string", Description: "ATT&CK tactics of those techniques"},
		},
	},
	{
		Name:        "Other",
		Description: "Events no parser recognized yet; still searchable by text",
		Fields: []Field{
			{Name: "app", Type: "string", Description: "Program that logged the event"},
		},
	},
}

// Get returns a model by case-insensitive name.
func Get(name string) (Model, bool) {
	for _, m := range Models {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return Model{}, false
}

// FieldsFor returns the common fields plus a model's own, sorted by name
// with _time first. An empty model name returns the union of all models.
func FieldsFor(model string) []Field {
	seen := map[string]bool{}
	var out []Field
	add := func(fs []Field) {
		for _, f := range fs {
			if !seen[f.Name] {
				seen[f.Name] = true
				out = append(out, f)
			}
		}
	}
	add(Common)
	if m, ok := Get(model); ok {
		add(m.Fields)
	} else {
		for _, m := range Models {
			add(m.Fields)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == "_time" {
			return true
		}
		if out[j].Name == "_time" {
			return false
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// RiskModel is the data model risk events are stored under. The default
// "all data" search leaves it out so risk events do not mix with raw events.
const RiskModel = "Risk"

// IndexName returns the daily index an event of a model goes to.
func IndexName(prefix, model, day string) string {
	return prefix + "-" + strings.ToLower(model) + "-" + day
}
