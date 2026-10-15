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
			{Name: "call_trace", Type: "string", Description: "Modules on the call stack when the target process was opened (Sysmon 10 CallTrace), separated by |"},
			{Name: "start_address", Type: "string", Description: "Memory address where a remote thread starts, in hex (Sysmon 8)", Examples: []string{"0xFFFFF80000001000"}},
			{Name: "start_module", Type: "string", Description: "Path of the module a remote thread starts in (Sysmon 8)"},
			{Name: "start_function", Type: "string", Description: "Function a remote thread starts at (Sysmon 8)", Examples: []string{"LoadLibraryW"}},
		},
	},
	{
		Name:        "Network_Traffic",
		Description: "Network connections (Sysmon event 3, firewalls, network sensors such as Zeek and Suricata)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "Outcome: allowed, blocked, or failed for a connection that was refused or never answered (network sensors cannot tell a firewall drop from a closed port)", Examples: []string{"allowed", "blocked", "failed"}},
			{Name: "src", Type: "ip", Description: "Source address"},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "ip", Description: "Destination address"},
			{Name: "dest_host", Type: "string", Description: "Destination host name"},
			{Name: "dest_port", Type: "number", Description: "Destination port"},
			{Name: "transport", Type: "string", Description: "Protocol", Examples: []string{"tcp", "udp"}},
			{Name: "user", Type: "string", Description: "Account that owns the connection"},
			{Name: "process_name", Type: "string", Description: "Process that made the connection"},
			{Name: "bytes", Type: "number", Description: "Total bytes"},
			{Name: "app", Type: "string", Description: "Service or application protocol the connection carried, as a network sensor recognized it", Examples: []string{"dns", "http", "ssl", "smb"}},
			{Name: "bytes_in", Type: "number", Description: "Bytes the destination sent back to the source"},
			{Name: "bytes_out", Type: "number", Description: "Bytes the source sent to the destination"},
			{Name: "packets_in", Type: "number", Description: "Packets the destination sent back to the source"},
			{Name: "packets_out", Type: "number", Description: "Packets the source sent to the destination"},
			{Name: "duration", Type: "number", Description: "How long the connection lasted, in seconds (may have decimals)", Examples: []string{"0.42", "3600"}},
			{Name: "direction", Type: "string", Description: "Which way the connection went, seen from your network: inbound (from outside in), outbound (from inside out), internal (inside to inside) or external (outside to outside)", Examples: []string{"inbound", "outbound", "internal", "external"}},
			{Name: "conn_state", Type: "string", Description: "Connection state as the network sensor wrote it (Zeek: SF normal, S0 no answer, REJ rejected; Suricata: new, established, closed)", Examples: []string{"SF", "S0", "REJ", "established"}},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection (Zeek uid, Suricata flow_id); every event of one connection shares it", Examples: []string{"CHhAvVGS1DHFjwGM9"}},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow: the same value in Zeek and Suricata events of one connection", Examples: []string{"1:LQU9qZlK+B5F3KDmev6m5PMibrg="}},
			{Name: "vlan", Type: "number", Description: "VLAN the traffic was seen on"},
			{Name: "src_mac", Type: "string", Description: "Hardware (MAC) address of the source, when the sensor logs it"},
			{Name: "dest_mac", Type: "string", Description: "Hardware (MAC) address of the destination, when the sensor logs it"},
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
			{Name: "old_value", Type: "string", Description: "Setting as it was, for a configuration change (Defender 5007)"},
			{Name: "new_value", Type: "string", Description: "Setting as it is now, for a configuration change (Defender 5007)", Examples: []string{`HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`}},
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
		Description: "Files created, changed or deleted on hosts (Sysmon 11, 23 and 26; executables and shredding blocked, 27 to 29; osquery file integrity monitoring)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What happened to the file", Examples: []string{"created", "modified", "deleted", "blocked"}},
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
			{Name: "registry_new_path", Type: "string", Description: "New full path of a renamed key or value (Sysmon 14 NewName)"},
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
		Description: "DNS lookups made on hosts (Sysmon 22) or seen on the network (Zeek, Suricata)",
		Fields: []Field{
			{Name: "query", Type: "string", Description: "Name that was looked up", Examples: []string{"example.com"}},
			{Name: "answer", Type: "string", Description: "What the lookup returned; a list when there were several answers"},
			{Name: "reply_code", Type: "string", Description: "Result of the lookup", Examples: []string{"NoError", "NXDomain"}},
			{Name: "process_name", Type: "string", Description: "Process that made the lookup"},
			{Name: "process_path", Type: "string", Description: "Path of that process"},
			{Name: "dest", Type: "string", Description: "Host the lookup was made on (host logs only; network sensors set src)"},
			{Name: "src", Type: "ip", Description: "Host that asked, for network sensors", Examples: []string{"192.0.2.10"}},
			{Name: "src_port", Type: "number", Description: "Port the question came from"},
			{Name: "dest_ip", Type: "ip", Description: "DNS server that was asked", Examples: []string{"192.0.2.53"}},
			{Name: "dest_port", Type: "number", Description: "Port of the DNS server", Examples: []string{"53"}},
			{Name: "transport", Type: "string", Description: "Protocol of the lookup", Examples: []string{"udp", "tcp"}},
			{Name: "query_type", Type: "string", Description: "Kind of record asked for", Examples: []string{"A", "AAAA", "TXT"}},
			{Name: "reply_code_id", Type: "number", Description: "Result of the lookup as a number (0 NoError, 2 ServFail, 3 NXDomain)", Examples: []string{"0", "3"}},
			{Name: "ttl", Type: "number", Description: "How long the first answer may be cached, in seconds"},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection the lookup was in (Zeek uid, Suricata flow_id)"},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow, shared by Zeek and Suricata events of one connection"},
		},
	},
	{
		Name:        "Intrusion_Detection",
		Description: "Alerts from network intrusion detection: Suricata rules such as Emerging Threats Open, and Zeek notices",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What the sensor did: allowed (it only raised the alert) or blocked (an inline sensor dropped the traffic)", Examples: []string{"allowed", "blocked"}},
			{Name: "ids_type", Type: "string", Description: "Kind of intrusion detection", Examples: []string{"network"}},
			{Name: "category", Type: "string", Description: "Rule category (Suricata classtype text) or Zeek notice", Examples: []string{"A Network Trojan was detected", "Zeek notice"}},
			{Name: "severity", Type: "string", Description: "How serious: critical, high, medium, low or informational", Examples: []string{"high", "medium"}},
			{Name: "severity_id", Type: "number", Description: "The tool's own severity number (Suricata: 1 high, 2 medium, 3 low)", Examples: []string{"1"}},
			{Name: "src", Type: "ip", Description: "Source address of the traffic that raised the alert", Examples: []string{"203.0.113.45"}},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "ip", Description: "Destination address", Examples: []string{"192.0.2.10"}},
			{Name: "dest_port", Type: "number", Description: "Destination port", Examples: []string{"443"}},
			{Name: "local_host", Type: "ip", Description: "Your network's end of the traffic: src when it went out, dest when it came in, both when it stayed inside; unset when neither end is inside", Examples: []string{"192.0.2.10"}},
			{Name: "dest_host", Type: "string", Description: "Host name in the traffic: web host, TLS server name or DNS name", Examples: []string{"updates.example.net"}},
			{Name: "transport", Type: "string", Description: "Protocol", Examples: []string{"tcp", "udp"}},
			{Name: "app", Type: "string", Description: "Application protocol of the traffic", Examples: []string{"http", "tls", "dns"}},
			{Name: "url", Type: "string", Description: "Web address in the traffic, when it was a web request", Examples: []string{"http://files.example.net/invoice.exe"}},
			{Name: "direction", Type: "string", Description: "Which way the traffic went, seen from your network: inbound, outbound, internal or external", Examples: []string{"outbound"}},
			{Name: "mitre", Type: "string", Description: "ATT&CK techniques the rule is tagged with", Examples: []string{"T1105"}},
			{Name: "reason", Type: "string", Description: "Why the alert was raised, from the tool's text", Examples: []string{"192.0.2.66 scanned at least 25 unique ports of host 192.0.2.10 in 0m3s"}},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection (Zeek uid, Suricata flow_id)"},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow: search it to see the connection, DNS lookup, web request and files of the same flow"},
		},
	},
	{
		Name:        "Web",
		Description: "Web requests seen on the network (Zeek, Suricata)",
		Fields: []Field{
			{Name: "http_method", Type: "string", Description: "Request method", Examples: []string{"GET", "POST"}},
			{Name: "url", Type: "string", Description: "Full web address asked for", Examples: []string{"http://updates.example.net/v2/check?os=win"}},
			{Name: "url_domain", Type: "string", Description: "Host name part of the address", Examples: []string{"updates.example.net"}},
			{Name: "uri_path", Type: "string", Description: "Path part of the address", Examples: []string{"/v2/check"}},
			{Name: "uri_query", Type: "string", Description: "Query part of the address, after the ?", Examples: []string{"os=win"}},
			{Name: "status", Type: "string", Description: "HTTP status code the server answered with, as text", Examples: []string{"200", "404"}},
			{Name: "http_user_agent", Type: "string", Description: "User agent the client sent", Examples: []string{"curl/8.5.0"}},
			{Name: "http_referrer", Type: "string", Description: "Page the request came from (Referer header)"},
			{Name: "http_content_type", Type: "string", Description: "Type of what the server sent back", Examples: []string{"text/html", "application/x-dosexec"}},
			{Name: "bytes_in", Type: "number", Description: "Bytes of the response body"},
			{Name: "bytes_out", Type: "number", Description: "Bytes of the request body"},
			{Name: "src", Type: "ip", Description: "Client address", Examples: []string{"192.0.2.10"}},
			{Name: "src_port", Type: "number", Description: "Client port"},
			{Name: "dest", Type: "ip", Description: "Server address", Examples: []string{"198.51.100.120"}},
			{Name: "dest_port", Type: "number", Description: "Server port", Examples: []string{"80"}},
			{Name: "dest_host", Type: "string", Description: "Host name the client asked for (Host header)", Examples: []string{"updates.example.net"}},
			{Name: "user", Type: "string", Description: "User name of HTTP basic authentication, when there was one (never the password)"},
			{Name: "direction", Type: "string", Description: "Which way the request went, seen from your network: inbound, outbound, internal or external", Examples: []string{"outbound"}},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection (Zeek uid, Suricata flow_id)"},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow, shared by Zeek and Suricata events of one connection"},
		},
	},
	{
		Name:        "Certificates",
		Description: "TLS sessions and the certificates in them (Zeek ssl and x509, Suricata tls)",
		Fields: []Field{
			{Name: "ssl_version", Type: "string", Description: "TLS version of the session", Examples: []string{"TLSv13", "TLS 1.2"}},
			{Name: "ssl_cipher", Type: "string", Description: "Cipher the session used", Examples: []string{"TLS_AES_128_GCM_SHA256"}},
			{Name: "ssl_server_name", Type: "string", Description: "Server name the client asked for (SNI)", Examples: []string{"www.example.com"}},
			{Name: "ssl_subject", Type: "string", Description: "Subject of the server's certificate", Examples: []string{"CN=www.example.com,O=Example Ltd,C=US"}},
			{Name: "ssl_subject_common_name", Type: "string", Description: "Common name (CN) in the subject", Examples: []string{"www.example.com"}},
			{Name: "ssl_issuer", Type: "string", Description: "Issuer of the server's certificate", Examples: []string{"CN=Example Issuing CA,O=Example Ltd,C=US"}},
			{Name: "ssl_issuer_common_name", Type: "string", Description: "Common name (CN) in the issuer", Examples: []string{"Example Issuing CA"}},
			{Name: "ssl_serial", Type: "string", Description: "Serial number of the certificate"},
			{Name: "ssl_hash", Type: "string", Description: "Fingerprint of the certificate, lower case hex without colons"},
			{Name: "ssl_start_time", Type: "string", Description: "When the certificate becomes valid (RFC 3339, UTC)", Examples: []string{"2026-01-01T00:00:00Z"}},
			{Name: "ssl_end_time", Type: "string", Description: "When the certificate expires (RFC 3339, UTC)", Examples: []string{"2027-01-01T00:00:00Z"}},
			{Name: "ssl_validation_status", Type: "string", Description: "Whether the sensor could check the certificate (Zeek)", Examples: []string{"ok", "self signed certificate"}},
			{Name: "ssl_self_signed", Type: "string", Description: "true when the certificate signs itself (subject and issuer are the same)", Examples: []string{"true", "false"}},
			{Name: "ja3", Type: "string", Description: "JA3 fingerprint of the client's TLS hello"},
			{Name: "ja3s", Type: "string", Description: "JA3S fingerprint of the server's TLS hello"},
			{Name: "ja4", Type: "string", Description: "JA4 fingerprint of the client's TLS hello"},
			{Name: "src", Type: "ip", Description: "Client address", Examples: []string{"192.0.2.10"}},
			{Name: "src_port", Type: "number", Description: "Client port"},
			{Name: "dest", Type: "ip", Description: "Server address", Examples: []string{"198.51.100.120"}},
			{Name: "dest_port", Type: "number", Description: "Server port", Examples: []string{"443"}},
			{Name: "dest_host", Type: "string", Description: "Server name, so threat intel matches the domain", Examples: []string{"www.example.com"}},
			{Name: "direction", Type: "string", Description: "Which way the session went, seen from your network: inbound, outbound, internal or external", Examples: []string{"outbound"}},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection (Zeek uid, Suricata flow_id)"},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow, shared by Zeek and Suricata events of one connection"},
		},
	},
	{
		Name:        "File_Transfers",
		Description: "Files seen crossing the network (Zeek files, Suricata fileinfo)",
		Fields: []Field{
			{Name: "file_name", Type: "string", Description: "File name, when the protocol carries one", Examples: []string{"invoice.exe"}},
			{Name: "file_size", Type: "number", Description: "File size in bytes"},
			{Name: "file_hash", Type: "string", Description: "SHA-256 of the file, lower case"},
			{Name: "file_md5", Type: "string", Description: "MD5 of the file (lower case)"},
			{Name: "file_sha1", Type: "string", Description: "SHA-1 of the file (lower case)"},
			{Name: "file_sha256", Type: "string", Description: "SHA-256 of the file (lower case)"},
			{Name: "mime_type", Type: "string", Description: "Kind of file, from its contents", Examples: []string{"application/x-dosexec", "application/pdf"}},
			{Name: "app", Type: "string", Description: "Protocol that carried the file", Examples: []string{"HTTP", "SMB", "FTP", "SMTP"}},
			{Name: "src", Type: "ip", Description: "Address that sent the file", Examples: []string{"198.51.100.120"}},
			{Name: "dest", Type: "ip", Description: "Address that received the file", Examples: []string{"192.0.2.10"}},
			{Name: "url", Type: "string", Description: "Web address the file came from, when it came over HTTP"},
			{Name: "direction", Type: "string", Description: "Which way the file went, seen from your network: inbound, outbound, internal or external", Examples: []string{"inbound"}},
			{Name: "session_id", Type: "string", Description: "The sensor's ID for the connection (Zeek uid, Suricata flow_id)"},
			{Name: "community_id", Type: "string", Description: "Community ID of the flow, shared by Zeek and Suricata events of one connection"},
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
		Name:        "Vulnerabilities",
		Description: "Vulnerabilities and open services that network scans found: one event per open port, and one per known vulnerability (CVE) in the software on it.",
		Fields: []Field{
			{Name: "category", Type: "string", Description: "Kind of result: open_port (a port that answered) or vulnerability (a CVE that applies to the software on it)", Examples: []string{"open_port", "vulnerability"}},
			{Name: "dest", Type: "string", Description: "Host that was scanned: its name when it has one, else its address", Examples: []string{"web-01.corp.example"}},
			{Name: "dest_ip", Type: "ip", Description: "Address of that host", Examples: []string{"192.0.2.15"}},
			{Name: "dest_port", Type: "number", Description: "Port the service answers on", Examples: []string{"443"}},
			{Name: "transport", Type: "string", Description: "Protocol of the port", Examples: []string{"tcp"}},
			{Name: "app", Type: "string", Description: "Service on the port, as the scanner names it", Examples: []string{"ssh", "http", "microsoft-ds"}},
			{Name: "product", Type: "string", Description: "Software that answers on the port", Examples: []string{"OpenSSH", "Apache httpd"}},
			{Name: "product_version", Type: "string", Description: "Version of that software", Examples: []string{"8.2p1"}},
			{Name: "cpe", Type: "string", Description: "Product name in CPE form, which CVEs are matched to", Examples: []string{"cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"}},
			{Name: "cve", Type: "string", Description: "The vulnerability's CVE ID", Examples: []string{"CVE-2023-38408"}},
			{Name: "cvss", Type: "number", Description: "CVSS base score, from 0 to 10", Examples: []string{"9.8"}},
			{Name: "severity", Type: "string", Description: "Severity from the score: critical, high, medium, low, or informational for an open port", Examples: []string{"critical", "high"}},
			{Name: "known_exploited", Type: "string", Description: "true when the CVE is in CISA's Known Exploited Vulnerabilities catalog: attackers are using it", Examples: []string{"true", "false"}},
			{Name: "url", Type: "string", Description: "Where to read about the vulnerability", Examples: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-38408"}},
			{Name: "scan_id", Type: "string", Description: "Scan that found it"},
			{Name: "scan_network", Type: "string", Description: "Network the scan covered, as named on the Vulnerabilities page", Examples: []string{"Office LAN"}},
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
			{Name: "capture_loss_percent", Type: "number", Description: "Network sensor health (Zeek capture_loss): share of the traffic Zeek missed, in percent", Examples: []string{"0.12", "7.8"}},
			{Name: "drop_percent", Type: "number", Description: "Network sensor health (Suricata stats): share of packets the capture dropped since Suricata started, in percent", Examples: []string{"0", "2.5"}},
			{Name: "packets_received", Type: "number", Description: "Network sensor health (Suricata or Zeek stats): packets the capture received, since Suricata started or in Zeek's interval", Examples: []string{"18342211"}},
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
