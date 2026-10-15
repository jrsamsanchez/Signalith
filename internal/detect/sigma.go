package detect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// SigmaResult is a converted Sigma rule.
type SigmaResult struct {
	Detection *Detection `json:"detection"`
	// Warnings describe approximations the admin should review.
	Warnings []string `json:"warnings,omitempty"`
}

type sigmaRule struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id"`
	Status      string         `yaml:"status"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	Logsource   map[string]any `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	FalsePos    []string       `yaml:"falsepositives"`
}

// sigmaFields maps Sigma (Sysmon, Windows Security and antivirus) field names to
// Signalith data model fields.
var sigmaFields = map[string]string{
	"image":               "process_path",
	"commandline":         "process",
	"parentimage":         "parent_process_path",
	"parentcommandline":   "parent_process",
	"user":                "user",
	"hashes":              "process_hash",
	"processid":           "process_id",
	"destinationip":       "dest",
	"destinationport":     "dest_port",
	"destinationhostname": "dest_host",
	"sourceip":            "src",
	"sourceport":          "src_port",
	"protocol":            "transport",
	"eventid":             "signature_id",
	"targetusername":      "user",
	"subjectusername":     "src_user",
	"ipaddress":           "src",
	"ipport":              "src_port",
	"logontype":           "logon_type",
	"workstationname":     "src_host",
	"computer":            "host",
	"computername":        "host",
	"targetdomainname":    "user_domain",
	"membername":          "member",
	"targetsid":           "object",
	// Sysmon process fields (event 1).
	"originalfilename":  "original_file_name",
	"description":       "process_description",
	"product":           "process_product",
	"company":           "process_company",
	"fileversion":       "process_file_version",
	"integritylevel":    "process_integrity_level",
	"currentdirectory":  "process_current_directory",
	"parentprocessid":   "parent_process_id",
	"parentuser":        "parent_user",
	"logonid":           "logon_id",
	"processguid":       "process_guid",
	"parentprocessguid": "parent_process_guid",
	// Sysmon network fields (event 3); Initiated becomes direction.
	"sourcehostname":      "src_host",
	"initiated":           "direction",
	"sourceisipv6":        "src_is_ipv6",
	"destinationportname": "dest_port_name",
	// The provider that wrote the event, in any log source.
	"provider_name": "provider",
	"signature":     "signature",
	"filename":      "file_path",
}

// sigmaEventFields maps the fields of Sysmon and PowerShell log sources
// whose events land in other data models. In these log sources only the
// listed fields are mapped: a name such as Description means the loaded
// DLL's description in image_load, not the process's, so the process
// creation mapping would be wrong.
var sigmaEventFields = func() map[string]map[string]string {
	common := map[string]string{
		"image": "process_path", "user": "user", "processid": "process_id", "processguid": "process_guid",
		"computer": "host", "computername": "host", "eventid": "signature_id", "provider_name": "provider",
	}
	with := func(m map[string]string) map[string]string {
		for k, v := range common {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		return m
	}
	file := with(map[string]string{"targetfilename": "file_path"})
	registry := with(map[string]string{"targetobject": "registry_path", "details": "registry_value_data", "newname": "registry_new_path", "eventtype": "registry_event_type"})
	access := with(map[string]string{
		"sourceimage": "process_path", "sourceprocessid": "process_id", "sourceprocessguid": "process_guid",
		"sourceuser": "user", "targetimage": "target_process_path", "targetprocessid": "target_process_id",
		"targetprocessguid": "target_process_guid", "grantedaccess": "granted_access", "calltrace": "call_trace",
		"startaddress": "start_address", "startmodule": "start_module", "startfunction": "start_function",
		"image": "", "processid": "", "processguid": "", "user": "",
	})
	// An image load's Hashes, OriginalFileName, Description, Product
	// and Company are the loaded file's.
	load := with(map[string]string{
		"imageloaded": "loaded_file_path", "signed": "signed", "signature": "signature", "signaturestatus": "signature_status",
		"hashes": "loaded_file_hash", "originalfilename": "loaded_original_file_name", "description": "loaded_file_description",
		"product": "loaded_file_product", "company": "loaded_file_company",
	})
	// Security log events: the account that acted (Subject*) is the
	// user, except in a logon, where it is the account logged on
	// (Target*).
	security := func(m map[string]string) map[string]string {
		for k, v := range map[string]string{
			"subjectusername": "user", "subjectdomainname": "user_domain", "subjectlogonid": "logon_id",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		} {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		return m
	}
	logon := map[string]string{
		"targetusername": "user", "targetdomainname": "user_domain", "targetusersid": "user_sid",
		"logontype": "logon_type", "logonprocessname": "logon_process", "authenticationpackagename": "authentication_method",
		"workstationname": "src_host", "ipaddress": "src", "ipport": "src_port", "processname": "process_path",
		"computer": "host", "computername": "host", "eventid": "signature_id",
	}
	// A successful logon (4624) also names the account that asked for it
	// and, on newer Windows versions, more about the session.
	success := map[string]string{
		"subjectusersid": "src_user_sid", "subjectusername": "src_user", "subjectdomainname": "src_user_domain",
		"keylength": "key_length", "impersonationlevel": "impersonation_level", "restrictedadminmode": "restricted_admin_mode",
		"targetoutboundusername": "target_outbound_user", "targetoutbounddomainname": "target_outbound_domain",
		"virtualaccount": "virtual_account", "elevatedtoken": "elevated_token",
	}
	for k, v := range logon {
		success[k] = v
	}
	handle := security(map[string]string{
		"subjectusersid": "user_sid", "objectserver": "object_server", "objectname": "object_path", "objecttype": "object_type",
		"accesslist": "access_names", "accessmask": "access_mask", "processname": "process_path",
	})
	// A user account created or changed.
	account := security(map[string]string{
		"subjectusersid": "user_sid", "targetusername": "object", "targetdomainname": "object_domain", "targetsid": "object_sid",
		"samaccountname": "sam_account_name", "displayname": "display_name", "userprincipalname": "user_principal_name",
		"primarygroupid": "primary_group_id", "allowedtodelegateto": "allowed_to_delegate_to", "olduacvalue": "old_uac_value",
		"newuacvalue": "new_uac_value", "useraccountcontrol": "user_account_control", "sidhistory": "sid_history",
	})
	// A connection the filtering platform allowed or blocked.
	wfp := map[string]string{
		"processid": "process_id", "application": "process_path", "sourceaddress": "src", "sourceport": "src_port",
		"destaddress": "dest", "destport": "dest_port", "filterrtid": "filter_rtid", "layername": "layer_name",
		"layerrtid": "layer_rtid", "computer": "host", "computername": "host", "eventid": "signature_id",
	}
	// A group's member added or removed.
	group := security(map[string]string{
		"subjectusersid": "user_sid", "membername": "member", "membersid": "member_sid", "targetusername": "object",
		"targetdomainname": "object_domain", "targetsid": "object_sid",
	})
	// A scheduled task deleted or disabled.
	task := security(map[string]string{"subjectusersid": "user_sid", "taskname": "task_name", "taskcontent": "task_content"})
	kerberos := map[string]string{
		"targetusername": "user", "targetdomainname": "user_domain", "targetsid": "user_sid",
		"servicename": "kerberos_service", "servicesid": "kerberos_service_sid", "ticketoptions": "ticket_options",
		"status": "kerberos_status", "ticketencryptiontype": "ticket_encryption_type", "preauthtype": "pre_auth_type",
		"ipaddress": "src", "ipport": "src_port", "certissuername": "cert_issuer", "certserialnumber": "cert_serial",
		"certthumbprint": "cert_thumbprint", "computer": "host", "computername": "host", "eventid": "signature_id",
	}
	return map[string]map[string]string{
		"file_event": file, "file_delete": file,
		"registry_add": registry, "registry_delete": registry, "registry_set": registry, "registry_event": registry,
		"dns_query":            with(map[string]string{"queryname": "query", "queryresults": "answer"}),
		"pipe_created":         with(map[string]string{"pipename": "pipe_name", "eventtype": "pipe_event_type"}),
		"raw_access_thread":    with(map[string]string{"device": "device"}),
		"create_stream_hash":   with(map[string]string{"targetfilename": "file_path", "hash": "file_hashes", "contents": "file_contents"}),
		"image_load":           load,
		"driver_load":          with(map[string]string{"imageloaded": "loaded_file_path", "hashes": "loaded_file_hash", "signed": "signed", "signature": "signature", "signaturestatus": "signature_status", "image": "", "user": "", "processid": "", "processguid": ""}),
		"process_access":       access,
		"create_remote_thread": access,
		"security_4624":        success,
		"security_4625":        logon,
		"security_4663": security(map[string]string{
			"subjectusersid": "user_sid", "objectserver": "object_server", "objectname": "object_path", "objecttype": "object_type", "accesslist": "access_names",
			"accessmask": "access_mask", "processname": "process_path",
		}),
		"security_4656":      handle,
		"security_4656_4663": handle,
		"security_4657": security(map[string]string{
			"subjectusersid": "user_sid", "objectname": "object_path", "objectvaluename": "registry_value_name", "operationtype": "registry_operation",
			"oldvalue": "registry_old_value_data", "newvalue": "registry_value_data", "newvaluetype": "registry_value_type",
			"processname": "process_path",
		}),
		"security_4661": security(map[string]string{
			"subjectusersid": "user_sid", "objectserver": "object_server", "objectname": "object_path", "objecttype": "object_type",
			"accesslist": "access_names", "accessmask": "access_mask", "properties": "object_properties", "processname": "process_path",
		}),
		"security_4662": security(map[string]string{
			"subjectusersid": "user_sid", "objectserver": "object_server", "objectname": "object", "objecttype": "object_type",
			"accesslist": "access_names", "accessmask": "access_mask", "properties": "object_properties",
		}),
		"security_4648": security(map[string]string{
			"subjectusersid": "user_sid", "subjectusername": "src_user", "subjectdomainname": "src_user_domain",
			"targetusername": "user", "targetdomainname": "user_domain", "targetservername": "dest", "targetinfo": "target_info",
			"processname": "process_path", "ipaddress": "src", "ipport": "src_port",
		}),
		"security_5156": wfp,
		"security_5157": wfp,
		"security_4706": security(map[string]string{
			"subjectusersid": "user_sid", "domainname": "object", "domainsid": "object_sid", "tdotype": "trust_type",
			"tdodirection": "trust_direction", "tdoattributes": "trust_attributes",
		}),
		"security_4719": security(map[string]string{
			"subjectusersid": "user_sid", "categoryid": "audit_category", "subcategoryid": "audit_subcategory",
			"subcategoryguid": "audit_subcategory_guid", "auditpolicychanges": "audit_policy_changes",
		}),
		"security_4720": account,
		"security_4738": account,
		"security_4732": group,
		"security_4794": security(map[string]string{"subjectusersid": "user_sid", "workstation": "src_host"}),
		"security_4728": group,
		"security_4729": group,
		"security_4730": security(map[string]string{
			"subjectusersid": "user_sid", "targetusername": "object", "targetdomainname": "object_domain", "targetsid": "object_sid",
		}),
		"security_1102":      security(map[string]string{"subjectusersid": "user_sid", "provider_name": "provider"}),
		"security_4699":      task,
		"security_4701":      task,
		"security_4699_4701": task,
		"security_4702":      security(map[string]string{"subjectusersid": "user_sid", "taskname": "task_name", "taskcontentnew": "task_content"}),
		"security_5140": security(map[string]string{
			"subjectusersid": "user_sid", "objecttype": "object_type", "ipaddress": "src", "ipport": "src_port",
			"sharename": "share_name", "sharelocalpath": "share_path", "accessmask": "access_mask", "accesslist": "access_names",
		}),
		"security_4768": kerberos,
		"security_4769": kerberos,
		"security_4697": security(map[string]string{
			"servicename": "service_name", "servicefilename": "service_path", "servicetype": "service_type",
			"servicestarttype": "service_start_type", "serviceaccount": "service_account",
			"clientprocessid": "client_process_id", "parentprocessid": "parent_process_id",
		}),
		"security_4698": security(map[string]string{"taskname": "task_name", "taskcontent": "task_content"}),
		"security_5136": security(map[string]string{
			"objectdn": "object", "objectguid": "ad_object_guid", "objectclass": "ad_object_class",
			"attributeldapdisplayname": "ad_attribute", "attributevalue": "ad_value", "operationtype": "ad_operation",
		}),
		"security_5145": security(map[string]string{
			"objecttype": "object_type", "ipaddress": "src", "ipport": "src_port", "sharename": "share_name",
			"sharelocalpath": "share_path", "relativetargetname": "share_target", "accessmask": "access_mask",
			"accesslist": "access_names",
		}),
		"system": {
			"servicename": "service_name", "imagepath": "service_path", "servicetype": "service_type",
			"starttype": "service_start_type", "accountname": "service_account", "provider_name": "provider",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		},
		// Defender's event data as its message names it (Path, Process
		// Name, New Value).
		"windefend": {
			"path": "file_path", "processname": "process_path", "newvalue": "new_value", "oldvalue": "old_value",
			"sourcename": "detection_source", "value": "setting",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		},
		"ps_script": {
			"scriptblocktext": "script_block_text", "path": "script_path", "scriptblockid": "script_block_id",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		},
	}
}()

// sigmaWindowsEvents are the Windows event IDs each log source is, so a
// Windows rule only sees its own kind of event: process creation and
// process access both land in Endpoint, for example.
var sigmaWindowsEvents = map[string][]string{
	"process_creation":     {"1", "4688"},
	"network_connection":   {"3"},
	"file_event":           {"11"},
	"file_delete":          {"23", "26"},
	"registry_add":         {"12"},
	"registry_delete":      {"12"},
	"registry_set":         {"13"},
	"registry_event":       {"12", "13", "14"},
	"dns_query":            {"22"},
	"pipe_created":         {"17", "18"},
	"raw_access_thread":    {"9"},
	"create_stream_hash":   {"15"},
	"image_load":           {"7"},
	"driver_load":          {"6"},
	"process_access":       {"10"},
	"create_remote_thread": {"8"},
	"ps_script":            {"4104"},
	"system":               {"7045"},
	"windefend": {"1006", "1007", "1008", "1009", "1015", "1116", "1117", "1118", "1119", "1121", "1122", "1123", "1124",
		"1125", "1126", "1127", "1128", "1150", "1151", "2000", "2001", "2002", "2003", "2004", "2006", "3002", "5000",
		"5001", "5004", "5007", "5008", "5009", "5010", "5011", "5012", "5013", "5101"},
	"security_4624":      {"4624"},
	"security_4625":      {"4625"},
	"security_4648":      {"4648"},
	"security_4656":      {"4656"},
	"security_4657":      {"4657"},
	"security_4661":      {"4661"},
	"security_4662":      {"4662"},
	"security_4663":      {"4663"},
	"security_4656_4663": {"4656", "4663"},
	"security_4706":      {"4706"},
	"security_4719":      {"4719"},
	"security_4720":      {"4720"},
	"security_4732":      {"4732"},
	"security_4738":      {"4738"},
	"security_4794":      {"4794"},
	"security_4728":      {"4728"},
	"security_4729":      {"4729"},
	"security_4730":      {"4730"},
	"security_1102":      {"1102"},
	"security_4699":      {"4699"},
	"security_4701":      {"4701"},
	"security_4699_4701": {"4699", "4701"},
	"security_4702":      {"4702"},
	"security_5140":      {"5140"},
	"security_4768":      {"4768"},
	"security_4769":      {"4769"},
	"security_4697":      {"4697"},
	"security_4698":      {"4698"},
	"security_5136":      {"5136"},
	"security_5145":      {"5145"},
	"security_5156":      {"5156"},
	"security_5157":      {"5157"},
}

// sigmaSecurityModels are the Security log events Security log rules
// (service: security) convert for, with each one's data model: a handle
// request or an object access is a file's (Filesystem), a registry key's
// (Registry) or another object's, so its rules search any.
var sigmaSecurityModels = map[string]string{
	"4624": "Authentication", "4625": "Authentication", "4656": "", "4657": "Registry", "4661": "", "4662": "Change",
	"4663": "", "4697": "Change", "4698": "Change", "4706": "Change", "4719": "Change", "4720": "Change", "4732": "Change",
	"4738": "Change", "4794": "Change", "4768": "Authentication", "4769": "Authentication",
	"4648": "Authentication", "4728": "Change", "4729": "Change", "4730": "Change", "1102": "Change", "4699": "Change",
	"4701": "Change", "4699_4701": "Change", "4702": "Change", "5140": "Filesystem", "5136": "Change", "5145": "Filesystem", "5156": "Network_Traffic", "5157": "Network_Traffic",
}

// anyModel reports whether the rule's events land in more than one data
// model, so it searches them all.
func (c *sigmaConv) anyModel() bool {
	switch c.category {
	case "security_4656", "security_4661", "security_4663", "security_4656_4663":
		return true
	}
	return false
}

// sigmaEventIDs returns the event IDs a rule's selections name (EventID
// without modifiers), sorted.
func sigmaEventIDs(det map[string]any) []string {
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, it := range x {
				walk(it)
			}
		case map[string]any:
			for k, val := range x {
				if k != "EventID" {
					continue
				}
				if list, ok := val.([]any); ok {
					for _, it := range list {
						seen[fmt.Sprint(it)] = true
					}
				} else {
					seen[fmt.Sprint(val)] = true
				}
			}
		}
	}
	for k, v := range det {
		if k != "condition" {
			walk(v)
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// modernEventIDs drops the Windows 2000 and XP event IDs (below 1000,
// such as 517 for the log cleared) from a rule's event IDs when it also
// names current ones: those systems' events never reach Signalith, so a
// selection on them matches nothing either way.
func modernEventIDs(ids []string) []string {
	modern := slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
		n, err := strconv.Atoi(id)
		return err == nil && n < 1000
	})
	if len(modern) == 0 {
		return ids
	}
	return modern
}

// sigmaLevels maps Sigma levels to severities.
var sigmaLevels = map[string]string{
	"informational": "informational", "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}

var sigmaTechnique = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)

// SigmaOptions changes how a rule converts.
type SigmaOptions struct {
	// Strict refuses any approximation, instead of warning about it: a
	// field without a Signalith mapping, a free-text keyword search, a log
	// source without a data model, and |cased. The SigmaHQ content pack
	// converts strictly, so every shipped rule means exactly what its
	// author wrote.
	Strict bool
}

// ConvertSigma converts one Sigma rule (YAML) into a disabled detection.
// Rules that use features Signalith cannot express, such as regular
// expressions, return an error naming the feature.
func ConvertSigma(src []byte) (*SigmaResult, error) {
	return ConvertSigmaWith(src, SigmaOptions{})
}

// ConvertSigmaWith is ConvertSigma with options.
func ConvertSigmaWith(src []byte, opt SigmaOptions) (*SigmaResult, error) {
	var r sigmaRule
	if err := yaml.Unmarshal(src, &r); err != nil {
		return nil, fmt.Errorf("not valid Sigma YAML: %w", err)
	}
	if r.Title == "" || r.Detection == nil {
		return nil, errors.New("not a Sigma rule: title and detection are required")
	}
	category, _ := r.Logsource["category"].(string)
	if product, _ := r.Logsource["product"].(string); category == "" && strings.EqualFold(product, "windows") {
		switch service, _ := r.Logsource["service"].(string); strings.ToLower(service) {
		case "system":
			// Services installed (7045), in Change; a rule about other
			// System log events finds them in Other, by provider and
			// event ID, with the data of the events the parser reads.
			category = "system"
			if ids := sigmaEventIDs(r.Detection); len(ids) > 0 && !slices.Contains(ids, "7045") {
				category = "system_event"
			}
		case "windefend":
			// Microsoft Defender Antivirus's own log, each rule naming
			// the events it is about.
			category = "windefend"
		case "application":
			// The Application log, each rule naming its provider and
			// events, and searching their data (Data).
			category = "application"
		case "codeintegrity-operational":
			// Code Integrity's log, each rule naming its events.
			category = "code_integrity"
		case "sysmon":
			// Sysmon's own events, by event ID: its file blocks (27, 28,
			// 29) are file events, the rest (a configuration change)
			// Other.
			category = "sysmon_event"
			if ids := sigmaEventIDs(r.Detection); len(ids) > 0 && !slices.ContainsFunc(ids, func(id string) bool {
				return id != "27" && id != "28" && id != "29"
			}) {
				category = "sysmon_file_block"
			}
		default:
			// A log the parser reads by name (Windows Firewall, BITS, AppX
			// deployment, WMI), each rule naming its events and their
			// data.
			if _, ok := ingest.NamedChannelServices[strings.ToLower(service)]; ok {
				category = ingest.NamedChannelCategory(service)
			}
		case "security":
			// A Security log rule's fields are its event's own, so it
			// converts for one event, or events with the same data.
			category = "security"
			if ids := modernEventIDs(sigmaEventIDs(r.Detection)); ingest.IsNamedSecurityEvents(ids...) {
				// Events no data model holds, read by name.
				category = "security_named"
			} else if len(ids) > 0 {
				if _, ok := sigmaWindowsEvents["security_"+strings.Join(ids, "_")]; ok {
					category = "security_" + strings.Join(ids, "_")
				}
			}
		}
	}
	if product, _ := r.Logsource["product"].(string); category == "" && strings.EqualFold(product, "linux") {
		if service, _ := r.Logsource["service"].(string); strings.EqualFold(service, "auditd") {
			// Linux audit records (service: auditd), each field named as
			// auditd names it.
			category = "auditd"
		}
	}
	c := &sigmaConv{strict: opt.Strict, category: strings.ToLower(category)}
	dm := c.datamodel(r.Logsource)
	if c.category == "security" {
		c.approx("Signalith converts Security log rules about one of the events %s", strings.Join(slices.Sorted(maps.Keys(sigmaSecurityModels)), ", "))
	}
	if dm == "" && opt.Strict && !c.anyModel() {
		return nil, fmt.Errorf("log source %v has no Signalith data model", r.Logsource)
	}
	cond, ok := r.Detection["condition"]
	if !ok {
		return nil, errors.New("detection.condition is missing")
	}
	condStr, ok := cond.(string)
	if !ok {
		if list, isList := cond.([]any); isList && len(list) == 1 {
			condStr, ok = list[0].(string)
		}
	}
	if !ok {
		return nil, errors.New("only a single detection.condition is supported")
	}
	if strings.Contains(condStr, "|") {
		return nil, errors.New("Sigma aggregation conditions (| count() ...) are not supported; use a correlation in the query instead")
	}
	if c.category == "system" && !bytes.Contains(src, []byte("7045")) {
		c.approx("Signalith reads only services installed (event 7045) from the System log, and this rule is about other events")
	}
	expr, err := c.condition(condStr, r.Detection)
	if err != nil {
		return nil, err
	}
	if c.err != nil {
		return nil, c.err
	}
	if scope := productScope(r.Logsource, c.category); scope != nil {
		expr = and([]query.Expr{scope, expr})
	}
	q := &query.Query{Datamodel: dm, Search: expr}

	d := &Detection{
		ID:          sigmaID(r),
		Title:       r.Title,
		Description: strings.TrimSpace(r.Description),
		Query:       q.String(),
		Schedule:    "5m",
		Lookback:    "10m",
		Severity:    "medium",
		Enabled:     false,
		Tags:        []string{"sigma"},
		Throttle:    Throttle{Window: "1h"},
	}
	if s, ok := sigmaLevels[strings.ToLower(r.Level)]; ok {
		d.Severity = s
	}
	seen := map[string]bool{}
	for _, t := range r.Tags {
		if m := sigmaTechnique.FindStringSubmatch(strings.ToLower(t)); m != nil {
			id := strings.ToUpper(m[1])
			if !seen[id] {
				seen[id] = true
				d.MITRE = append(d.MITRE, id)
			}
		}
	}
	if len(r.FalsePos) > 0 {
		d.Guidance = "Known false positives: " + strings.Join(r.FalsePos, "; ")
	}
	if r.Status != "" && r.Status != "stable" && r.Status != "test" {
		c.warn("rule status is %q; review it before enabling", r.Status)
	}
	if dm == "" {
		c.warn("log source %v has no Signalith data model, so the rule searches all events", r.Logsource)
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	sort.Strings(c.warnings)
	return &SigmaResult{Detection: d, Warnings: dedupe(c.warnings)}, nil
}

func dedupe(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

var nonID = regexp.MustCompile(`[^a-z0-9]+`)

func sigmaID(r sigmaRule) string {
	slug := strings.Trim(nonID.ReplaceAllString(strings.ToLower(r.Title), "-"), "-")
	if len(slug) > 48 {
		slug = strings.TrimRight(slug[:48], "-")
	}
	id := "sigma-" + slug
	if len(id) < 3 {
		id = "sigma-rule"
	}
	return id
}

type sigmaConv struct {
	strict   bool
	category string // the log source category, lower case
	warnings []string
	err      error // the first approximation, in strict mode
}

func (c *sigmaConv) warn(format string, args ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

// approx records an approximation: a warning, or in strict mode an error.
func (c *sigmaConv) approx(format string, args ...any) {
	if c.strict && c.err == nil {
		c.err = fmt.Errorf(format, args...)
	}
	c.warn(format, args...)
}

// windowsSourcetypes matches every event the Windows parser writes, from
// Fluent Bit and from the OpenTelemetry Collector alike.
const windowsSourcetypes = "WinEventLog:*"

// productScope limits a rule to its operating system's events: a Windows
// rule to Windows events of its log source's event IDs, and a Linux or
// macOS rule away from Windows events, since data models such as Endpoint
// hold events from every system and several kinds of event.
func productScope(ls map[string]any, category string) query.Expr {
	p, _ := ls["product"].(string)
	switch strings.ToLower(p) {
	case "windows":
		switch category {
		case "system_event":
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:" + ingest.SystemChannel}
		case "application":
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:" + ingest.ApplicationChannel}
		case "code_integrity":
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:" + ingest.CodeIntegrityChannel}
		}
		if ch, ok := sigmaNamedChannels[category]; ok {
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:" + ch}
		}
		if category == "security_named" {
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:" + ingest.SecurityChannel}
		}
		if category == "sysmon_event" || category == "sysmon_file_block" {
			return &query.Compare{Field: "sourcetype", Op: "=", Value: "WinEventLog:Microsoft-Windows-Sysmon/Operational"}
		}
		st := &query.Compare{Field: "sourcetype", Op: "=", Value: windowsSourcetypes}
		if ids := sigmaWindowsEvents[category]; len(ids) > 0 {
			return and([]query.Expr{st, &query.In{Field: "signature_id", Values: ids}})
		}
		return st
	case "linux", "macos":
		if category == "auditd" {
			return &query.Compare{Field: "sourcetype", Op: "=", Value: ingest.AuditdSourcetype}
		}
		return &query.Not{Child: &query.Compare{Field: "sourcetype", Op: "=", Value: windowsSourcetypes}}
	}
	return nil
}

func (c *sigmaConv) datamodel(ls map[string]any) string {
	get := func(k string) string { s, _ := ls[k].(string); return strings.ToLower(s) }
	switch c.category {
	case "process_creation":
		return "Endpoint"
	case "network_connection", "firewall":
		return "Network_Traffic"
	case "authentication":
		return "Authentication"
	case "antivirus":
		return "Malware"
	case "file_event", "file_delete", "create_stream_hash":
		return "Filesystem"
	case "registry_add", "registry_delete", "registry_set", "registry_event":
		return "Registry"
	case "dns_query":
		return "Network_Resolution"
	case "image_load", "driver_load":
		return "Image_Load"
	case "process_access", "create_remote_thread", "pipe_created", "raw_access_thread":
		return "Endpoint"
	case "ps_script":
		return "Script"
	case "system":
		return "Change"
	case "system_event", "application", "code_integrity", "sysmon_event", "security_named":
		return "Other"
	case "sysmon_file_block":
		return "Filesystem"
	case "auditd":
		return "Other"
	case "windefend":
		return "Malware"
	}
	if _, ok := sigmaNamedChannels[c.category]; ok {
		return "Other"
	}
	if id, ok := strings.CutPrefix(c.category, "security_"); ok {
		return sigmaSecurityModels[id]
	}
	if get("product") == "linux" && get("service") == "auth" {
		return "Authentication"
	}
	return ""
}

func (c *sigmaConv) field(name string) string {
	if c.category == "auditd" {
		return c.auditdField(name)
	}
	if c.category == "system_event" {
		return c.systemField(name)
	}
	if c.category == "application" || c.category == "code_integrity" {
		return c.eventDataField(name)
	}
	if ch, ok := sigmaNamedChannels[c.category]; ok {
		return c.channelField(ch, name)
	}
	if c.category == "security_named" {
		return c.channelField(ingest.SecurityChannel, name)
	}
	if c.category == "sysmon_file_block" {
		if f, ok := sigmaEventFields["file_event"][strings.ToLower(name)]; ok {
			return f
		}
	}
	if m, ok := sigmaEventFields[c.category]; ok {
		if f := m[strings.ToLower(name)]; f != "" {
			return f
		}
		c.approx("field %s has no Signalith mapping in %s and is searched as-is", name, c.category)
		return name
	}
	if f, ok := sigmaFields[strings.ToLower(name)]; ok {
		return f
	}
	c.approx("field %s has no Signalith mapping and is searched as-is", name)
	return name
}

// systemField is the stored field of a System log event's field: its
// provider, ID and host, or its data (see ingest.SystemDataField).
func (c *sigmaConv) systemField(name string) string {
	switch strings.ToLower(name) {
	case "provider_name":
		return "provider"
	case "eventid":
		return "signature_id"
	case "computer", "computername":
		return "host"
	}
	f, ok := ingest.SystemDataField(name)
	if !ok {
		c.approx("field %s is not data Signalith reads from System log events", name)
		return name
	}
	return f
}

// eventDataField is the stored field of an Application or Code Integrity
// log event's field: its provider, ID and host, or its data values
// (Data).
func (c *sigmaConv) eventDataField(name string) string {
	switch strings.ToLower(name) {
	case "provider_name":
		return "provider"
	case "eventid":
		return "signature_id"
	case "computer", "computername":
		return "host"
	case "data":
		return "event_data"
	}
	c.approx("field %s is not data Signalith reads by name from these log events", name)
	return name
}

// sigmaNamedChannels are the Windows logs whose events the parser reads by
// name (ingest.ChannelDataField), by the category of their rules.
var sigmaNamedChannels = func() map[string]string {
	out := map[string]string{}
	for service, channel := range ingest.NamedChannelServices {
		out[ingest.NamedChannelCategory(service)] = channel
	}
	return out
}()

// channelField is the stored field of such a log's event's field: its
// provider, ID and host, or its data (see ingest.ChannelDataField).
func (c *sigmaConv) channelField(channel, name string) string {
	switch strings.ToLower(name) {
	case "provider_name":
		return "provider"
	case "eventid":
		return "signature_id"
	case "computer", "computername":
		return "host"
	}
	f, ok := ingest.ChannelDataField(channel, name)
	if !ok {
		c.approx("field %s is not data Signalith reads from %s events", name, channel)
		return name
	}
	return f
}

// auditdField is the stored field of an audit record's field (see
// ingest.AuditdField).
func (c *sigmaConv) auditdField(name string) string {
	f, ok := ingest.AuditdField(name)
	if !ok {
		c.approx("field %s is not an audit record field", name)
		return name
	}
	return f
}

// ---- condition expressions ----

func (c *sigmaConv) condition(cond string, det map[string]any) (query.Expr, error) {
	toks := tokenizeCondition(cond)
	p := &condParser{toks: toks, det: det, conv: c}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("condition: unexpected %q", p.toks[p.pos])
	}
	return e, nil
}

func tokenizeCondition(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

type condParser struct {
	toks []string
	pos  int
	det  map[string]any
	conv *sigmaConv
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *condParser) or() (query.Expr, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	kids := []query.Expr{left}
	for p.peek() == "or" {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	return or(kids), nil
}

func (p *condParser) and() (query.Expr, error) {
	left, err := p.not()
	if err != nil {
		return nil, err
	}
	kids := []query.Expr{left}
	for p.peek() == "and" {
		p.pos++
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	return and(kids), nil
}

func (p *condParser) not() (query.Expr, error) {
	if p.peek() == "not" {
		p.pos++
		e, err := p.not()
		if err != nil {
			return nil, err
		}
		return &query.Not{Child: e}, nil
	}
	return p.primary()
}

func (p *condParser) primary() (query.Expr, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, errors.New("condition ended early")
	case t == "(":
		p.pos++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("condition: missing )")
		}
		p.pos++
		return e, nil
	case t == "1" || t == "all" || t == "any":
		p.pos++
		if p.peek() != "of" {
			return nil, fmt.Errorf("condition: expected 'of' after %q", t)
		}
		p.pos++
		if p.pos >= len(p.toks) {
			return nil, errors.New("condition: 'of' needs a selection name, pattern or 'them'")
		}
		pat := p.toks[p.pos]
		p.pos++
		names := p.match(pat)
		if len(names) == 0 {
			return nil, fmt.Errorf("condition: no selection matches %q", pat)
		}
		var kids []query.Expr
		for _, n := range names {
			e, err := p.conv.selection(n, p.det[n])
			if err != nil {
				return nil, err
			}
			kids = append(kids, e)
		}
		if t == "all" {
			return and(kids), nil
		}
		return or(kids), nil
	}
	name := p.toks[p.pos]
	p.pos++
	v, ok := p.det[name]
	if !ok || name == "condition" {
		return nil, fmt.Errorf("condition refers to unknown selection %q", name)
	}
	return p.conv.selection(name, v)
}

func (p *condParser) match(pat string) []string {
	var out []string
	for k := range p.det {
		if k == "condition" || k == "timeframe" {
			continue
		}
		if pat == "them" || k == pat || (strings.HasSuffix(pat, "*") && strings.HasPrefix(k, strings.TrimSuffix(pat, "*"))) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// uniq drops repeated expressions, which arise when two Sigma fields map
// to the same Signalith field.
func uniq(kids []query.Expr) []query.Expr {
	seen := map[string]bool{}
	out := kids[:0:0]
	for _, k := range kids {
		if s := k.String(); !seen[s] {
			seen[s] = true
			out = append(out, k)
		}
	}
	return out
}

func and(kids []query.Expr) query.Expr {
	kids = uniq(kids)
	if len(kids) == 1 {
		return kids[0]
	}
	return &query.And{Children: kids}
}

func or(kids []query.Expr) query.Expr {
	kids = uniq(kids)
	if len(kids) == 1 {
		return kids[0]
	}
	return &query.Or{Children: kids}
}

// ---- selections ----

func (c *sigmaConv) selection(name string, v any) (query.Expr, error) {
	switch s := v.(type) {
	case map[string]any:
		return c.fieldMap(s)
	case []any:
		var kids []query.Expr
		for _, item := range s {
			switch it := item.(type) {
			case map[string]any:
				e, err := c.fieldMap(it)
				if err != nil {
					return nil, err
				}
				kids = append(kids, e)
			default:
				// Keyword list: free-text search of the raw event.
				c.approx("selection %s searches free text, which matches words of the raw event rather than exact values", name)
				kids = append(kids, &query.Text{Value: "*" + sigmaString(it) + "*"})
			}
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("selection %s is empty", name)
		}
		return or(kids), nil
	case string:
		c.approx("selection %s searches free text, which matches words of the raw event rather than exact values", name)
		return &query.Text{Value: "*" + s + "*"}, nil
	}
	return nil, fmt.Errorf("selection %s has an unsupported shape", name)
}

func (c *sigmaConv) fieldMap(m map[string]any) (query.Expr, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var kids []query.Expr
	for _, k := range keys {
		e, err := c.fieldCond(k, m[k])
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
	}
	if len(kids) == 0 {
		return nil, errors.New("empty selection")
	}
	return and(kids), nil
}

func sigmaString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func (c *sigmaConv) fieldCond(key string, v any) (query.Expr, error) {
	parts := strings.Split(key, "|")
	sigField, mods := parts[0], parts[1:]
	field := c.field(sigField)
	var values []any
	switch vv := v.(type) {
	case []any:
		values = vv
	default:
		values = []any{vv}
	}
	all := false
	how := "equals"
	reFlags := ""
	// transforms apply in order to each value before matching.
	var transforms []string
	for _, m := range mods {
		switch lm := strings.ToLower(m); lm {
		case "contains", "startswith", "endswith", "cidr", "re":
			how = lm
		case "i", "m", "s":
			// Regular expression flags.
			reFlags += lm
		case "all":
			all = true
		case "windash", "base64", "base64offset", "utf16le", "wide", "utf16be", "utf16":
			transforms = append(transforms, lm)
		case "exists":
			if b, ok := v.(bool); ok && !b {
				return &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}}, nil
			}
			if s, ok := v.(string); ok && strings.EqualFold(s, "false") {
				return &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}}, nil
			}
			return &query.Compare{Field: field, Op: "=", Value: "*"}, nil
		case "cased":
			c.approx("%s: |cased is matched case-insensitively", key)
		default:
			return nil, fmt.Errorf("Sigma modifier |%s (in %s) is not supported", m, key)
		}
	}
	var kids []query.Expr
	for _, raw := range values {
		if raw == nil || sigmaString(raw) == "" {
			// Signalith does not store empty values, so an empty value
			// and a missing field are the same.
			kids = append(kids, &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}})
			continue
		}
		s := sigmaString(raw)
		if field == "direction" {
			// Sysmon's Initiated is stored as the direction it implies.
			switch strings.ToLower(s) {
			case "true":
				s = "outbound"
			case "false":
				s = "inbound"
			}
		}
		if how == "re" {
			e, err := c.regex(field, key, reFlags, s)
			if err != nil {
				return nil, err
			}
			kids = append(kids, e)
			continue
		}
		if how == "cidr" {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not an address range", key, s)
			}
			kids = append(kids, &query.Compare{Field: field, Op: "=", Value: p.Masked().String()})
			continue
		}
		var variants []string
		if len(transforms) > 0 {
			// Transformed values are literal text: the encodings have no
			// wildcards of their own.
			lit, err := sigmaLiteral(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			variants = []string{lit}
			for _, t := range transforms {
				variants = transform(t, variants)
			}
			for i, v := range variants {
				if strings.ContainsAny(v, "*?") {
					return nil, fmt.Errorf("%s: the %s form of %q holds a wildcard character", key, strings.Join(transforms, "|"), s)
				}
				if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 && r != '\t' }) {
					return nil, fmt.Errorf("%s: the %s form of %q is binary", key, strings.Join(transforms, "|"), s)
				}
				variants[i] = v
			}
		} else {
			v, err := sigmaValue(s)
			if errors.Is(err, errEscapedWildcard) {
				// A literal * or ? in a pattern: a regular expression says
				// it.
				e, err := c.regex(field, key, "is", sigmaWildcardRegex(s, how))
				if err != nil {
					return nil, err
				}
				kids = append(kids, e)
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			variants = []string{v}
		}
		var vk []query.Expr
		for _, s := range variants {
			switch how {
			case "contains":
				s = "*" + s + "*"
			case "startswith":
				s = s + "*"
			case "endswith":
				s = "*" + s
			}
			vk = append(vk, c.compare(field, sigField, how, s))
		}
		kids = append(kids, or(vk))
	}
	if all {
		return and(kids), nil
	}
	return or(kids), nil
}

// pathNames are the path fields whose file name every parser that sets
// them also stores.
var pathNames = map[string]string{
	"process_path": "process_name", "parent_process_path": "parent_process_name",
	"target_process_path": "target_process_name", "loaded_file_path": "loaded_file_name",
}

// compare builds field=value, preferring process_name over a path
// suffix match since it is cheaper and exact.
func (c *sigmaConv) compare(field, sigField, how, s string) query.Expr {
	if name, ok := pathNames[field]; ok && how == "endswith" {
		rest := strings.TrimPrefix(s, "*")
		if i := strings.LastIndexAny(rest, `\/`); i == 0 && !strings.ContainsAny(rest[1:], `*?\/`) {
			return &query.Compare{Field: name, Op: "=", Value: rest[1:]}
		}
	}
	return &query.Compare{Field: field, Op: "=", Value: s}
}

// errEscapedWildcard is a value with a literal * or ?, which a wildcard
// pattern cannot say.
var errEscapedWildcard = errors.New("escaped wildcard")

// sigmaValue resolves Sigma escapes: \\ is a backslash; \* and \? are
// literal wildcards, which a Signalith pattern cannot express
// (errEscapedWildcard).
func sigmaValue(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			case '*', '?':
				return "", errEscapedWildcard
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

// regex is field=~pattern for a Sigma regular expression (|re, with
// the flags of |i, |m and |s): found anywhere in the value, and
// case-sensitive unless it says otherwise. A long text field is indexed
// lowercased, so a case-sensitive expression cannot be searched on one.
func (c *sigmaConv) regex(field, key, flags, pattern string) (query.Expr, error) {
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	if _, err := search.ParseRegex(pattern); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if search.WildcardFields[field] && search.CaseMatters(pattern) {
		return nil, fmt.Errorf("%s: a case-sensitive regular expression on %s, which is searched ignoring case", key, field)
	}
	return &query.Compare{Field: field, Op: "=~", Value: pattern}, nil
}

// sigmaWildcardRegex is the regular expression of a Sigma pattern with
// a literal * or ?: * any run of characters, ? any one, the rest (and
// the escaped wildcards) literal, matched as how says.
func sigmaWildcardRegex(s, how string) string {
	var b strings.Builder
	if how == "equals" || how == "startswith" {
		b.WriteByte('^')
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(string(rs[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if how == "equals" || how == "endswith" {
		b.WriteByte('$')
	}
	return b.String()
}

// sigmaLiteral resolves a value's escapes and refuses wildcards, for
// values that are encoded before matching.
func sigmaLiteral(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '*' || c == '?' {
			return "", fmt.Errorf("a wildcard in %q cannot be encoded", s)
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

// transform applies one value-transforming Sigma modifier to each
// variant.
func transform(t string, vs []string) []string {
	var out []string
	for _, v := range vs {
		switch t {
		case "windash":
			out = append(out, windashVariants(v)...)
		case "base64":
			out = append(out, base64.StdEncoding.EncodeToString([]byte(v)))
		case "base64offset":
			out = append(out, base64Offsets(v)...)
		case "utf16le", "wide":
			out = append(out, encodeUTF16(v, false, false))
		case "utf16be":
			out = append(out, encodeUTF16(v, true, false))
		case "utf16":
			out = append(out, encodeUTF16(v, false, true))
		}
	}
	return out
}

func encodeUTF16(s string, bigEndian, bom bool) string {
	var b []byte
	if bom {
		b = append(b, 0xff, 0xfe)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return string(b)
}

// base64Offsets returns the base64 text of s at each of the three byte
// offsets it can start at inside longer data, cut to the characters that
// do not depend on the bytes around it (Sigma's |base64offset).
func base64Offsets(s string) []string {
	cutStart := [3]int{0, 2, 3}
	cutEnd := [3]int{0, 3, 2}
	var out []string
	for i := range 3 {
		enc := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{' '}, i), s...))
		end := len(enc) - cutEnd[(len(s)+i)%3]
		if end > cutStart[i] {
			out = append(out, enc[cutStart[i]:end])
		}
	}
	return out
}

// windashVariants expands - and / at the start of a command-line switch
// (after a non-word character or the start, before a word character) into
// every dash form Windows accepts, as Sigma's |windash defines it.
func windashVariants(s string) []string {
	dashes := []string{"-", "/", "–", "—", "―"}
	rs := []rune(s)
	word := func(r rune) bool {
		return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range dashes {
		var b strings.Builder
		for i, r := range rs {
			if (r == '-' || r == '/') && (i == 0 || !word(rs[i-1])) && i+1 < len(rs) && word(rs[i+1]) {
				b.WriteString(d)
				continue
			}
			b.WriteRune(r)
		}
		if v := b.String(); !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
