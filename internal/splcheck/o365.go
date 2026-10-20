// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// O365Node is the node of Microsoft 365 audit records (the
// o365_management_activity macro). A search names no event code. Its
// fields are the record's own (Operation, Workload, LogonError,
// ModifiedProperties{}.NewValue), which Signalith keeps by the same
// names, and the CIM fields Splunk's Microsoft 365 add-on gives each
// record, which Signalith sets too.
const O365Node = "O365"

// o365Source is the macro of Microsoft 365 audit records.
const o365Source = "o365_management_activity"

// o365CIM are the CIM fields of a Microsoft 365 record, with the
// Signalith field each is stored as. A sign-in's user agent is one of its
// extended properties, which Splunk's add-on reads as UserAgent and
// Signalith keeps as user_agent; its operating system one of its device
// properties, OS to the add-on and os to Signalith.
var o365CIM = map[string]string{
	"action": "action", "status": "status", "user": "user", "user_id": "user", "src": "src", "src_ip": "src",
	"dest": "dest", "signature": "signature", "command": "command", "app": "app", "user_agent": "user_agent",
	"UserAgent": "user_agent", "reason": "reason", "vendor_account": "vendor_account", "vendor_product": "vendor_product",
	"object": "object", "object_category": "object_category", "record_type": "record_type",
	"authentication_method": "authentication_method", "change_type": "change_type", "sourcetype": "sourcetype",
	"OS": "os",
}

// o365Fields are the fields of Microsoft's audit record schema that a
// search may name, as Signalith keeps them: the common schema, and the
// fields of Entra ID, Exchange, SharePoint, the Security & Compliance
// Center's alerts and searches, and Defender for Office 365's email
// records. A list's values are by Splunk's names for them
// (ModifiedProperties{}.NewValue). An Exchange cmdlet's parameters are
// only in Parameters{}.Name and Parameters{}.Value, not by their own
// names (Role, AccessRights), as Splunk's add-on extracts them.
var o365Fields = map[string]bool{}

// o365FieldGroups are those fields by the workload whose records carry
// them ("" for the common schema, DLPRuleMatch for data loss prevention
// matches), which a test record gets only when it is of that workload.
var o365FieldGroups = map[string][]string{
	"": {"Id", "RecordType", "CreationTime", "Operation", "OrganizationId", "UserType", "UserKey", "Workload",
		"ResultStatus", "ObjectId", "UserId", "ClientIP"},
	// Entra ID, and its sign-ins.
	"AzureActiveDirectory": {"AzureActiveDirectoryEventType", "ActorContextId", "ActorIpAddress", "InterSystemsId",
		"IntraSystemId", "TargetContextId", "ApplicationId", "Client", "ErrorNumber", "LogonError", "Actor{}.ID",
		"Actor{}.Type", "Target{}.ID", "Target{}.Type", "ModifiedProperties{}.Name", "ModifiedProperties{}.NewValue",
		"ModifiedProperties{}.OldValue", "ExtendedProperties{}.Name", "ExtendedProperties{}.Value"},
	// Exchange: admin cmdlets and mailbox access.
	"Exchange": {"OrganizationName", "OriginatingServer", "ExternalAccess", "Parameters{}.Name", "Parameters{}.Value",
		"AppId", "ClientAppId", "ClientInfoString", "ClientIPAddress", "ClientProcessName", "ClientVersion", "LogonType",
		"MailboxOwnerUPN", "OperationCount", "OperationProperties{}.Name", "OperationProperties{}.Value", "Folder.Path",
		"Item.ParentFolder.Path", "Item.ParentFolder.MemberUpn", "Item.ParentFolder.MemberRights", "Item.Subject",
		"InternetMessageId"},
	// SharePoint and OneDrive.
	"SharePoint": {"SiteUrl", "SourceFileName", "SourceFileExtension", "SourceRelativeUrl", "EventSource", "ItemType",
		"EventData", "VirusInfo", "VirusVendor", "CorrelationId"},
	// The Security & Compliance Center's alerts.
	"SecurityComplianceCenter": {"AlertId", "AlertType", "AlertEntityId", "EntityType", "Name", "PolicyId", "Severity",
		"Category", "Source", "Data"},
	// Defender for Office 365's email records.
	"ThreatIntelligence": {"DeliveryAction", "Directionality", "DetectionMethod", "DetectionType",
		"LatestDeliveryLocation", "OriginalDeliveryLocation", "NetworkMessageId", "P1Sender", "P2Sender", "SenderIp",
		"Recipients{}", "Subject", "Verdict"},
}

func init() {
	for _, fs := range o365FieldGroups {
		for _, f := range fs {
			o365Fields[f] = true
		}
	}
}

// o365Carries reports whether a record of a workload has a field of
// Microsoft's schema.
func o365Carries(workload, field string) bool {
	if workload == "OneDrive" {
		workload = "SharePoint"
	}
	return slices.Contains(o365FieldGroups[""], field) || slices.Contains(o365FieldGroups[workload], field)
}

// o365Field is the stored field of a Microsoft 365 search's field.
func o365Field(name string) (string, bool) {
	if f, ok := o365CIM[name]; ok {
		return f, true
	}
	return name, o365Fields[name] && ingest.O365Field(name)
}

// o365Unrename is the field a name a later stage reads had before the
// search's renames, which name fields one by one (rename UserId as user).
func o365Unrename(name string, renames []rename) string {
	for i := len(renames) - 1; i >= 0; i-- {
		if name == renames[i].to {
			name = renames[i].from
		}
	}
	return name
}

// o365Record turns a field-level event into the Microsoft 365 audit
// record that carries it: CIM fields back to the record fields they come
// from. A sign-in (action success or failure) is UserLoggedIn or
// UserLoginFailed, and a change's operation starts with a verb that
// says what it did.
func o365Record(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		// A record's own field: one a search may name, or a list a later
		// stage reads (ModifiedProperties, written as JSON).
		if _, cim := o365CIM[k]; !cim && (o365Fields[k] || ingest.O365Field(k) && strings.HasPrefix(v, "[{")) {
			data[k] = v
		}
	}
	set("Operation", ev["signature"])
	set("Operation", ev["command"])
	set("Workload", ev["app"])
	set("Workload", ev["dest"])
	set("UserId", ev["user"])
	set("UserId", ev["user_id"])
	set("ClientIP", ev["src"])
	set("ClientIP", ev["src_ip"])
	set("ObjectId", ev["object"])
	set("OrganizationId", ev["vendor_account"])
	set("UserAgent", ev["user_agent"])
	set("UserAgent", ev["UserAgent"])
	// The test record's builder makes OS a device property.
	set("OS", ev["OS"])
	set("LogonError", ev["reason"])
	set("RecordType", ingest.O365RecordType(ev["record_type"]))
	switch strings.ToLower(ev["status"]) {
	case "success":
		set("ResultStatus", "Succeeded")
	case "failure":
		set("ResultStatus", "Failed")
	}
	switch a := strings.ToLower(ev["action"]); a {
	case "success":
		set("Operation", "UserLoggedIn")
	case "failure":
		set("Operation", "UserLoginFailed")
	case "created", "modified", "deleted":
		if op := data["Operation"]; ingest.O365ChangeAction(op) != a {
			data["Operation"] = map[string]string{"created": "Add", "modified": "Update", "deleted": "Remove"}[a] + " " + op
		}
	}
	if op := data["Operation"]; op == "UserLoggedIn" || op == "UserLoginFailed" {
		// A sign-in to Entra ID, to Office 365 from a browser.
		set("RecordType", ingest.O365RecordType("AzureActiveDirectoryStsLogon"))
		set("Workload", "AzureActiveDirectory")
		set("ApplicationId", "4765445b-32c6-49b0-83e6-1d93765276ca")
		set("UserAgent", "Mozilla/5.0")
	}
	if data["Category"] != "" || data["AlertId"] != "" {
		// An alert of the Security & Compliance Center.
		set("Operation", "AlertTriggered")
		set("Workload", "SecurityComplianceCenter")
		set("RecordType", ingest.O365RecordType("SecurityComplianceAlerts"))
	}
	// Each workload's records are of its own type.
	switch data["Workload"] {
	case "Exchange":
		if data["Operation"] == "MailItemsAccessed" {
			set("RecordType", ingest.O365RecordType("ExchangeItemAggregated"))
		}
		set("RecordType", ingest.O365RecordType("ExchangeAdmin"))
	case "SharePoint", "OneDrive":
		set("RecordType", ingest.O365RecordType("SharePointFileOperation"))
	case "ThreatIntelligence":
		set("RecordType", ingest.O365RecordType("ThreatIntelligence"))
	}
	// What every record has, so a count can group its test records.
	set("Workload", "AzureActiveDirectory")
	set("Operation", "Update user.")
	set("UserId", "admin@example.com")
	set("ClientIP", "203.0.113.7")
	return sigmacheck.Case{Channel: sigmacheck.O365Channel, EventID: data["Workload"], Data: data}
}
