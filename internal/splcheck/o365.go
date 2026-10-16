package splcheck

import (
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
// Signalith keeps as user_agent.
var o365CIM = map[string]string{
	"action": "action", "status": "status", "user": "user", "user_id": "user", "src": "src", "src_ip": "src",
	"dest": "dest", "signature": "signature", "command": "command", "app": "app", "user_agent": "user_agent",
	"UserAgent": "user_agent", "reason": "reason", "vendor_account": "vendor_account", "vendor_product": "vendor_product",
	"object": "object", "object_category": "object_category", "record_type": "record_type",
	"authentication_method": "authentication_method", "change_type": "change_type", "sourcetype": "sourcetype",
}

// o365Fields are the fields of Microsoft's audit record schema that a
// search may name, as Signalith keeps them: the common schema, and the
// fields of Entra ID, Exchange, SharePoint, the Security & Compliance
// Center's alerts and searches, and Defender for Office 365's email
// records. A list's values are by Splunk's names for them
// (ModifiedProperties{}.NewValue). An Exchange cmdlet's parameters are
// only in Parameters{}.Name and Parameters{}.Value, not by their own
// names (Role, AccessRights), as Splunk's add-on extracts them.
var o365Fields = map[string]bool{
	// The common schema.
	"Id": true, "RecordType": true, "CreationTime": true, "Operation": true, "OrganizationId": true, "UserType": true,
	"UserKey": true, "Workload": true, "ResultStatus": true, "ObjectId": true, "UserId": true, "ClientIP": true,
	// Entra ID, and its sign-ins.
	"AzureActiveDirectoryEventType": true, "ActorContextId": true, "ActorIpAddress": true, "InterSystemsId": true,
	"IntraSystemId": true, "TargetContextId": true, "ApplicationId": true, "Client": true, "ErrorNumber": true,
	"LogonError": true, "Actor{}.ID": true, "Actor{}.Type": true, "Target{}.ID": true, "Target{}.Type": true,
	"ModifiedProperties{}.Name": true, "ModifiedProperties{}.NewValue": true, "ModifiedProperties{}.OldValue": true,
	"ExtendedProperties{}.Name": true, "ExtendedProperties{}.Value": true,
	// Exchange: admin cmdlets and mailbox access.
	"OrganizationName": true, "OriginatingServer": true, "ExternalAccess": true, "Parameters{}.Name": true,
	"Parameters{}.Value": true, "AppId": true, "ClientAppId": true, "ClientInfoString": true, "ClientIPAddress": true,
	"ClientProcessName": true, "ClientVersion": true, "LogonType": true, "MailboxOwnerUPN": true, "OperationCount": true,
	"OperationProperties{}.Name": true, "OperationProperties{}.Value": true, "Folder.Path": true,
	"Item.ParentFolder.Path": true, "Item.ParentFolder.MemberUpn": true, "Item.ParentFolder.MemberRights": true,
	"Item.Subject": true, "InternetMessageId": true,
	// SharePoint and OneDrive.
	"SiteUrl": true, "SourceFileName": true, "SourceFileExtension": true, "SourceRelativeUrl": true, "EventSource": true,
	"ItemType": true, "EventData": true, "VirusInfo": true, "VirusVendor": true, "CorrelationId": true,
	// The Security & Compliance Center's alerts.
	"AlertId": true, "AlertType": true, "AlertEntityId": true, "EntityType": true, "Name": true, "PolicyId": true,
	"Severity": true, "Category": true, "Source": true, "Data": true,
	// Defender for Office 365's email records.
	"DeliveryAction": true, "Directionality": true, "DetectionMethod": true, "DetectionType": true,
	"LatestDeliveryLocation": true, "OriginalDeliveryLocation": true, "NetworkMessageId": true, "P1Sender": true,
	"P2Sender": true, "SenderIp": true, "Recipients{}": true, "Subject": true, "Verdict": true,
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
		if _, cim := o365CIM[k]; !cim && o365Fields[k] {
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
