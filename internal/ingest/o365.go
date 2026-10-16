package ingest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Microsoft 365 keeps an audit log of what users and admins do in Entra
// ID, Exchange Online, SharePoint, OneDrive, Teams and the security and
// compliance center, which the Office 365 Management Activity API serves
// (internal/m365 reads it). Each record becomes an event with the
// record's own field names (Operation, Workload, UserId,
// ModifiedProperties{}.Name), as Splunk's Microsoft 365 add-on keeps
// them (sourcetype o365:management:activity), plus the CIM fields that
// add-on gives it: a sign-in is an Authentication event, an alert an
// Alerts event, an admin change a Change event, and the rest (files and
// mail read, searches) Other events.
//
// Every value is kept as text: Microsoft's records give some fields a
// number in one workload and text in another (ListBaseType), and a list
// in one and text in another (Parameters), which one index's mapping
// could not hold. A list is kept as its JSON text, and its values also by
// Splunk's names for them (Parameters{}.Name), as Entra ID's are.

// O365Tag is the tag of Microsoft 365 audit records.
const O365Tag = "o365"

// O365Sourcetype is Splunk's sourcetype for these records.
const O365Sourcetype = "o365:management:activity"

// O365Channel names Microsoft 365 records in test events
// (sigmacheck.Case); a case's event ID is the record's workload.
const O365Channel = "o365"

// o365MaxLeaves caps the fields one record's nested objects and lists
// become; the rest stay in the message.
const o365MaxLeaves = 150

// o365Mapped are the fields the index template maps as keywords: what a
// Microsoft 365 search reads first. The rest are mapped as they come.
var o365Mapped = []string{"Operation", "Workload", "UserId", "ClientIP", "ResultStatus", "OrganizationId", "ObjectId", "record_type"}

// o365RecordTypes are the names of the record types (RecordType) that
// Microsoft documents, as Splunk's add-on gives them in record_type.
var o365RecordTypes = map[string]string{
	"1": "ExchangeAdmin", "2": "ExchangeItem", "3": "ExchangeItemGroup", "4": "SharePoint",
	"6": "SharePointFileOperation", "7": "OneDrive", "8": "AzureActiveDirectory", "9": "AzureActiveDirectoryAccountLogon",
	"10": "DataCenterSecurityCmdlet", "11": "ComplianceDLPSharePoint", "13": "ComplianceDLPExchange",
	"14": "SharePointSharingOperation", "15": "AzureActiveDirectoryStsLogon", "16": "SkypeForBusinessPSTNUsage",
	"17": "SkypeForBusinessUsersBlocked", "18": "SecurityComplianceCenterEOPCmdlet", "19": "ExchangeAggregatedOperation",
	"20": "PowerBIAudit", "21": "CRM", "22": "Yammer", "23": "SkypeForBusinessCmdlets", "24": "Discovery",
	"25": "MicrosoftTeams", "28": "ThreatIntelligence", "29": "MailSubmission", "30": "MicrosoftFlow",
	"31": "AeD", "32": "MicrosoftStream", "33": "ComplianceDLPSharePointClassification", "34": "ThreatFinder",
	"35": "Project", "36": "SharePointListOperation", "37": "SharePointCommentOperation", "38": "DataGovernance",
	"39": "Kaizala", "40": "SecurityComplianceAlerts", "41": "ThreatIntelligenceUrl",
	"42": "SecurityComplianceInsights", "43": "MIPLabel", "44": "WorkplaceAnalytics", "45": "PowerAppsApp",
	"46": "PowerAppsPlan", "47": "ThreatIntelligenceAtpContent", "48": "LabelContentExplorer", "49": "TeamsHealthcare",
	"50": "ExchangeItemAggregated", "51": "HygieneEvent", "52": "DataInsightsRestApiAudit", "53": "InformationBarrierPolicyApplication",
	"54": "SharePointListItemOperation", "55": "SharePointContentTypeOperation", "56": "SharePointFieldOperation",
	"57": "MicrosoftTeamsAdmin", "58": "HRSignal", "59": "MicrosoftTeamsDevice", "60": "MicrosoftTeamsAnalytics",
	"61": "InformationWorkerProtection", "62": "Campaign", "63": "DLPEndpoint", "64": "AirInvestigation",
	"65": "Quarantine", "66": "MicrosoftForms", "68": "ComplianceManager", "78": "MyAnalyticsSettings",
	"82": "MipAutoLabelSharePointItem", "85": "PrivacyInsights", "87": "SecurityComplianceRBAC",
	"90": "PublicFolder", "91": "PrivacyDataMinimization", "102": "SensitivityLabelAction", "113": "MipAutoLabelExchangeItem",
	"148": "DataCenterSecurityCmdlet", "174": "PowerPlatformAdminEnvironment",
}

// O365RecordType is the number of the record type a name names
// (AzureActiveDirectoryStsLogon is 15), for test events, or "" when
// Microsoft documents none by that name.
func O365RecordType(name string) string {
	for _, n := range slices.Sorted(maps.Keys(o365RecordTypes)) {
		if o365RecordTypes[n] == name {
			return n
		}
	}
	return ""
}

// IsO365Record reports whether a decoded object is a Microsoft 365 audit
// record: it has a time, an operation, a workload, a record type and the
// tenant.
func IsO365Record(r map[string]any) bool {
	return has(r, "CreationTime") && has(r, "Operation") && has(r, "Workload") && has(r, "OrganizationId") && r["RecordType"] != nil
}

// o365Text is a scalar value as text: numbers as Microsoft wrote them,
// booleans as true or false.
func o365Text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	}
	return ""
}

// flattenO365 puts a record's values in out under dotted names
// (Item.ParentFolder.Path), every value as text. A list, and an object
// nested past the deepest field name, is kept as its JSON text; a list's
// values are also kept by Splunk's names for them.
func flattenO365(prefix string, v any, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		if strings.Count(prefix, ".")+1 >= maxFieldDepth {
			if b, err := json.Marshal(x); err == nil {
				out[prefix] = CapValue(string(b))
			}
			return
		}
		for k, e := range x {
			if k != "" && !strings.ContainsAny(k, ".{}") {
				flattenO365(prefix+"."+k, e, out)
			}
		}
	case []any:
		if b, err := json.Marshal(x); err == nil {
			out[prefix] = CapValue(string(b))
		}
		for _, e := range x {
			azureListValue(prefix+"{}", e, out)
		}
	default:
		if s := o365Text(v); s != "" {
			out[prefix] = CapValue(s)
		}
	}
}

// ParseO365 maps a Microsoft 365 audit record (decoded JSON) onto an
// event.
func ParseO365(r map[string]any) Event {
	flat := map[string]any{}
	for k, v := range r {
		if k != "" && !strings.ContainsAny(k, ".{}") {
			flattenO365(k, v, flat)
		}
	}
	f := map[string]any{"sourcetype": O365Sourcetype, "vendor_product": "Microsoft 365"}
	// Top-level fields first, then the nested ones in order, as far as
	// o365MaxLeaves.
	leaves := 0
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		if !validFieldName(k) || !o365Own(k) {
			// A record's field never takes the name of one of
			// Signalith's own.
			continue
		}
		if !strings.Contains(k, ".") && !strings.Contains(k, "{") {
			f[k] = flat[k]
		} else if leaves < o365MaxLeaves {
			f[k] = flat[k]
			leaves++
		}
	}
	raw, rawErr := json.Marshal(r)
	if rawErr == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	// The machine that sent the record, when it says (Microsoft 365
	// itself has no host).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	op := str(r, "Operation")
	workload := str(r, "Workload")
	rt := o365Text(r["RecordType"])
	set("record_type", cmp.Or(o365RecordTypes[rt], rt))
	set("signature", op)
	set("command", op)
	set("app", workload)
	set("dest", workload)
	set("vendor_account", str(r, "OrganizationId"))
	set("user", str(r, "UserId"))
	set("src", o365Address(cmp.Or(str(r, "ClientIP"), str(r, "ActorIpAddress"), str(r, "ClientIPAddress"), str(r, "SenderIp"))))
	set("object", str(r, "ObjectId"))
	set("user_agent", cmp.Or(o365Property(r, "ExtendedProperties", "UserAgent"), str(r, "UserAgent"), str(r, "ClientInfoString")))
	// The record's result: success unless it failed. A record that has
	// none (many reads do not) has no status.
	status := ""
	switch strings.ToLower(str(r, "ResultStatus")) {
	case "":
	case "failed", "failure", "false", "partiallysucceeded":
		status = "failure"
	default:
		status = "success"
	}
	if op == "UserLoginFailed" {
		status = "failure"
	}
	set("status", status)

	ev := Event{Fields: f, Model: "Other"}
	if t, ok := o365Time(str(r, "CreationTime")); ok {
		ev.Time = t
	}
	// The same record, read twice from the API, is stored once. The ID
	// covers the whole record, not just its Id, so a record sent with a
	// real record's Id before the poller reads it cannot take its place.
	if id := str(r, "Id"); id != "" && rawErr == nil {
		ev.ID = sensorDocID("o365", id+"\n"+string(raw))
	}
	switch {
	case op == "UserLoggedIn" || op == "UserLoginFailed":
		ev.Model = "Authentication"
		f["action"] = status
		set("reason", str(r, "LogonError"))
		set("authentication_method", o365Property(r, "ExtendedProperties", "RequestType"))
	case rt == "40" || op == "AlertTriggered" || op == "AlertEntityGenerated":
		ev.Model = "Alerts"
		set("type", str(r, "Name"))
		set("description", cmp.Or(str(r, "Name"), op))
		set("severity", strings.ToLower(str(r, "Severity")))
		set("id", str(r, "AlertId"))
		// Sigma names an alert by its name (eventName).
		set("signature", str(r, "Name"))
	default:
		if a := O365ChangeAction(op); a != "" {
			ev.Model = "Change"
			f["action"] = a
			set("change_type", workload)
			set("object_category", str(r, "ObjectType"))
		}
	}
	return ev
}

// O365ChangeAction is what an admin operation did, by its verb: Exchange
// cmdlets (New-InboxRule, Set-Mailbox) and Entra ID's operations ("Add
// member to role.", "Update user."). "" is not a change.
func O365ChangeAction(op string) string {
	verb, _, _ := strings.Cut(op, "-")
	if verb == op {
		verb, _, _ = strings.Cut(op, " ")
	}
	switch strings.ToLower(verb) {
	case "new", "add", "create", "enable", "install", "register":
		return "created"
	case "remove", "delete", "disable", "uninstall":
		return "deleted"
	case "set", "update", "change", "reset", "grant", "revoke", "assign", "consent":
		return "modified"
	}
	return ""
}

// o365Property is the value of the item called name in one of a record's
// lists of names and values (ExtendedProperties, Parameters).
func o365Property(r map[string]any, list, name string) string {
	l, _ := r[list].([]any)
	for _, e := range l {
		if m, ok := e.(map[string]any); ok && strings.EqualFold(str(m, "Name"), name) {
			return o365Text(m["Value"])
		}
	}
	return ""
}

// o365Address is a client address without the port Exchange adds
// (203.0.113.7:51234, [2001:db8::1]:443).
func o365Address(s string) string {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String()
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().String()
	}
	return s
}

// o365Time reads a record's CreationTime, which is UTC without a zone.
func o365Time(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// O365Records decodes the records of a content blob of the Management
// Activity API: a JSON array of records.
func O365Records(b []byte) ([]map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var list []map[string]any
	if err := d.Decode(&list); err != nil {
		return nil, err
	}
	out := list[:0]
	for _, r := range list {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// o365SigmaFields map the field names Sigma's Microsoft 365 rules use to
// the fields an event keeps: the record's own names, and for the older
// rules a generic event's (eventSource is the workload, eventName the
// operation or an alert's name, status how it went).
var o365SigmaFields = map[string]string{
	"eventSource": "Workload", "eventName": "signature", "status": "status",
	// A sign-in's request type is one of its extended properties.
	"RequestType": "ExtendedProperties{}.Value",
}

// O365SigmaField returns the field an event keeps for a field of a Sigma
// rule of Microsoft 365, or false when it keeps none.
func O365SigmaField(name string) (string, bool) {
	if f, ok := o365SigmaFields[name]; ok {
		return f, true
	}
	if O365Field(name) {
		return name, true
	}
	return "", false
}

// O365Field reports whether an event keeps a field of a Microsoft 365
// record by its own name: one in PascalCase (Operation,
// Item.ParentFolder.Path, ModifiedProperties{}.Name).
func O365Field(name string) bool {
	return name != "" && name[0] >= 'A' && name[0] <= 'Z' && validFieldName(name) && o365Own(name)
}

// o365Own reports whether a record's field may keep its name: it is not
// one of Signalith's own fields, unless the template maps it for these
// records.
func o365Own(name string) bool {
	return !KnownField(name) || slices.Contains(o365Mapped, name) || slices.Contains(cloudRuleFields, name)
}

// O365Record is a Microsoft 365 audit record of a workload with the
// fields data names, by the record's names (Operation,
// ModifiedProperties{}.Name, Item.ParentFolder.Path), for test events
// (Normalize with O365Tag).
func O365Record(t time.Time, workload string, data map[string]string) map[string]any {
	r := map[string]any{
		"CreationTime": t.UTC().Format("2006-01-02T15:04:05"), "Id": "11111111-2222-3333-4444-555555555555",
		"Workload": cmp.Or(workload, "AzureActiveDirectory"), "Operation": "Update user.",
		"OrganizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "RecordType": json.Number("8"),
		"UserId": "admin@example.com", "UserType": json.Number("0"), "ResultStatus": "Success",
	}
	put := func(path string, v any) {
		parts := strings.Split(path, ".")
		m := r
		for _, p := range parts[:len(parts)-1] {
			if name, ok := strings.CutSuffix(p, "{}"); ok {
				l, _ := m[name].([]any)
				if len(l) == 0 {
					l = []any{map[string]any{}}
					m[name] = l
				}
				next, ok := l[0].(map[string]any)
				if !ok {
					next = map[string]any{}
					l[0] = next
				}
				m = next
				continue
			}
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		last := parts[len(parts)-1]
		if name, ok := strings.CutSuffix(last, "{}"); ok {
			l, _ := m[name].([]any)
			m[name] = append(l, v)
			return
		}
		m[last] = v
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		if k == "RecordType" {
			r[k] = json.Number(data[k])
			continue
		}
		put(k, data[k])
	}
	return r
}

// O365SigmaRecord is the Microsoft 365 audit record a Sigma rule's
// fields describe, for test events: the older rules' eventSource,
// eventName and status become the workload, the operation (an alert's
// name, for the Security & Compliance Center's alerts) and the result.
func O365SigmaRecord(host string, t time.Time, data map[string]string) map[string]any {
	d := map[string]string{}
	for k, v := range data {
		switch k {
		case "eventSource", "eventName", "status":
		case "RequestType":
			d["ExtendedProperties{}.Name"], d["ExtendedProperties{}.Value"] = "RequestType", v
		default:
			d[k] = v
		}
	}
	workload := cmp.Or(data["eventSource"], data["Workload"])
	if name := data["eventName"]; name != "" {
		if strings.EqualFold(workload, "SecurityComplianceCenter") {
			d["Operation"], d["Name"], d["RecordType"] = "AlertTriggered", name, "40"
		} else {
			d["Operation"] = name
		}
	}
	if s, ok := data["status"]; ok {
		d["ResultStatus"] = "Failed"
		if strings.EqualFold(s, "success") {
			d["ResultStatus"] = "Succeeded"
		}
	}
	r := O365Record(t, workload, d)
	r["hostname"] = host
	// Each test record its own Id, as the same Id is stored once.
	h := sha256.New()
	fmt.Fprintln(h, host, t.UnixNano())
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintln(h, k, data[k])
	}
	r["Id"] = hex.EncodeToString(h.Sum(nil))[:32]
	if _, ok := d["ResultStatus"]; !ok {
		// A record without a result, so a rule's status is not met.
		delete(r, "ResultStatus")
	}
	return r
}
