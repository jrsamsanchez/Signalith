package ingest

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Microsoft Entra ID and Azure send their logs through diagnostic
// settings to an Azure Event Hub, as JSON messages of records
// ({"records": [...]}): Entra ID's sign-ins, audit log and risk
// detections, and each Azure subscription's activity log (what was
// created, changed or deleted, and by whom). Each record becomes an event
// with the record's own field names (operationName, resultType,
// properties.userPrincipalName), as Splunk's add-on for Microsoft cloud
// services keeps them, so Splunk's rules search them as written and
// Sigma's through the names in azureSigmaFields, plus the data model
// fields of what it records: a sign-in is an Authentication event, a
// change Change, and a risk detection an Alert.
//
// Records come from the OpenTelemetry Collector's azure_event_hub
// receiver with format raw, which passes each message on whole (see
// azureFromOTLP), or one by one as JSON records under the azure tag.

// AzureTag is the tag of Azure records sent as JSON.
const AzureTag = "azure"

// The sourcetypes of Azure events, Splunk's: Entra ID's logs, Azure's
// activity log, and the logs of other Azure resources.
const (
	AzureADSourcetype       = "azure:monitor:aad"
	AzureActivitySourcetype = "azure:monitor:activity"
	AzureResourceSourcetype = "azure:monitor:resource"
)

// AzureChannel names Azure records in test events (sigmacheck.Case), as a
// Windows channel names Windows events; a case's event ID is the Sigma
// service its record is from (signinlogs).
const AzureChannel = "azure"

// azureMaxLeaves caps the fields one record's nested objects (properties,
// identity) become; the rest stay in the message.
const azureMaxLeaves = 120

// azureTop are a record's top-level fields, kept by name when set.
var azureTop = []string{
	"time", "resourceId", "operationName", "operationVersion", "category", "tenantId", "resultType",
	"resultSignature", "resultDescription", "durationMs", "callerIpAddress", "correlationId", "level",
	"location", "identity",
}

// azureMapped are the fields the index template maps (see knownFields):
// what an Azure search reads first. The rest are mapped as they come.
var azureMapped = []string{
	"category", "operationName", "resultType", "resultDescription", "callerIpAddress", "tenantId", "resourceId",
	"signin_status",
}

// azureADCategories are the categories of Entra ID's diagnostic settings.
var azureADCategories = []string{
	"SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs",
	"ADFSSignInLogs", "AuditLogs", "ProvisioningLogs", "RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals",
	"ServicePrincipalRiskEvents", "MicrosoftGraphActivityLogs", "NetworkAccessTrafficLogs", "EnrichedOffice365AuditLogs",
	"MicrosoftServicePrincipalSignInLogs", "B2CRequestLogs",
}

// azureActivityCategories are the categories of an Azure subscription's
// activity log.
var azureActivityCategories = []string{
	"Administrative", "Security", "ServiceHealth", "Alert", "Recommendation", "Policy", "Autoscale", "ResourceHealth",
}

// IsAzureRecord reports whether a decoded object is an Azure resource log
// or activity log record: it has a time, a category and an operation, and
// names its resource or tenant.
func IsAzureRecord(r map[string]any) bool {
	return has(r, "time") && has(r, "category") && has(r, "operationName") && (has(r, "resourceId") || has(r, "tenantId"))
}

// ParseAzure maps an Azure record (decoded JSON) onto an event.
func ParseAzure(r map[string]any) Event {
	category := str(r, "category")
	f := map[string]any{"sourcetype": AzureResourceSourcetype, "vendor_product": "Microsoft Azure"}
	switch {
	case slices.Contains(azureADCategories, category):
		f["sourcetype"], f["vendor_product"] = AzureADSourcetype, "Microsoft Entra ID"
	case slices.Contains(azureActivityCategories, category):
		f["sourcetype"], f["vendor_product"] = AzureActivitySourcetype, "Azure Activity Log"
	}
	flat := map[string]any{}
	for _, k := range azureTop {
		if v, ok := r[k]; ok {
			flattenAzure(k, v, flat)
		}
	}
	// Entra ID's identity is a name, the activity log's an object
	// (identity.claims.appid): the name goes under the object's name, so
	// both fit one index's mapping.
	if v, ok := flat["identity"]; ok {
		delete(flat, "identity")
		flat["identity.name"] = v
	}
	if v, ok := r["properties"]; ok {
		flattenAzure("properties", v, flat)
	}
	// Top-level fields first, then the nested ones in order, as far as
	// azureMaxLeaves.
	leaves := 0
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		if !strings.Contains(k, ".") {
			f[k] = flat[k]
			continue
		}
		if leaves < azureMaxLeaves && validFieldName(k) {
			f[k] = flat[k]
			leaves++
		}
	}
	if raw, err := json.Marshal(r); err == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	// The machine that sent the record, when it says (Azure itself has
	// no host).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	op := str(r, "operationName")
	set("signature", op)
	set("command", op)
	set("vendor_account", str(r, "tenantId"))
	set("vendor_region", str(r, "location"))
	props, _ := r["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}

	ev := Event{Fields: f, Model: "Other"}
	if t, err := time.Parse(time.RFC3339Nano, str(r, "time")); err == nil {
		ev.Time = t.UTC()
	}
	switch {
	case strings.HasSuffix(category, "SignInLogs"):
		ev.Model = "Authentication"
		azureSignIn(r, props, f, set)
	case category == "AuditLogs":
		ev.Model = "Change"
		azureAudit(props, f, set)
	case strings.HasSuffix(category, "RiskEvents"):
		ev.Model = "Alerts"
		set("app", "Microsoft Entra ID Protection")
		set("type", str(props, "riskEventType"))
		set("description", cmp.Or(str(props, "riskEventType"), op))
		set("severity", strings.ToLower(str(props, "riskLevel")))
		set("id", str(props, "id"))
		set("user", cmp.Or(str(props, "userPrincipalName"), str(props, "servicePrincipalDisplayName")))
		set("src", str(props, "ipAddress"))
	case category == "Administrative":
		// What was created, changed or deleted in a subscription. The
		// activity log's other categories (service health, alerts,
		// autoscale, policy) are Other.
		ev.Model = "Change"
		azureActivity(r, f, set)
	}
	return ev
}

// azureSignIn fills an Entra ID sign-in's Authentication fields, and
// signin_status, which is Success or Failure with why, as Microsoft
// Sentinel shows a sign-in's status.
func azureSignIn(r, props map[string]any, f map[string]any, set func(k, v string)) {
	status, _ := props["status"].(map[string]any)
	code := cmp.Or(str(status, "errorCode"), str(r, "resultType"))
	why := cmp.Or(str(status, "additionalDetails"), str(status, "failureReason"), str(r, "resultDescription"))
	if code == "" || code == "0" {
		f["action"] = "success"
		f["signin_status"] = "Success"
	} else {
		f["action"] = "failure"
		f["signin_status"] = CapValue(strings.TrimSuffix("Failure: "+why, ": "))
		set("reason", cmp.Or(str(status, "failureReason"), str(r, "resultDescription"), why))
	}
	set("user", cmp.Or(str(props, "userPrincipalName"), str(props, "servicePrincipalName"), str(props, "servicePrincipalId"), str(r, "identity")))
	set("app", str(props, "appDisplayName"))
	set("dest", str(props, "resourceDisplayName"))
	set("src", cmp.Or(str(props, "ipAddress"), str(r, "callerIpAddress")))
	set("user_agent", str(props, "userAgent"))
	if details, ok := props["authenticationDetails"].([]any); ok && len(details) > 0 {
		if d, ok := details[0].(map[string]any); ok {
			set("authentication_method", str(d, "authenticationMethod"))
		}
	}
}

// azureAudit fills an Entra ID audit record's Change fields: who did it,
// and to what.
func azureAudit(props map[string]any, f map[string]any, set func(k, v string)) {
	set("status", strings.ToLower(str(props, "result")))
	set("change_type", "Entra ID "+str(props, "category"))
	set("object_category", str(props, "category"))
	switch strings.ToLower(str(props, "operationType")) {
	case "add", "assign":
		f["action"] = "created"
	case "delete", "unassign":
		f["action"] = "deleted"
	default:
		f["action"] = "modified"
	}
	if by, ok := props["initiatedBy"].(map[string]any); ok {
		u, _ := by["user"].(map[string]any)
		app, _ := by["app"].(map[string]any)
		who := cmp.Or(str(u, "userPrincipalName"), str(u, "displayName"), str(app, "displayName"), str(app, "servicePrincipalName"))
		set("user", who)
		// Also where Splunk's add-on keeps who made the change.
		set("src_user", who)
		set("src", str(u, "ipAddress"))
		if app != nil && u == nil {
			set("src_user_type", "servicePrincipal")
		} else if u != nil {
			set("src_user_type", "user")
		}
	}
	if targets, ok := props["targetResources"].([]any); ok && len(targets) > 0 {
		if t, ok := targets[0].(map[string]any); ok {
			set("object", cmp.Or(str(t, "userPrincipalName"), str(t, "displayName"), str(t, "id")))
			set("object_category", strings.ToLower(cmp.Or(str(t, "type"), str(props, "category"))))
		}
	}
	set("dest", "entra:"+wstr(f["vendor_account"]))
	if f["dest"] == "entra:" {
		delete(f, "dest")
	}
}

// azureActivity fills an activity log record's Change fields: the
// Azure Resource Manager operation, the resource and who asked.
func azureActivity(r map[string]any, f map[string]any, set func(k, v string)) {
	op := strings.ToUpper(str(r, "operationName"))
	switch {
	case strings.HasSuffix(op, "/DELETE"):
		f["action"] = "deleted"
	case strings.HasSuffix(op, "/WRITE"):
		f["action"] = "modified"
	default:
		f["action"] = "modified"
	}
	if i := strings.LastIndex(op, "/"); i > 0 {
		set("object_category", strings.ToLower(op[:i]))
	}
	id := str(r, "resourceId")
	set("object", id[strings.LastIndex(id, "/")+1:])
	set("object_path", id)
	set("dest", id)
	set("change_type", "Azure Resource Manager")
	set("src", str(r, "callerIpAddress"))
	switch strings.ToLower(str(r, "resultType")) {
	case "failure", "failed":
		f["status"] = "failure"
		set("reason", str(r, "resultSignature"))
	case "success", "succeeded":
		f["status"] = "success"
	}
	// The subscription, from the resource's ID.
	parts := strings.Split(strings.Trim(id, "/"), "/")
	if len(parts) >= 2 && strings.EqualFold(parts[0], "subscriptions") {
		set("vendor_account", strings.ToLower(parts[1]))
	}
	// Who asked: their sign-in name, or the app's ID.
	if ident, ok := r["identity"].(map[string]any); ok {
		claims, _ := ident["claims"].(map[string]any)
		set("user", cmp.Or(
			str(claims, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"),
			str(claims, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),
			str(claims, "name"), str(claims, "appid")))
	}
}

// flattenAzure puts a record's values in out under dotted names
// (properties.deviceDetail.trustType): strings, booleans and numbers
// (whole numbers as integers) as themselves, and lists, and objects nested
// past the deepest field name, as JSON text. Empty strings are left out,
// as Signalith keeps no empty values; an empty list is kept, as []. A
// list's values are also kept by Splunk's names (azureListValue).
func flattenAzure(prefix string, v any, out map[string]any) {
	depth := strings.Count(prefix, ".") + 1
	switch x := v.(type) {
	case map[string]any:
		if depth >= maxFieldDepth {
			if b, err := json.Marshal(x); err == nil {
				out[prefix] = CapValue(string(b))
			}
			return
		}
		for k, e := range x {
			if k == "" || strings.Contains(k, ".") {
				continue
			}
			flattenAzure(prefix+"."+k, e, out)
		}
	case []any:
		if b, err := json.Marshal(x); err == nil {
			out[prefix] = CapValue(string(b))
		}
		for _, e := range x {
			azureListValue(prefix+"{}", e, out)
		}
	case string:
		if x != "" {
			out[prefix] = CapValue(x)
		}
	case bool:
		out[prefix] = x
	case json.Number:
		if n, err := x.Int64(); err == nil {
			out[prefix] = n
		} else if d, err := x.Float64(); err == nil {
			out[prefix] = d
		}
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			out[prefix] = int64(x)
		} else {
			out[prefix] = x
		}
	case int64:
		out[prefix] = x
	case int:
		out[prefix] = int64(x)
	}
}

// azureMaxListValues caps the values one list field keeps.
const azureMaxListValues = 64

// azureListValue adds a value in a list to the list field Splunk's add-on
// names it by: each changed property's new value in a record's
// targetResources is one of properties.targetResources{}.modifiedProperties{}.newValue.
// A search for one value then matches the record, as in Splunk. Every
// value is kept as text, so each list field has one type.
func azureListValue(name string, v any, out map[string]any) {
	if strings.Count(name, ".") >= maxFieldDepth {
		return
	}
	var s string
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if k != "" && !strings.ContainsAny(k, ".{}") {
				azureListValue(name+"."+k, e, out)
			}
		}
		return
	case []any:
		for _, e := range x {
			azureListValue(name+"{}", e, out)
		}
		return
	case string:
		s = x
	case bool:
		s = strconv.FormatBool(x)
	case json.Number:
		s = x.String()
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	case int64:
		s = strconv.FormatInt(x, 10)
	case int:
		s = strconv.Itoa(x)
	}
	if s == "" {
		return
	}
	if l, _ := out[name].([]any); len(l) < azureMaxListValues {
		out[name] = append(l, CapValue(s))
	}
}

// AzureRecords decodes the records of an Event Hub message from Azure
// ({"records": [...]}), or returns nil when the text is not one.
func AzureRecords(b []byte) []map[string]any {
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b[:min(len(b), 64)], []byte(`"records"`)) {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var msg struct {
		Records []map[string]any `json:"records"`
	}
	if err := d.Decode(&msg); err != nil {
		return nil
	}
	var out []map[string]any
	for _, r := range msg.Records {
		if r != nil && IsAzureRecord(r) {
			out = append(out, r)
		}
	}
	return out
}

// azureFromOTLP returns the Azure records of an OTLP log record whose body
// is an Event Hub message: bytes (the azure_event_hub receiver's format
// raw, which reach here as base64 text), text, or a map with records.
func azureFromOTLP(body any) []map[string]any {
	switch b := body.(type) {
	case string:
		if strings.HasPrefix(b, "ey") || strings.HasPrefix(b, "IC") || strings.HasPrefix(b, "Cn") || strings.HasPrefix(b, "DQ") {
			// Base64 of {", { ", a space or a line break: decode the start
			// first, so other text costs little.
			head, err := base64.StdEncoding.DecodeString(b[:min(len(b), 88)&^3])
			if err != nil || !bytes.Contains(head, []byte(`"records"`)) {
				return nil
			}
			raw, err := base64.StdEncoding.DecodeString(b)
			if err != nil {
				return nil
			}
			return AzureRecords(raw)
		}
		return AzureRecords([]byte(b))
	case map[string]any:
		list, ok := b["records"].([]any)
		if !ok {
			return nil
		}
		var out []map[string]any
		for _, e := range list {
			if r, ok := e.(map[string]any); ok && IsAzureRecord(r) {
				out = append(out, r)
			}
		}
		return out
	}
	return nil
}

// azureSigmaFields map the field names Sigma's Azure rules use, which are
// Microsoft Sentinel's (Log Analytics) names, to the fields an Azure
// record's event keeps, by the rule's service (signinlogs, auditlogs,
// activitylogs, riskdetection, pim).
var azureSigmaFields = map[string]map[string]string{
	"signinlogs": {
		"ResultType": "resultType", "ResultDescription": "resultDescription", "Resultdescription": "resultDescription",
		"Status": "signin_status", "OperationName": "operationName",
		"AuthenticationRequirement": "properties.authenticationRequirement",
		"conditionalAccessStatus":   "properties.conditionalAccessStatus",
		"ConditionalAccessStatus":   "properties.conditionalAccessStatus",
		"RiskState":                 "properties.riskState", "RiskLevelDuringSignIn": "properties.riskLevelDuringSignIn",
		"ResourceDisplayName": "properties.resourceDisplayName", "AppDisplayName": "properties.appDisplayName",
		"NetworkLocationDetails":   "properties.networkLocationDetails",
		"DeviceDetail.isCompliant": "properties.deviceDetail.isCompliant", "DeviceDetail.trusttype": "properties.deviceDetail.trustType",
		"DeviceDetail.trustType": "properties.deviceDetail.trustType", "DeviceDetail.deviceId": "properties.deviceDetail.deviceId",
		"DeviceDetail.operatingSystem": "properties.deviceDetail.operatingSystem",
		"userAgent":                    "properties.userAgent", "UserAgent": "properties.userAgent",
		"UserPrincipalName": "properties.userPrincipalName", "IPAddress": "properties.ipAddress",
		"ClientAppUsed": "properties.clientAppUsed", "AuthenticationProtocol": "properties.authenticationProtocol",
	},
	"auditlogs": {
		"Category": "properties.category", "OperationName": "operationName", "operationName": "operationName",
		"ActivityDisplayName": "properties.activityDisplayName", "LoggedByService": "properties.loggedByService",
		"Status": "properties.result", "Result": "properties.result", "ResultReason": "properties.resultReason",
		// Older audit log exports called the operation the message.
		"properties.message": "operationName",
		// The changed resources and their changed properties, as JSON text,
		// which rules search for words inside.
		"TargetResources": "properties.targetResources", "TargetResources.modifiedProperties": "properties.targetResources",
		"TargetResources.ModifiedProperties": "properties.targetResources", "TargetResources.modifiedProperties.newValue": "properties.targetResources",
		"TargetResources.ModifiedProperties.NewValue": "properties.targetResources",
		"properties.targetResources":                  "properties.targetResources",
	},
	"activitylogs": {
		"OperationNameValue": "operationName", "CategoryValue": "category", "ResourceId": "resourceId",
	},
	"riskdetection": {"riskEventType": "properties.riskEventType"},
	"pim":           {"riskEventType": "properties.riskEventType"},
}

// azureServiceCategory is the category of a Sigma service's test records.
var azureServiceCategory = map[string]string{
	"signinlogs": "SignInLogs", "auditlogs": "AuditLogs", "activitylogs": "Administrative",
	"riskdetection": "UserRiskEvents", "pim": "UserRiskEvents",
}

// AzureServices are the Sigma services of Azure (product: azure) whose
// rules Signalith converts.
var AzureServices = slices.Sorted(maps.Keys(azureServiceCategory))

// AzureSigmaField returns the field an Azure event keeps for a field of a
// Sigma rule of service (signinlogs), or false when it keeps none.
func AzureSigmaField(service, name string) (string, bool) {
	if f, ok := azureSigmaFields[service][name]; ok {
		return f, true
	}
	if slices.Contains(azureTop, name) && name != "identity" {
		return name, true
	}
	if strings.HasPrefix(name, "properties.") && name != "properties.message" && validFieldName(name) &&
		strings.Count(name, ".") < maxFieldDepth {
		return name, true
	}
	if service == "activitylogs" && name == "properties.message" {
		return name, true
	}
	return "", false
}

// AzureField reports whether an Azure record's event keeps a field by the
// name Splunk's add-on gives it: a top-level field (operationName), one
// under properties or identity (properties.status.errorCode), or a
// list's values (properties.targetResources{}.type).
func AzureField(name string) bool {
	if slices.Contains(azureTop, name) {
		return name != "identity"
	}
	return (strings.HasPrefix(name, "properties.") || strings.HasPrefix(name, "identity.")) && validFieldName(name)
}

// AzureRecord is an Azure record of a Sigma service (signinlogs) with the
// fields a Sigma rule names (ResultType, properties.message), for test
// events (Normalize with AzureTag), as host sent it.
func AzureRecord(host string, t time.Time, service string, data map[string]string) map[string]any {
	r := map[string]any{
		"time": t.UTC().Format(time.RFC3339), "category": azureServiceCategory[service], "hostname": host,
		"tenantId": "11111111-2222-3333-4444-555555555555", "operationName": "Sign-in activity",
		"properties": map[string]any{},
	}
	switch service {
	case "auditlogs":
		r["operationName"] = "Update user"
	case "activitylogs":
		r["operationName"] = "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE"
		r["resourceId"] = "/SUBSCRIPTIONS/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.RESOURCES/DEPLOYMENTS/D1"
		r["resultType"] = "Success"
	case "signinlogs":
		// A failed sign-in, unless the rule says how it went.
		if _, ok := data["Status"]; !ok && data["ResultType"] == "" {
			r["resultType"] = "50126"
			r["properties"] = map[string]any{"status": map[string]any{"errorCode": json.Number("50126")}}
		}
	case "riskdetection", "pim":
		r["operationName"] = "User Risk Detection"
	}
	put := func(path string, v any) {
		parts := strings.Split(path, ".")
		m := r
		for _, p := range parts[:len(parts)-1] {
			if name, ok := strings.CutSuffix(p, "{}"); ok {
				// A list of objects (targetResources{}.type): its first.
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
		v := data[k]
		f, ok := AzureSigmaField(service, k)
		if !ok {
			continue
		}
		switch f {
		case "signin_status":
			// Success, or a failure with why.
			if strings.EqualFold(v, "Success") {
				put("properties.status.errorCode", json.Number("0"))
			} else {
				put("properties.status.errorCode", json.Number("500121"))
				put("properties.status.additionalDetails", v)
			}
			continue
		case "resultType":
			if _, err := strconv.ParseInt(v, 10, 64); err == nil && service == "signinlogs" {
				put("properties.status.errorCode", json.Number(v))
			}
		case "properties.status.errorCode":
			if _, err := strconv.ParseInt(v, 10, 64); err == nil {
				put(f, json.Number(v))
				continue
			}
		case "properties.networkLocationDetails", "properties.targetResources":
			// A list, written as JSON: kept as its text.
			var list []any
			if json.Unmarshal([]byte(v), &list) == nil {
				put(f, list)
				continue
			}
		}
		put(f, v)
	}
	return r
}
