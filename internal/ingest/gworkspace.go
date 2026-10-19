// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Google Workspace records what its admins and users do in audit logs,
// which an organization can share with Google Cloud (in the Admin console,
// Account settings, then Legal and compliance, then Sharing options). Cloud
// Logging then keeps each activity as a LogEntry in the organization's
// audit logs, as it keeps Google Cloud's own: the Admin log's in Admin
// Activity, the Login log's in Data Access. The audit record's
// serviceName is the Workspace log (admin.googleapis.com,
// login.googleapis.com), its methodName the event in camel case
// (google.admin.AdminService.createRole), and its metadata the event as
// Workspace's Reports API has it: its name (CREATE_ROLE, login_failure),
// its type, and its parameters, each a name with a value or a list of
// them. ParseGCP reads these entries as it reads the rest, and adds the
// event's name (event_name), as the Reports API spells it, and each of its
// parameters as a field of its own (event_parameters.setting_name), with
// the name in lower case. Sigma's Google Workspace rules name the event
// and parameters by those names (eventName, new_value).

// WorkspaceChannel names Google Workspace audit log entries in test
// events (sigmacheck.Case), as GCPChannel names Google Cloud's.
const WorkspaceChannel = "gworkspace"

// WorkspaceVendor is the vendor_product of a Google Workspace entry.
const WorkspaceVendor = "Google Workspace"

// WorkspaceServices are the Sigma services of Google Workspace's audit
// logs (product: gcp), whose rules Signalith converts.
var WorkspaceServices = []string{"google_workspace.admin", "google_workspace.login"}

// workspaceParamPrefix is the start of the field each of an event's
// parameters is kept as.
const workspaceParamPrefix = "event_parameters."

// workspaceMaxParams caps the parameters one entry's events become
// fields, out of gcpMaxLeaves; the rest stay in the message.
const workspaceMaxParams = 40

// workspaceMaxEvents caps the events of one entry that are read (a real
// one has one or a few), and workspaceMaxValues the values one parameter
// keeps.
const (
	workspaceMaxEvents = 20
	workspaceMaxValues = 100
)

// workspaceLogin is the service of Workspace's sign-ins.
const workspaceLogin = "login.googleapis.com"

// workspaceObjects are the parameters that name what an admin's change is
// about, in the order they are looked for.
var workspaceObjects = []string{
	"user_email", "group_email", "role_name", "application_name", "app_name", "org_unit_name", "domain_name",
	"setting_name",
}

// workspaceEvents returns the events of a Workspace audit record's
// metadata (a list, or one event as an object), or nil when the record is
// not Workspace's.
func workspaceEvents(proto map[string]any) []map[string]any {
	meta, _ := proto["metadata"].(map[string]any)
	if meta == nil {
		return nil
	}
	var out []map[string]any
	switch e := meta["event"].(type) {
	case map[string]any:
		out = append(out, e)
	case []any:
		for _, x := range e {
			if m, ok := x.(map[string]any); ok && len(out) < workspaceMaxEvents {
				out = append(out, m)
			}
		}
	}
	return out
}

// isWorkspace reports whether an audit record is Google Workspace's: its
// metadata is a Reports API activity, or it has none and a Workspace
// service's method (google.admin.AdminService.createRole).
func isWorkspace(proto map[string]any) bool {
	meta, _ := proto["metadata"].(map[string]any)
	if strings.HasSuffix(str(meta, "@type"), "ccc_hosted_reporting.ActivityProto") || len(workspaceEvents(proto)) > 0 {
		return true
	}
	method := str(proto, "methodName")
	switch str(proto, "serviceName") {
	case "admin.googleapis.com":
		return strings.HasPrefix(method, "google.admin.")
	case workspaceLogin:
		return strings.HasPrefix(method, "google.login.")
	}
	return false
}

// WorkspaceEventName is the Reports API's name of the event a method
// records, for an entry whose metadata does not say: the method's last
// part in snake case, in upper case except for sign-ins
// (google.admin.AdminService.createRole is CREATE_ROLE,
// google.login.LoginService.loginFailure login_failure).
func WorkspaceEventName(service, method string) string {
	verb := method[strings.LastIndex(method, ".")+1:]
	var b strings.Builder
	for i, r := range verb {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	if service == workspaceLogin {
		return b.String()
	}
	return strings.ToUpper(b.String())
}

// workspaceMethod is the method of a Workspace event, from its name, the
// other way from WorkspaceEventName (CREATE_ROLE is
// google.admin.AdminService.createRole).
func workspaceMethod(service, event string) string {
	svc := strings.TrimSuffix(service, ".googleapis.com")
	var b strings.Builder
	for i, part := range strings.Split(strings.ToLower(event), "_") {
		if i > 0 && part != "" {
			part = strings.ToUpper(part[:1]) + part[1:]
		}
		b.WriteString(part)
	}
	title := svc
	if svc != "" {
		title = strings.ToUpper(svc[:1]) + svc[1:]
	}
	return "google." + svc + "." + title + "Service." + b.String()
}

// workspaceParamValue is a parameter's value as text, or its values: a
// Reports API parameter has one of value, boolValue and intValue, or a
// list in multiValue (multiStrValue in Cloud Logging) or multiIntValue.
func workspaceParamValue(p map[string]any) any {
	for _, k := range []string{"value", "boolValue", "intValue"} {
		if s := wstr(p[k]); s != "" {
			return CapValue(s)
		}
	}
	for _, k := range []string{"multiValue", "multiStrValue", "multiIntValue"} {
		l, _ := p[k].([]any)
		var out []any
		for _, v := range l {
			if s := wstr(v); s != "" && len(out) < workspaceMaxValues {
				out = append(out, CapValue(s))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// workspaceFields sets a Workspace entry's event_name and its events'
// parameters (event_parameters.*), and returns the parameters by their
// lower-case names, each one's first value as text, and the type of its
// first event (USER_SETTINGS).
func workspaceFields(f map[string]any, proto map[string]any) (map[string]string, string) {
	service, method := str(proto, "serviceName"), str(proto, "methodName")
	var names []any
	seen := map[string]bool{}
	params := map[string]string{}
	eventType := ""
	for _, e := range workspaceEvents(proto) {
		if n := CapValue(str(e, "eventName", "name")); n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
		if eventType == "" {
			eventType = str(e, "eventType", "type")
		}
		list, _ := e["parameter"].([]any)
		if list == nil {
			list, _ = e["parameters"].([]any)
		}
		for _, x := range list {
			p, _ := x.(map[string]any)
			name := strings.ToLower(str(p, "name"))
			v := workspaceParamValue(p)
			field := workspaceParamPrefix + name
			// A name of letters, digits and underscores, as Google's are, so one
			// parameter cannot become an object holding another.
			if v == nil || !workspaceParamName.MatchString(name) || f[field] != nil || len(params) >= workspaceMaxParams || !validFieldName(field) {
				continue
			}
			f[field] = v
			if l, ok := v.([]any); ok {
				params[name] = l[0].(string)
			} else {
				params[name] = v.(string)
			}
		}
	}
	if len(names) == 0 && method != "" {
		names = append(names, WorkspaceEventName(service, method))
	}
	switch len(names) {
	case 0:
	case 1:
		f["event_name"] = names[0]
	default:
		f["event_name"] = names
	}
	return params, eventType
}

// workspaceEventNames returns an event's event_name, one or several, as a
// list.
func workspaceEventNames(f map[string]any) []string {
	switch v := f["event_name"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, wstr(x))
		}
		return out
	}
	return nil
}

// workspaceParamName is a Sigma field that names an event's parameter by
// its own name, in lower case (setting_name, new_value).
var workspaceParamName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// workspaceSigmaFields map the field names Sigma's Google Workspace rules
// use to the fields an event keeps: the older rules' eventService and
// eventName, after the Reports API's, and the event's name in the entry's
// metadata as Splunk's add-on names it (without its list's {}).
var workspaceSigmaFields = map[string]string{
	"eventService":                          "protoPayload.serviceName",
	"eventName":                             "event_name",
	"protoPayload.metadata.event.eventName": "event_name",
}

// WorkspaceSigmaField returns the field a Google Workspace event keeps for
// a field of a Sigma rule of one of WorkspaceServices, or false when it
// keeps none. A name in lower case with underscores (new_value) is one of
// the event's parameters.
func WorkspaceSigmaField(name string) (string, bool) {
	if f, ok := workspaceSigmaFields[strings.TrimPrefix(name, "data.")]; ok {
		return f, true
	}
	if workspaceParamName.MatchString(name) && validFieldName(workspaceParamPrefix+name) {
		return workspaceParamPrefix + name, true
	}
	if name = strings.TrimPrefix(name, "data."); GCPField(name) {
		return name, true
	}
	return "", false
}

// WorkspaceField reports whether a Google Workspace event keeps a field
// of its own beyond a log entry's (GCPField): its event's name, or one of
// its parameters.
func WorkspaceField(name string) bool {
	if name == "event_name" {
		return true
	}
	p, ok := strings.CutPrefix(name, workspaceParamPrefix)
	return ok && p != "" && validFieldName(name)
}

// WorkspaceRecord is a Google Workspace audit log entry, as an
// organization that shares its Workspace logs with Google Cloud has it,
// with the fields a Sigma rule names (eventService, eventName,
// new_value), for test events (Normalize with GCPTag), as host sent it:
// a change, or a sign-in when the service is login.googleapis.com. An
// entry whose service or event the data do not name is a group's setting
// changed, in Cloud Identity's log, which no rule names.
func WorkspaceRecord(host string, t time.Time, data map[string]string) map[string]any {
	service, event := "cloudidentity.googleapis.com", "CHANGE_GROUP_SETTING"
	type param struct{ name, value string }
	var params []param
	others := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		f, ok := WorkspaceSigmaField(k)
		switch {
		case !ok:
		case f == "protoPayload.serviceName":
			service = data[k]
		case f == "event_name":
			event = data[k]
		case strings.HasPrefix(f, workspaceParamPrefix):
			params = append(params, param{strings.TrimPrefix(f, workspaceParamPrefix), data[k]})
		default:
			others[f] = data[k]
		}
	}
	log := "activity"
	if service == workspaceLogin {
		log = "data_access"
	}
	method := workspaceMethod(service, event)
	var plist []any
	for _, p := range params {
		name := p.name
		if service != workspaceLogin {
			// The Admin log's parameters are in upper case.
			name = strings.ToUpper(name)
		}
		plist = append(plist, map[string]any{"name": name, "type": "TYPE_STRING", "value": p.value})
	}
	ts := t.UTC().Format(time.RFC3339Nano)
	r := map[string]any{
		"logName":   "organizations/123456789012/logs/" + url.PathEscape("cloudaudit.googleapis.com/"+log),
		"timestamp": ts, "receiveTimestamp": ts, "severity": "NOTICE", "hostname": host,
		"resource": map[string]any{"type": "audited_resource", "labels": map[string]any{"service": service, "method": method}},
		"protoPayload": map[string]any{
			"@type":       "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName": service, "methodName": method, "resourceName": "organizations/123456789012",
			"authenticationInfo": map[string]any{"principalEmail": "admin@example.com"},
			"requestMetadata":    map[string]any{"callerIp": "203.0.113.7"},
			"metadata": map[string]any{
				"@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
				"event": []any{map[string]any{"eventName": event, "parameter": plist}},
			},
		},
	}
	for _, k := range slices.Sorted(maps.Keys(others)) {
		gcpPut(r, k, others[k])
	}
	// Each test entry its own insertId, as the same entry is stored once.
	h := sha256.New()
	fmt.Fprintln(h, host, t.UnixNano())
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintln(h, k, data[k])
	}
	r["insertId"] = hex.EncodeToString(h.Sum(nil))[:16]
	return r
}
