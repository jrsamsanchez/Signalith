// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Google Cloud records what is done in each project, folder and
// organization in its audit logs: Admin Activity (what was created,
// changed or deleted, and by whom), Data Access, System Event and Policy
// Denied. Cloud Logging keeps each entry as a LogEntry, and a log sink
// sends the entries to a Pub/Sub topic. Each entry becomes an event with
// the entry's own field names flattened with dots (protoPayload.methodName,
// protoPayload.authenticationInfo.principalEmail, resource.labels.project_id).
// Splunk's add-on for Google Cloud Platform keeps the same names under
// data. (data.protoPayload.methodName), as the Pub/Sub message holds the
// entry there; Signalith leaves that prefix off, and Sigma's and Splunk's
// rules are converted to the names without it. Each event also gets the
// data model fields of what the entry records: a change is a Change
// event, a sign-in an Authentication event, and the rest (reads, system
// events, denied requests) Other. Google Workspace's audit logs, which an
// organization can share with Google Cloud, are entries of the same kind,
// with a little more (see gworkspace.go).
//
// Entries come from the OpenTelemetry Collector's googlecloudpubsub
// receiver with the text encoding, which passes each message's data on as
// the body's text (see gcpFromOTLP), or under the gcp tag as JSON: a
// LogEntry, or a Pub/Sub push or pull message ({"message": {"data":
// "<base64 LogEntry>"}}).

// GCPTag is the tag of Google Cloud log entries sent as JSON.
const GCPTag = "gcp"

// GCPSourcetype is the sourcetype of Google Cloud events, Splunk's.
const GCPSourcetype = "google:gcp:pubsub:message"

// GCPChannel names Google Cloud audit log entries in test events
// (sigmacheck.Case), as a Windows channel names Windows events.
const GCPChannel = "gcp"

// GCPService is the Sigma service of Google Cloud's audit logs (product:
// gcp), whose rules Signalith converts.
const GCPService = "gcp.audit"

// GCPKeywordField is the Sigma field a Google Cloud rule's keywords are
// searched in: the call's request, as JSON text (request_parameters),
// where the rules look for an object's annotations.
const GCPKeywordField = "data.protoPayload.request"

// gcpMaxLeaves caps the fields one entry's nested objects (the request,
// the response, their metadata) become, beyond gcpFields; the rest stay
// in the message.
const gcpMaxLeaves = 100

// gcpTop are an entry's top-level fields, kept by name when set. Its
// labels, whose keys the sender chooses, are kept as one field of JSON
// text.
var gcpTop = []string{
	"logName", "insertId", "timestamp", "receiveTimestamp", "severity", "trace", "spanId", "traceSampled", "textPayload",
	"labels",
}

// gcpObjects are an entry's objects whose fields are kept, each as its own
// field (resource.labels.project_id).
var gcpObjects = []string{"resource", "protoPayload", "operation", "httpRequest", "sourceLocation", "jsonPayload"}

// gcpFields are the fields of an audit log entry kept by name whenever
// it has them, before the request's and response's own (gcpMaxLeaves).
var gcpFields = []string{
	"resource.type", "resource.labels.project_id", "resource.labels.location", "resource.labels.zone",
	"resource.labels.region", "resource.labels.cluster_name", "resource.labels.bucket_name",
	"resource.labels.email_id", "resource.labels.unique_id", "resource.labels.instance_id", "resource.labels.service",
	"resource.labels.method",
	"protoPayload.@type", "protoPayload.serviceName", "protoPayload.methodName", "protoPayload.resourceName",
	"protoPayload.numResponseItems", "protoPayload.status.code", "protoPayload.status.message",
	"protoPayload.authenticationInfo.principalEmail", "protoPayload.authenticationInfo.principalSubject",
	"protoPayload.authenticationInfo.serviceAccountKeyName", "protoPayload.authenticationInfo.serviceAccountDelegationInfo",
	"protoPayload.authenticationInfo.authoritySelector",
	"protoPayload.requestMetadata.callerIp", "protoPayload.requestMetadata.callerSuppliedUserAgent",
	"protoPayload.requestMetadata.callerNetwork",
	"protoPayload.authorizationInfo", "protoPayload.authorizationInfo{}.permission",
	"protoPayload.authorizationInfo{}.granted", "protoPayload.authorizationInfo{}.resource",
	"protoPayload.resourceLocation.currentLocations", "protoPayload.resourceLocation.currentLocations{}",
	"operation.id", "operation.producer", "operation.first", "operation.last",
}

// gcpMapped are the fields the index template maps (see knownFields): what
// a Google Cloud search reads first. The rest are mapped as they come.
var gcpMapped = []string{
	"logName", "log_id", "insertId", "resource.type", "resource.labels.project_id", "protoPayload.serviceName",
	"protoPayload.methodName", "protoPayload.resourceName", "protoPayload.status.code",
	"protoPayload.authenticationInfo.principalEmail", "protoPayload.requestMetadata.callerIp",
	"protoPayload.requestMetadata.callerSuppliedUserAgent", "protoPayload.authorizationInfo{}.permission",
	"protoPayload.authorizationInfo{}.granted",
	// A Google Workspace event's name (gworkspace.go).
	"event_name",
}

// gcpCallerKeyed are the objects in an entry whose keys the caller
// chooses: labels and annotations. Each is kept as one field of JSON text,
// so it can't use up the index's field names. A resource's labels are
// Google's own, and kept field by field.
var gcpCallerKeyed = map[string]bool{"labels": true, "annotations": true}

// IsGCPRecord reports whether a decoded object is a Cloud Logging
// LogEntry: it names its log (projects/p/logs/...) and the resource it is
// about.
func IsGCPRecord(r map[string]any) bool {
	name, _ := r["logName"].(string)
	_, res := r["resource"].(map[string]any)
	return res && strings.Contains(name, "/logs/")
}

// GCPEntry returns the LogEntry a decoded record holds: the record itself,
// or the entry in a Pub/Sub message, as a push subscription posts it or a
// pull returns it ({"message": {"data": "<base64>"}}), or as Splunk's
// add-on stores it ({"data": {...}}). It returns nil when there is none.
func GCPEntry(r map[string]any) map[string]any {
	if IsGCPRecord(r) {
		return r
	}
	if d, ok := r["data"].(map[string]any); ok && IsGCPRecord(d) {
		return d
	}
	msg, ok := r["message"].(map[string]any)
	if !ok {
		return nil
	}
	data, _ := msg["data"].(string)
	if data == "" || len(data) > 2*MaxRecordBytes {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(data); err != nil {
			return nil
		}
	}
	return gcpText(raw)
}

// gcpText decodes a LogEntry from JSON text, or returns nil when the text
// is not one.
func gcpText(b []byte) map[string]any {
	b = bytes.TrimSpace(b)
	// The text sat inside a string, past the body's own depth check.
	if len(b) == 0 || b[0] != '{' || len(b) > MaxRecordBytes || !bytes.Contains(b, []byte(`"logName"`)) || depth(b) > MaxDepth {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil || !IsGCPRecord(r) {
		return nil
	}
	return r
}

// gcpFromOTLP returns the LogEntry of an OTLP log record whose body is one:
// text (the googlecloudpubsub receiver with the text encoding) or a map.
func gcpFromOTLP(body any) map[string]any {
	switch b := body.(type) {
	case string:
		if strings.HasPrefix(b, "{") {
			return gcpText([]byte(b))
		}
	case map[string]any:
		if IsGCPRecord(b) {
			return b
		}
	}
	return nil
}

// gcpKeyed returns v with the objects whose keys the caller chooses
// (gcpCallerKeyed) replaced by their JSON text, except a resource's own
// labels.
func gcpKeyed(prefix string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			if _, obj := e.(map[string]any); obj && gcpCallerKeyed[k] && name != "resource.labels" {
				if b, err := json.Marshal(e); err == nil {
					out[k] = string(b)
				}
				continue
			}
			out[k] = gcpKeyed(name, e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = gcpKeyed(prefix+"{}", e)
		}
		return out
	}
	return v
}

// ParseGCP maps a Google Cloud log entry (decoded JSON), or a Pub/Sub
// message that holds one, onto an event.
func ParseGCP(rec map[string]any) Event {
	r := GCPEntry(rec)
	if r == nil {
		return parseGeneric(rec)
	}
	f := map[string]any{"sourcetype": GCPSourcetype, "vendor_product": "Google Cloud"}
	flat := map[string]any{}
	keyed, _ := gcpKeyed("", r).(map[string]any)
	for _, k := range gcpTop {
		if v, ok := keyed[k]; ok {
			flattenAzure(k, v, flat)
		}
	}
	for _, k := range gcpObjects {
		if v, ok := keyed[k]; ok {
			flattenAzure(k, v, flat)
		}
	}
	proto, _ := r["protoPayload"].(map[string]any)
	if proto == nil {
		proto = map[string]any{}
	}
	// A Google Workspace event's name and parameters (gworkspace.go),
	// which come out of gcpMaxLeaves.
	workspace := isWorkspace(proto)
	var params map[string]string
	eventType := ""
	if workspace {
		f["vendor_product"] = WorkspaceVendor
		params, eventType = workspaceFields(f, proto)
	}
	// The top-level fields and gcpFields, then the rest in order, as far
	// as gcpMaxLeaves.
	leaves := len(params)
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		switch {
		case !strings.Contains(k, ".") || slices.Contains(gcpFields, k):
			f[k] = flat[k]
		case leaves < gcpMaxLeaves && validFieldName(k):
			f[k] = flat[k]
			leaves++
		}
	}
	// A call's whole request and response as JSON text, as CloudTrail's
	// are, which rules search for words inside.
	for obj, field := range map[string]string{"request": "request_parameters", "response": "response_elements"} {
		if v, ok := proto[obj].(map[string]any); ok {
			if b, err := json.Marshal(v); err == nil {
				f[field] = truncateUTF8(string(b), MaxRecordBytes)
			}
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
	// The machine that sent the entry, when it says (Google Cloud itself
	// has no host).
	if h, ok := rec["hostname"].(string); ok {
		set("host", h)
	}
	logName := str(r, "logName")
	logID := logName[strings.Index(logName, "/logs/")+len("/logs/"):]
	if id, err := url.PathUnescape(logID); err == nil {
		logID = id
	}
	set("log_id", logID)
	auth, _ := proto["authenticationInfo"].(map[string]any)
	meta, _ := proto["requestMetadata"].(map[string]any)
	res, _ := r["resource"].(map[string]any)
	labels, _ := res["labels"].(map[string]any)
	method := str(proto, "methodName")
	service := str(proto, "serviceName")
	user := str(auth, "principalEmail", "principalSubject")
	set("signature", method)
	set("command", method)
	if names := workspaceEventNames(f); len(names) > 0 {
		// A Workspace event by its own name (CREATE_ROLE), as Splunk's
		// add-on for Google Workspace names it.
		set("signature", names[0])
		set("command", names[0])
	}
	set("app", service)
	set("dest", service)
	set("user", user)
	// Also where Splunk's add-on keeps who made the call.
	set("src_user", user)
	set("src", str(meta, "callerIp"))
	set("user_agent", str(meta, "callerSuppliedUserAgent"))
	set("http_user_agent", str(meta, "callerSuppliedUserAgent"))
	// The project, from the resource or else the log's name, or the
	// organization for an organization's own log (Google Workspace's).
	project := str(labels, "project_id")
	if project == "" {
		for _, p := range []string{"projects/", "organizations/"} {
			if rest, ok := strings.CutPrefix(logName, p); ok && project == "" {
				project, _, _ = strings.Cut(rest, "/")
			}
		}
	}
	set("vendor_account", project)
	set("vendor_region", str(labels, "location", "region", "zone"))
	set("id", str(r, "insertId"))
	status := ""
	if proto["status"] != nil || method != "" {
		status = "success"
	}
	if st, ok := proto["status"].(map[string]any); ok {
		if code := str(st, "code"); code != "" && code != "0" {
			status = "failure"
			set("reason", cmp.Or(str(st, "message"), code))
		}
	}

	ev := Event{Fields: f, Model: "Other"}
	if t, err := time.Parse(time.RFC3339Nano, str(r, "timestamp")); err == nil {
		ev.Time = t.UTC()
	}
	// The same entry, delivered twice by Pub/Sub, is stored once.
	if id := str(r, "insertId"); id != "" {
		ev.ID = sensorDocID("gcp", logName+"\n"+id+"\n"+str(r, "timestamp"))
	}
	switch {
	case service == workspaceLogin:
		// A sign-in to a Google account, which Cloud Audit Logs has when
		// the organization shares its Google Workspace data.
		ev.Model = "Authentication"
		f["action"] = "success"
		if strings.Contains(strings.ToLower(method), "failure") ||
			slices.ContainsFunc(workspaceEventNames(f), func(n string) bool { return strings.Contains(n, "failure") }) {
			f["action"] = "failure"
		}
		set("status", wstr(f["action"]))
		set("app", "google:login")
		// How the user signed in (google_password, saml, reauth), and why
		// it failed (login_failure_invalid_password).
		set("authentication_method", params["login_type"])
		set("reason", params["login_failure_type"])
	case strings.HasSuffix(logID, "/activity") || strings.HasSuffix(logID, "/system_event"):
		// What was created, changed or deleted: Admin Activity, and the
		// changes Google made itself (System Event).
		ev.Model = "Change"
		set("status", status)
		f["action"] = GCPAction(method)
		set("change_type", "GCP API Call")
		set("object_category", str(res, "type"))
		name := str(proto, "resourceName")
		set("object", name[strings.LastIndex(name, "/")+1:])
		set("object_path", name)
		if workspace {
			// An admin's change in Google Workspace: what it is about is
			// in the event's parameters (the user, group, role or
			// setting), and its kind in the event's type
			// (USER_SETTINGS).
			set("change_type", "Google Workspace")
			set("object_category", eventType)
			for _, p := range workspaceObjects {
				if v := params[p]; v != "" {
					set("object", v)
					break
				}
			}
		}
	default:
		set("status", status)
	}
	return ev
}

// GCPAction is the Change data model's action of a call, from the verb
// that ends its method's name (v1.compute.instances.insert,
// google.iam.admin.v1.CreateServiceAccount).
func GCPAction(method string) string {
	verb := strings.ToLower(method[strings.LastIndex(method, ".")+1:])
	for _, p := range [][2]string{
		{"create", "created"}, {"insert", "created"}, {"add", "created"}, {"import", "created"}, {"upload", "created"},
		{"attach", "created"}, {"undelete", "created"}, {"delete", "deleted"}, {"remove", "deleted"}, {"detach", "deleted"},
		{"destroy", "deleted"}, {"disable", "disabled"}, {"enable", "enabled"}, {"stop", "stopped"}, {"start", "started"},
	} {
		if strings.HasPrefix(verb, p[0]) {
			return p[1]
		}
	}
	return "modified"
}

// gcpSigmaFields map the field names Sigma's Google Cloud rules use to the
// fields an event keeps: Elastic's (gcp.audit.method_name), and Splunk's
// add-on's under data., where some rules put the entry's own fields under
// protoPayload.
var gcpSigmaFields = map[string]string{
	"gcp.audit.method_name":                          "protoPayload.methodName",
	"gcp.audit.service_name":                         "protoPayload.serviceName",
	"gcp.audit.resource_name":                        "protoPayload.resourceName",
	"gcp.audit.authentication_info.principal_email":  "protoPayload.authenticationInfo.principalEmail",
	"gcp.audit.request_metadata.caller_ip":           "protoPayload.requestMetadata.callerIp",
	"gcp.audit.status.code":                          "protoPayload.status.code",
	"gcp.audit.status.message":                       "protoPayload.status.message",
	"data.protoPayload.logName":                      "log_id",
	"data.protoPayload.resource.type":                "resource.type",
	"data.protoPayload.authorizationInfo.permission": "protoPayload.authorizationInfo{}.permission",
	"data.protoPayload.authorizationInfo.granted":    "protoPayload.authorizationInfo{}.granted",
	"data.protoPayload.authorizationInfo.resource":   "protoPayload.authorizationInfo{}.resource",
	// A rule's keywords: words in the call's request.
	GCPKeywordField: "request_parameters",
}

// GCPSigmaField returns the field a Google Cloud event keeps for a field
// of a Sigma rule of service gcp.audit, or false when it keeps none.
func GCPSigmaField(name string) (string, bool) {
	if f, ok := gcpSigmaFields[name]; ok {
		return f, true
	}
	name = strings.TrimPrefix(name, "data.")
	if GCPField(name) {
		return name, true
	}
	return "", false
}

// GCPField reports whether a Google Cloud event keeps a field of a log
// entry by its own name: a top-level field (logName), or one under the
// resource, the audit record or the operation (protoPayload.methodName,
// protoPayload.authorizationInfo{}.permission). A field inside labels or
// annotations is not one: they are kept whole, as JSON text.
func GCPField(name string) bool {
	if slices.Contains(gcpTop, name) {
		return true
	}
	if !slices.ContainsFunc(gcpObjects, func(obj string) bool { return strings.HasPrefix(name, obj+".") }) ||
		!validFieldName(name) {
		return false
	}
	parts := strings.Split(name, ".")
	for i, p := range parts[:len(parts)-1] {
		if gcpCallerKeyed[strings.TrimSuffix(p, "{}")] && !(i == 1 && parts[0] == "resource") {
			return false
		}
	}
	return true
}

// GCPRecord is a Google Cloud audit log entry with the fields a Sigma
// rule names (gcp.audit.method_name, data.protoPayload.serviceName), for
// test events (Normalize with GCPTag), as host sent it: a change, by a
// user, that went through. It is in the System Event log unless the rule
// names its log (data.protoPayload.logName), so a rule about the Admin
// Activity log is met only by the entries its test says are in it.
func GCPRecord(host string, t time.Time, data map[string]string) map[string]any {
	r := map[string]any{
		"logName":   "projects/example-project/logs/cloudaudit.googleapis.com%2Fsystem_event",
		"timestamp": t.UTC().Format(time.RFC3339Nano), "receiveTimestamp": t.UTC().Format(time.RFC3339Nano),
		"severity": "NOTICE", "hostname": host,
		"resource": map[string]any{"type": "project", "labels": map[string]any{"project_id": "example-project"}},
		"protoPayload": map[string]any{
			"@type":       "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName": "cloudresourcemanager.googleapis.com", "methodName": "SetIamPolicy",
			"resourceName":       "projects/example-project",
			"authenticationInfo": map[string]any{"principalEmail": "admin@example.com"},
			"requestMetadata":    map[string]any{"callerIp": "203.0.113.7", "callerSuppliedUserAgent": "google-cloud-sdk gcloud/500.0.0"},
		},
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		v := data[k]
		f, ok := GCPSigmaField(k)
		if !ok {
			continue
		}
		switch f {
		case "log_id":
			r["logName"] = "projects/example-project/logs/" + url.PathEscape(v)
			continue
		case "request_parameters":
			// A word in the request: an annotation of the object it makes.
			gcpPut(r, "protoPayload.request.metadata.annotations", map[string]any{v: "true"})
			continue
		case "protoPayload.authorizationInfo{}.granted":
			gcpPut(r, f, v == "true")
			continue
		case "protoPayload.status.code":
			if _, err := strconv.ParseInt(v, 10, 64); err == nil {
				gcpPut(r, f, json.Number(v))
				continue
			}
		}
		gcpPut(r, f, v)
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

// gcpPut sets the field of a test entry at a dotted path
// (protoPayload.request.metadata.annotations), making the objects on the
// way. A part ending in {} is a list: its first object, or the list a
// value is added to.
func gcpPut(r map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	m := r
	for _, p := range parts[:len(parts)-1] {
		if name, ok := strings.CutSuffix(p, "{}"); ok {
			// A list of objects (authorizationInfo{}.permission): its
			// first.
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
